// End-to-end test of hem-sdk.js against an in-process mock of the device and
// the broker. Run: node --test test/sdk.test.mjs
//
// The mock speaks the wire format the SDK expects (see the PHP reference in
// hem-api-tester for the device side); it verifies the eJWT the SDK signs, so
// the password path is checked cryptographically, not only for shape.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { HEM, Broker, HemError, jwtParse, verifyLog, verifyLoggerKey, generateMnemonic, entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from '../hem-sdk.js';

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
const fromB64 = (s) => new Uint8Array(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
const json = (res, status, body) => {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(body === undefined ? '' : JSON.stringify(body));
};
const fakeJwt = (payload) => `${b64url(Buffer.from('{"alg":"HS256"}'))}.${b64url(Buffer.from(JSON.stringify(payload)))}.sig`;

// ---- mock state ----------------------------------------------------------------
const state = {
  devKeys: null,          // X25519 key pair of the mock device
  spkB64: null,
  eid: 'eid-salt-1234',
  configNonce: null,      // what a password change proves possession against
  log: [],                // every request: { method, path, body }
  eventPolls: 0,          // 202 until this reaches eventReadyAfter
  eventReadyAfter: 2,
  eventAnswer: { authreply: 'reply-from-phone' },
  regPolls: 0,
  regReadyAfter: 1,
  deleted: [],
  provisioned: false,
  domainTaken: { my: true },
  paired: true,
  keys: [
    { kid: 'K1', label: 'git-signing', type: 'ATT,PKEY,ExDSA,ED25519', descr: Buffer.from('Commits and tags').toString('base64'), created: 1738454400, updated: 1738454400 },
    { kid: 'K2', label: 'wg-peer-03', type: 'PKEY,ECDH,CURVE25519', descr: Buffer.from('WireGuard identity').toString('base64'), created: 1738454401, updated: 1738454402 },
    { kid: 'K3', label: 'bob', type: 'ED25519', descr: '', created: 1751846400, updated: 1751846400 },
  ],
};

async function verifyEjwt(ejwt) {
  const [h, p, sig] = ejwt.split('.');
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
  const userPub = await crypto.subtle.importKey('raw', fromB64(payload.iss), 'X25519', false, []);
  const shared = await crypto.subtle.deriveBits({ name: 'X25519', public: userPub }, state.devKeys.privateKey, 256);
  const key = await crypto.subtle.importKey('raw', shared, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('HMAC', key, fromB64(sig), Buffer.from(`${h}.${p}`));
  return { ok, payload };
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
  });
}

async function handle(req, res) {
  const url = new URL(req.url, 'http://x');
  const raw = await readBody(req);
  const isJson = (req.headers['content-type'] ?? '').includes('json');
  const body = raw.length && isJson ? JSON.parse(raw.toString()) : null;
  const path = url.pathname;
  state.log.push({ method: req.method, path, body, raw, auth: req.headers.authorization ?? null });

  // ---- device ------------------------------------------------------------------
  if (path === '/dev/api/system/checkin' && req.method === 'GET') return json(res, 200, { check: 'c1' });
  if (path === '/dev/api/system/checkin' && req.method === 'POST') {
    assert.equal(body.checked, 'ok');
    return json(res, 200, { status: 'ok', newfws: 'v2.0.1+/x', newuis: null });
  }
  if (path === '/dev/api/system/version') return json(res, 200, { hwv: '1', blv: '1', fwv: '2', fws: 'x', conf: 'PPA' });
  if (path === '/dev/api/system/config' && req.method === 'GET') {
    return json(res, 200, { eid: state.eid, user: 'Ann', email: 'ann@example.com', hostname: 'my.ence.do', spk: state.spkB64, nonce: state.configNonce });
  }
  if (path === '/dev/api/system/config' && req.method === 'POST') {
    if (body.gen_csr) return json(res, 200, { genuine: 'GEN', csr: 'CSR' });
    return json(res, 200, { updated: true, received: body });
  }
  if (path === '/dev/api/system/config/attestation') return json(res, 200, state.provisioned ? { genuine: 'GEN' } : { genuine: 'GEN', csr: 'CSR', key: 'KEY' });
  if (path === '/dev/api/system/config/provisioning') { state.provisioned = true; return json(res, 200, { installed: true }); }
  if (path === '/dev/api/auth/token' && req.method === 'GET') return json(res, 200, { eid: state.eid, spk: state.spkB64, jti: 'jti-1', genuine: 'GEN' });
  if (path === '/dev/api/auth/token' && req.method === 'POST') {
    const { ok, payload } = await verifyEjwt(body.auth);
    if (!ok) return json(res, 401, { error: 'bad signature' });
    return json(res, 200, { token: fakeJwt({ scope: payload.scope, exp: payload.exp, sub: 'user' }) });
  }
  if (path === '/dev/api/auth/init' && req.method === 'GET') return json(res, 200, { eid: state.eid, spk: state.spkB64, jti: 'jti-init', exp: Math.floor(Date.now() / 1000) + 300 });
  if (path === '/dev/api/auth/init' && req.method === 'POST') {
    const { ok, payload } = await verifyEjwt(body.init);
    if (!ok) return json(res, 401, { error: 'bad signature' });
    state.initCfg = payload.cfg;
    state.initIss = payload.iss;
    return json(res, 200, { instanceid: 'INST-1', inited: true });
  }
  if (path === '/dev/api/auth/ext/request') return json(res, 200, { challenge: 'CH', epk: body.epk, scope: body.scope });
  if (path === '/dev/api/auth/ext/token') return json(res, 200, { token: fakeJwt({ scope: 'remote', exp: Math.floor(Date.now() / 1000) + 300 }) });
  if (path === '/dev/api/auth/ext/init') return json(res, 200, { eid: state.eid, request: 'REQUEST-JWT' });
  if (path === '/dev/api/auth/ext/validate') return json(res, 200, { confirmed: body.pid });
  if (path === '/dev/api/auth/ext/mac') return json(res, 200, { nonce: 'N', mac: 'M', eid: state.eid });
  if (path === '/dev/api/system/upgrade/upload_fw') return json(res, 200, { bytes: raw.length, ct: req.headers['content-type'] });
  if (path === '/dev/api/keymgmt/create') return json(res, 200, { kid: 'NEW1' });
  if (path.startsWith('/dev/api/keymgmt/get/')) return json(res, 200, { type: 'ED25519', pubkey: 'PUB', updated: 1738454400 });
  if (path.startsWith('/dev/api/keymgmt/list/')) {
    const [offset, limit] = path.split('/').slice(-2).map(Number);
    const page = state.keys.slice(offset, offset + limit);
    return json(res, 200, { total: state.keys.length, listed: page.length, list: page });
  }
  if (path === '/dev/api/logger/key') return json(res, 200, { key: state.loggerKeyB64, nonce: state.loggerNonce, nonce_signed: state.loggerNonceSig });
  if (path.startsWith('/dev/api/logger/')) { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end(state.logText); }

  // ---- broker ------------------------------------------------------------------
  if (path === '/brk/checkin') { assert.equal(body.check, 'c1'); return json(res, 200, { checked: 'ok' }); }
  if (path === '/brk/notify/session' && req.method === 'GET') return json(res, 200, { epk: 'EPK-anon' });
  if (path === '/brk/notify/session' && req.method === 'POST') return json(res, 200, { epk: 'EPK-' + body.eid, paired: state.paired });
  if (path === '/brk/notify/event/new') return json(res, 200, { eventid: 'EV1' });
  if (path === '/brk/notify/event/check/EV1') {
    state.eventPolls++;
    if (state.eventPolls < state.eventReadyAfter) return json(res, 202);
    return json(res, 200, state.eventAnswer);
  }
  if (path === '/brk/notify/event/EV1' && req.method === 'DELETE') { state.deleted.push('EV1'); return json(res, 200, { deleted: true }); }
  if (path === '/brk/notify/register/init') return json(res, 200, { rid: 'RID1', link: 'https://api.encedo.com/r/RID1' });
  if (path === '/brk/notify/register/check/RID1') {
    state.regPolls++;
    if (state.regPolls < state.regReadyAfter) return json(res, 202);
    return json(res, 200, { pid: 'PID9', reply: 'PHONE-REPLY' });
  }
  if (path === '/brk/notify/register/finalise/RID1') return json(res, 200, { paired: true, got: body });
  if (path === '/brk/notify/subscribers/list') return json(res, 200, [{ pid: 'PID9', label: 'Phone' }]);
  if (path === '/brk/notify/subscribers/delete') return json(res, 200, { deleted: body.pid });
  if (path === '/brk/download/firmware/v2.0.1-_x/bin') { res.writeHead(200, { 'Content-Type': 'application/octet-stream' }); return res.end(Buffer.from([1, 2, 3, 4, 5])); }
  if (path === '/brk/domain/predefs') return json(res, 200, { prefix: ['my', 'dev'] });
  if (path.startsWith('/brk/domain/check/')) return json(res, state.domainTaken[path.split('/').pop()] ? 200 : 404, {});
  if (path.startsWith('/brk/domain/register/')) {
    const tail = path.split('/').pop();
    // A custom prefix (one that sends a CSR) waits for an e-mail click: 201 + id, then a status to poll.
    if (req.method === 'POST' && body?.csr && tail !== 'my') { state.domainPolls = 0; return json(res, 201, { id: 'JOB-' + tail }); }
    if (req.method === 'GET' && tail.startsWith('JOB-')) {
      const n = ++state.domainPolls;
      if (n === 1) return json(res, 200, { status: 'pending' });
      if (n === 2) return json(res, 200, { status: 'email_confirmed' });
      return json(res, 200, { status: 'done', emp: 'E', key: 'K', crt: 'C', prefix: tail.slice(4) });
    }
    return json(res, 200, { emp: 'E', key: 'K', crt: 'C', prefix: tail, got: body });
  }
  if (path === '/brk/provisioning') return json(res, 200, { crt: 'CERT', genuine: body.genuine });
  if (path === '/brk/share/emailpubkey') return json(res, 200, { sent: true, got: body });

  json(res, 404, { error: 'unmocked ' + req.method + ' ' + path });
}

let server, base;
before(async () => {
  state.devKeys = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  state.spkB64 = b64(new Uint8Array(await crypto.subtle.exportKey('raw', state.devKeys.publicKey)));
  server = http.createServer((req, res) => handle(req, res).catch((e) => json(res, 500, { error: e.message })));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const mk = () => new HEM(`${base}/dev`, { broker: `${base}/brk` });

test('hemCheckin returns the device payload with update flags', async () => {
  const r = await mk().hemCheckin();
  assert.equal(r.status, 'ok');
  assert.equal(r.newfws, 'v2.0.1+/x');
});

test('a shared Broker instance can be passed in', async () => {
  const broker = new Broker(`${base}/brk`);
  const hem = new HEM(`${base}/dev`, { broker });
  assert.equal(hem.broker, broker);
  assert.equal(hem.broker.url, `${base}/brk`);
});

test('authorizePassword signs an eJWT the device accepts and caches the token', async () => {
  const hem = mk();
  const t1 = await hem.authorizePassword('correct horse', 'keymgmt:list', 120);
  const p = jwtParse(t1);
  assert.equal(p.scope, 'keymgmt:list');
  const before = state.log.length;
  const t2 = await hem.authorizePassword(null, 'keymgmt:list');
  assert.equal(t2, t1, 'second call is served from the cache');
  assert.equal(state.log.length, before, 'no request for a cached scope');
  const t3 = await hem.authorizePassword(null, 'system:config');
  assert.equal(jwtParse(t3).scope, 'system:config', 'escalation reuses derived keys without a password');
});

test('a password change sends the new public key and a proof it can be used', async () => {
  state.configNonce = b64(crypto.getRandomValues(new Uint8Array(32)));
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'system:config');
  await hem.setUserPassword(token, 'a new password');

  const sent = state.log.filter((e) => e.path === '/dev/api/system/config' && e.method === 'POST').at(-1).body;
  assert.deepEqual(Object.keys(sent).sort(), ['userkey', 'userkey_hmac', 'userkey_nonce']);
  assert.equal(sent.userkey_nonce, state.configNonce);
  assert.equal(fromB64(sent.userkey).length, 32, 'a public key, not a password');

  // The device checks the proof by doing the same ECDH from its side.
  const userPub = await crypto.subtle.importKey('raw', fromB64(sent.userkey), 'X25519', false, []);
  const shared = await crypto.subtle.deriveBits({ name: 'X25519', public: userPub }, state.devKeys.privateKey, 256);
  const key = await crypto.subtle.importKey('raw', shared, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  assert.equal(await crypto.subtle.verify('HMAC', key, fromB64(sent.userkey_hmac), fromB64(state.configNonce)), true);

  // And the key really is the one that password derives to.
  const same = mk();
  await same.authorizePassword('a new password', 'system:config');
  const proof = state.log.filter((e) => e.path === '/dev/api/auth/token' && e.method === 'POST').at(-1).body;
  const payload = JSON.parse(Buffer.from(proof.auth.split('.')[1], 'base64url').toString());
  assert.equal(payload.iss, sent.userkey, 'the module can now be unlocked with it');
});

test('authorising with the master secret never reuses a token the words did not make', async () => {
  const hem = mk();
  await hem.authorizePassword('correct horse', 'system:config');    // a cached token for that scope
  assert.equal(hem.tokens.length, 1);

  const mnemonic = await generateMnemonic();
  await assert.rejects(hem.authorizeMaster(mnemonic.replace(/^\S+/, 'zoo'), 'system:config'), (e) => e.code === 'mnemonic_checksum',
    'the cached token must not stand in for checking the words');
  await assert.rejects(hem.authorizeMaster('four words only here', 'system:config'), (e) => /mnemonic/.test(e.code));

  const before = state.log.filter((e) => e.path === '/dev/api/auth/token' && e.method === 'POST').length;
  await hem.authorizeMaster(mnemonic, 'system:config');
  const after = state.log.filter((e) => e.path === '/dev/api/auth/token' && e.method === 'POST');
  assert.equal(after.length, before + 1, 'it went to the device with the master key');
  const payload = JSON.parse(Buffer.from(after.at(-1).body.auth.split('.')[1], 'base64url').toString());
  const fromWords = await mnemonicToEntropy(mnemonic);
  assert.notEqual(payload.iss, undefined);
  assert.equal(fromWords.length, 32);
});

test('the token cache can be looked at without handing out the tokens', async () => {
  const hem = mk();
  assert.deepEqual(hem.tokens, []);
  await hem.authorizePassword('correct horse', 'keymgmt:list', 120);
  await hem.authorizePassword(null, 'logger:get');
  assert.deepEqual(hem.tokens.map((t) => t.scope).sort(), ['keymgmt:list', 'logger:get']);
  assert.ok(hem.tokens.every((t) => typeof t.exp === 'number' && !('token' in t)), 'scope and expiry, nothing else');
  hem.clearCache();
  assert.deepEqual(hem.tokens, []);
});

test('authorizeRemote polls the broker until the phone answers', async () => {
  state.eventPolls = 0; state.eventReadyAfter = 3; state.deleted = [];
  let pending = 0, seenEvent = null;
  const token = await mk().authorizeRemote('remote', { pollInterval: 10, onPending: () => pending++, onEvent: (id) => { seenEvent = id; } });
  assert.equal(jwtParse(token).scope, 'remote');
  assert.equal(seenEvent, 'EV1');
  assert.equal(pending, 3);
  assert.deepEqual(state.deleted, [], 'a completed event is not deleted');
});

test('authorizeRemote withdraws the event when cancelled', async () => {
  state.eventPolls = 0; state.eventReadyAfter = 1000; state.deleted = [];
  const ac = new AbortController();
  setTimeout(() => ac.abort(), 30);
  await assert.rejects(mk().authorizeRemote('remote', { pollInterval: 10, signal: ac.signal }), (e) => e instanceof HemError && e.code === 'aborted');
  assert.deepEqual(state.deleted, ['EV1']);
});

test('authorizeRemote withdraws the event on timeout and reports denial', async () => {
  state.eventPolls = 0; state.eventReadyAfter = 1000; state.deleted = [];
  await assert.rejects(mk().authorizeRemote('remote', { pollInterval: 10, pollTimeout: 40 }), (e) => e.code === 'timeout');
  assert.deepEqual(state.deleted, ['EV1']);
  state.eventPolls = 0; state.eventReadyAfter = 1; state.eventAnswer = { deny: true };
  await assert.rejects(mk().authorizeRemote('remote2', { pollInterval: 10 }), (e) => e.code === 'denied');
  state.eventAnswer = { authreply: 'reply-from-phone' };
});

test('registerExtAuth builds the QR payload with the request hash and completes the pairing', async () => {
  state.regPolls = 0; state.regReadyAfter = 2;
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'system:config');
  let qr = null;
  const result = await hem.registerExtAuth(token, { pollInterval: 10, onQrCode: (text, payload) => { qr = { text, payload }; } });
  const expectedHash = b64(new Uint8Array(await crypto.subtle.digest('SHA-256', Buffer.from('REQUEST-JWT'))));
  assert.deepEqual(JSON.parse(qr.text), { link: 'https://api.encedo.com/r/RID1', hash: expectedHash, user: 'Ann', email: 'ann@example.com', hostname: 'my.ence.do' });
  assert.deepEqual(Object.keys(qr.payload), ['link', 'hash', 'user', 'email', 'hostname'], 'key order is what the phone parses');
  assert.equal(result.paired, true);
  assert.deepEqual(result.got, { confirmed: 'PID9' }, 'device confirmation is forwarded to finalise');
  const validate = state.log.find((l) => l.path === '/dev/api/auth/ext/validate');
  assert.deepEqual(validate.body, { pid: 'PID9', reply: 'PHONE-REPLY' });
});

test('paired authenticators: mac carries epk, list and delete round-trip', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'system:config');
  const mac = await hem.getExtAuthMac(token);
  assert.deepEqual(mac, { nonce: 'N', mac: 'M', eid: state.eid, epk: 'EPK-' + state.eid });
  assert.deepEqual(await hem.listExtAuth(token), [{ pid: 'PID9', label: 'Phone' }]);
  assert.deepEqual(await hem.deleteExtAuth(token, 'PID9'), { deleted: 'PID9' });
  const del = state.log.filter((l) => l.path === '/brk/notify/subscribers/delete').pop();
  assert.equal(del.body.pid, 'PID9');
  assert.equal(del.body.epk, 'EPK-' + state.eid);
  state.paired = true;
  assert.equal(await hem.hasExtAuth(), true);
  state.paired = false;
  assert.equal(await hem.hasExtAuth(), false);
});

test('broker downloads return bytes and domain helpers map status codes', async () => {
  const broker = new Broker(`${base}/brk`);
  const fw = await broker.download('firmware', 'v2.0.1+/x');
  assert.ok(fw instanceof Uint8Array);
  assert.deepEqual([...fw], [1, 2, 3, 4, 5]);
  assert.deepEqual(await broker.domainPredefs(), { prefix: ['my', 'dev'] });
  assert.equal(await broker.domainTaken('my'), true);
  assert.equal(await broker.domainTaken('free'), false);
  const share = await broker.shareEmailPubkey('bob@example.com', { kid: 'K1' });
  assert.equal(share.got.email, 'bob@example.com');
  assert.deepEqual(JSON.parse(Buffer.from(share.got.msg, 'base64').toString()), { kid: 'K1' });
});

test('registerDomain asks for a CSR, registers and installs the tls block', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'system:config');
  const tls = await hem.registerDomain(token, 'my', { ip: '192.168.7.1' });
  assert.equal(tls.prefix, 'my');
  assert.deepEqual(tls.got, { genuine: 'GEN', csr: 'CSR', ip: '192.168.7.1' });
  const install = state.log.filter((l) => l.path === '/dev/api/system/config' && l.method === 'POST').pop();
  assert.deepEqual(install.body, { tls });
  assert.ok(install.auth?.startsWith('Bearer '), 'config writes carry the token');
  const again = await hem.registerDomain(token, 'my', { newCertificate: false });
  assert.deepEqual(again.got, { genuine: 'GEN' }, 're-registration uses the attestation from the auth challenge only');
});

test('a prefix of the owner\'s choosing is confirmed by e-mail before the tls block arrives', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'system:config');
  const seen = [];
  const tls = await hem.registerDomain(token, 'alice', { ip: '192.168.7.1', pollInterval: 5, onPending: (st) => seen.push(st) });
  assert.deepEqual(seen, ['pending', 'email_confirmed']);
  assert.equal(tls.crt, 'C');
  assert.equal(tls.prefix, 'alice');
  const install = state.log.filter((l) => l.path === '/dev/api/system/config' && l.method === 'POST').pop();
  assert.deepEqual(install.body, { tls }, 'what the poll ended with is what the device gets');
  assert.deepEqual(await hem.broker.domainStatus('JOB-alice'), { status: 'done', emp: 'E', key: 'K', crt: 'C', prefix: 'alice' });
});

test('provision installs a certificate once and is a no-op afterwards', async () => {
  state.provisioned = false;
  const hem = mk();
  const cert = await hem.provision();
  assert.deepEqual(cert, { crt: 'CERT', genuine: 'GEN' });
  assert.equal(state.provisioned, true);
  assert.equal(await hem.provision(), null);
});

test('uploadFirmware sends raw bytes as octet-stream (Node transport)', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'system:upgrade');
  const r = await hem.uploadFirmware(token, new Uint8Array(1000), 'fw.bin');
  assert.equal(r.bytes, 1000);
  assert.equal(r.ct, 'application/octet-stream');
});

test('getVersion honours timeoutMs as a cancelled request', async () => {
  const hem = new HEM('http://127.0.0.1:9', { broker: `${base}/brk` });   // nothing listens on port 9
  await assert.rejects(hem.getVersion({ timeoutMs: 200 }), (e) => e instanceof HemError && (e.code === 'network' || e.code === 'timeout'));
});

// ---- audit log ---------------------------------------------------------------------
async function buildLog() {
  const keys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  state.loggerKeyB64 = b64(new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey)));
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, keys.privateKey, nonce));
  // What /api/logger/key answers with: the key, a fresh nonce, and its signature.
  const proof = crypto.getRandomValues(new Uint8Array(32));
  state.loggerNonce = b64(proof);
  state.loggerNonceSig = b64(new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, keys.privateKey, proof)));
  const hmacKey = await crypto.subtle.importKey('raw', nonce, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const seal = async (prefix) => {
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, Buffer.from(prefix))).subarray(0, 16);
    return prefix + b64url(mac);
  };
  const lines = ['# encedo audit log'];
  lines.push(await seal(`${(1).toString(16)}|1700000000|0|0|${b64url(nonce)}|${b64url(sig)}|`));
  lines.push(await seal(`${(2).toString(16)}|1700000001|3|1|auth ok user|`));
  lines.push(await seal(`${(2).toString(16)}|1700000002|3|2|auth ok user again|`));   // repeated counter is allowed
  lines.push(await seal(`${(3).toString(16)}|1700000003|5|0|storage unlock disk0|`));
  state.logText = lines.join('\n') + '\n';
}

test('verifyLog accepts a well-formed log and names the first bad line', async () => {
  await buildLog();
  assert.deepEqual(await verifyLog(state.loggerKeyB64, state.logText), { ok: true, lines: 4 });

  const tampered = state.logText.replace('storage unlock disk0', 'storage unlock disk1');
  assert.deepEqual(await verifyLog(state.loggerKeyB64, tampered), { ok: false, lines: 3, line: 3, reason: 'hmac' });

  const gap = state.logText.replace(/^3\|/m, '9|');
  assert.deepEqual(await verifyLog(state.loggerKeyB64, gap), { ok: false, lines: 3, line: 9, reason: 'sequence' });

  const otherKey = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const wrongKey = b64(new Uint8Array(await crypto.subtle.exportKey('raw', otherKey.publicKey)));
  assert.equal((await verifyLog(wrongKey, state.logText)).reason, 'signature');
});

test('the logger key is only worth something if the device signed its nonce', async () => {
  await buildLog();
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'logger:get');
  const answer = await hem.getLoggerKey(token);
  assert.equal(await verifyLoggerKey(answer), true);

  assert.equal(await verifyLoggerKey({ ...answer, nonce: b64(crypto.getRandomValues(new Uint8Array(32))) }), false, 'a nonce it did not sign');
  assert.equal(await verifyLoggerKey({ ...answer, key: state.spkB64 }), false, 'another key entirely');
  assert.equal(await verifyLoggerKey({ key: answer.key }), false, 'no proof at all');
  assert.equal(await verifyLoggerKey(undefined), false);
});

test('verifyLogEntry fetches key and file and verifies them', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'logger:get');
  const r = await hem.verifyLogEntry(token, 7);
  assert.equal(r.ok, true);
  assert.equal(r.lines, 4);
  assert.equal(r.text, state.logText);
});

// ---- BIP39 master secret -------------------------------------------------------------

// The official BIP39 English vectors (Trezor test set).
test('listKeys pages the repository and reports its total', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'keymgmt:list');
  const first = await hem.listKeys(token, 0, 2);
  assert.equal(first.total, 3);
  assert.deepEqual(first.list.map((k) => k.kid), ['K1', 'K2']);
  assert.equal(first.list[0].label, 'git-signing');
  assert.equal(Buffer.from(first.list[0].description).toString(), 'Commits and tags');
  assert.equal(first.list[0].created, 1738454400);
  assert.equal(first.list[1].updated, 1738454402);

  const second = await hem.listKeys(token, 2, 2);
  assert.deepEqual(second.list.map((k) => k.kid), ['K3']);
  assert.equal(second.list[0].description, null, 'an empty description is null, not an empty array');
  assert.equal(second.total, 3);
});

test('createKeyPair sends a mode only where the device wants one', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'keymgmt:gen');
  const sent = () => state.log.filter((e) => e.path === '/dev/api/keymgmt/create').at(-1).body;

  await hem.createKeyPair(token, 'signing', 'ED25519', 'ZA==');
  assert.equal(sent().mode, 'ExDSA', 'the 25519 defaults are unchanged');
  await hem.createKeyPair(token, 'wrap', 'MLKEM768', 'ZA==');
  assert.equal('mode' in sent(), false, 'a key with one possible use carries no mode');
  await hem.createKeyPair(token, 'nist', 'SECP384R1', 'ZA==', 'ECDH,ExDSA');
  assert.equal(sent().mode, 'ECDH,ExDSA', "a curve that can do both takes the caller's word");
  assert.deepEqual(Object.keys(sent()).sort(), ['descr', 'label', 'mode', 'type']);

  const pub = await hem.getPubKey(token, 'NEW1');
  assert.equal(pub.pubkey, 'PUB');
});

const VECTORS = [
  ['00000000000000000000000000000000', 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'],
  ['0000000000000000000000000000000000000000000000000000000000000000', ('abandon '.repeat(23) + 'art')],
  ['7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f', 'legal winner thank year wave sausage worth useful legal winner thank yellow'],
  ['80808080808080808080808080808080', 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above'],
  ['ffffffffffffffffffffffffffffffff', ('zoo '.repeat(11) + 'wrong')],
  ['ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', ('zoo '.repeat(23) + 'vote')],
];
const bytes = (hex) => new Uint8Array(Buffer.from(hex, 'hex'));
const hex = (b) => Buffer.from(b).toString('hex');

test('BIP39 encoding matches the official vectors, both ways', async () => {
  for (const [entropy, mnemonic] of VECTORS) {
    assert.equal(await entropyToMnemonic(bytes(entropy)), mnemonic, entropy);
    assert.equal(hex(await mnemonicToEntropy(mnemonic)), entropy, mnemonic);
  }
});

test('generateMnemonic makes 24 distinct words that round-trip', async () => {
  const seen = new Set();
  for (let i = 0; i < 20; i++) {
    const m = await generateMnemonic();
    assert.equal(m.split(' ').length, 24);
    const e = await mnemonicToEntropy(m);
    assert.equal(e.length, 32);
    assert.equal(await entropyToMnemonic(e), m);
    seen.add(m);
  }
  assert.equal(seen.size, 20, 'every generated secret is different');
  assert.equal((await generateMnemonic(128)).split(' ').length, 12);
  await assert.rejects(generateMnemonic(200), (e) => e.code === 'mnemonic_invalid');
});

test('a mistyped word is caught and named, and the checksum is enforced', async () => {
  const good = VECTORS[1][1];
  assert.equal(await validateMnemonic(good), true);

  // a word that is not in the list: the error says which one
  const typo = good.split(' '); typo[6] = 'abandonn';
  const e1 = await mnemonicToEntropy(typo.join(' ')).catch((e) => e);
  assert.equal(e1.code, 'mnemonic_invalid');
  assert.deepEqual(e1.data, { word: 7, value: 'abandonn' });

  // a real word in the wrong place: the checksum catches it
  const swapped = good.split(' '); swapped[3] = 'ability';
  await assert.rejects(mnemonicToEntropy(swapped.join(' ')), (e) => e.code === 'mnemonic_checksum');
  assert.equal(await validateMnemonic(swapped.join(' ')), false);

  // wrong length
  await assert.rejects(mnemonicToEntropy('abandon abandon abandon'), (e) => e.code === 'mnemonic_invalid');

  // case and spacing do not matter
  assert.equal(hex(await mnemonicToEntropy('  ABANDON   ' + 'abandon '.repeat(22) + 'ART ')), VECTORS[1][0]);
});

test('initialize with a mnemonic writes that key as masterkey', async () => {
  const hem = mk();
  const mnemonic = await generateMnemonic();
  const entropy = await mnemonicToEntropy(mnemonic);

  const r = await hem.initialize({ mnemonic }, 'user-password', { user: 'Ann', hostname: 'my.ence.do' });
  assert.equal(r.inited, true);

  // The master public key on the device is X25519(entropy) — the words are the key.
  const priv = await crypto.subtle.importKey('pkcs8',
    Buffer.concat([Buffer.from('302e020100300506032b656e042204209'.slice(0, 32), 'hex'), Buffer.from(entropy)]),
    'X25519', false, ['deriveBits']).catch(() => null);
  assert.ok(state.initCfg.masterkey, 'masterkey written');
  assert.equal(state.initCfg.user, 'Ann');
  assert.equal(state.initIss, state.initCfg.masterkey, 'the eJWT is signed by the master key');
  assert.notEqual(state.initCfg.userkey, state.initCfg.masterkey);

  // The same words authorise afterwards, and produce the same public key.
  const token = await hem.authorizeMaster(mnemonic, 'system:config');
  assert.equal(jwtParse(token).scope, 'system:config');
  const authEjwt = state.log.filter((l) => l.path === '/dev/api/auth/token' && l.method === 'POST').pop();
  const iss = JSON.parse(Buffer.from(authEjwt.body.auth.split('.')[1], 'base64url').toString()).iss;
  assert.equal(iss, state.initCfg.masterkey, 'authorizeMaster signs with the master key');

  // A wrong word never reaches the network.
  const before = state.log.length;
  await assert.rejects(hem.authorizeMaster(mnemonic.replace(/^\S+/, 'zoo'), 'keymgmt:list'), (e) => e.code === 'mnemonic_checksum');
  assert.equal(state.log.length, before, 'no request for an invalid mnemonic');
});

test('the v1 derivation is available for an existing device and differs from the new one', async () => {
  const hem = mk();
  const mnemonic = VECTORS[1][1];   // 24 x abandon ... art
  await hem.authorizeMaster(mnemonic, 'legacy-scope', 300, { legacy: true });
  const ejwt = state.log.filter((l) => l.path === '/dev/api/auth/token' && l.method === 'POST').pop();
  const legacyIss = JSON.parse(Buffer.from(ejwt.body.auth.split('.')[1], 'base64url').toString()).iss;

  const hem2 = mk();
  await hem2.authorizeMaster(mnemonic, 'new-scope');
  const ejwt2 = state.log.filter((l) => l.path === '/dev/api/auth/token' && l.method === 'POST').pop();
  const newIss = JSON.parse(Buffer.from(ejwt2.body.auth.split('.')[1], 'base64url').toString()).iss;

  assert.notEqual(legacyIss, newIss, 'the two derivations give different master keys');
  // Regression vector for the all-zero 24-word mnemonic, taken from the v1
  // libraries themselves (jsbip39 + sjcl + tweetnacl, run against this value).
  assert.equal(legacyIss, 'npHoBqiizdNniy/kAK2QJnlTAdGVxgA7dza2FKIaqhY=');
});
