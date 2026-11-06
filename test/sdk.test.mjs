// End-to-end test of hem-sdk.js against an in-process mock of the device and
// the broker. Run: node --test test/sdk.test.mjs
//
// The mock speaks the wire format the SDK expects (see the PHP reference in
// hem-api-tester for the device side); it verifies the eJWT the SDK signs, so
// the password path is checked cryptographically, not only for shape.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import nodeCrypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { HEM, Broker, Attest, HemError, jwtParse, verifyLog, verifyLoggerKey, generateMnemonic, entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from '../hem-sdk.js';

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
  fwChecks: 0,
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
    if (!req.headers.authorization) return json(res, 200, body.att ? { att: { csr: b64([0x30, 0x82]) } } : undefined);   // bootstrap
    return json(res, 200, { updated: true, received: body });
  }
  if (path === '/dev/api/system/config/attestation' && req.method === 'POST') return json(res, 200, { attestation: 'eyJ.x.y' });
  if (path.startsWith('/dev/api/system/config/attestation')) return json(res, 200, state.provisioned ? { genuine: 'GEN' } : { genuine: 'GEN', csr: 'CSR', key: 'KEY' });
  if (path === '/dev/api/system/config/provisioning') { state.provisioned = true; return json(res, 200, { installed: true }); }
  if (path === '/dev/api/auth/token' && req.method === 'GET') return json(res, 200, { eid: state.eid, spk: state.spkB64, jti: 'jti-1' });   // no genuine: only auth/init has one
  if (path === '/dev/api/auth/token' && req.method === 'POST') {
    const { ok, payload } = await verifyEjwt(body.auth);
    if (!ok) return json(res, 401, { error: 'bad signature' });
    return json(res, 200, { token: fakeJwt({ scope: payload.scope, exp: payload.exp, sub: 'user', ...(payload.ctx ? { ctx: payload.ctx } : {}) }) });
  }
  if (path === '/dev/api/auth/init' && req.method === 'GET') return json(res, 200, { eid: state.eid, spk: state.spkB64, jti: 'jti-init', exp: Math.floor(Date.now() / 1000) + 300 });
  if (path === '/dev/api/auth/init' && req.method === 'POST') {
    const { ok, payload } = await verifyEjwt(body.init);
    if (!ok) return json(res, 401, { error: 'bad signature' });
    state.initCfg = payload.cfg;
    state.initIss = payload.iss;
    return json(res, 200, { instanceid: 'INST-1', token: fakeJwt({ scope: 'system:config', sub: 'U', exp: Math.floor(Date.now() / 1000) + 28800 }) });
  }
  if (path === '/dev/api/auth/ext/request') return json(res, 200, { authreq: 'AUTHREQ', epk: body.epk });
  if (path === '/dev/api/auth/ext/token') return json(res, 200, { token: fakeJwt({ scope: 'remote', exp: Math.floor(Date.now() / 1000) + 300 }) });
  if (path === '/dev/api/auth/ext/init') return json(res, 200, { eid: state.eid, request: 'REQUEST-JWT' });
  if (path === '/dev/api/auth/ext/validate') return json(res, 200, { confirmed: body.pid });
  if (path === '/dev/api/auth/ext/mac') return json(res, 200, { nonce: 'N', mac: 'M', eid: state.eid });
  if (path === '/dev/api/system/upgrade/upload_fw' || path === '/dev/api/system/upgrade/upload_ui') {
    state.fwChecks = 0;
    state.upload = { bytes: raw.length, ct: req.headers['content-type'], disposition: req.headers['content-disposition'] };
    return json(res, 200);
  }
  // The device verifies in the background: 202 while at it, 200 with the result once done.
  if (path === '/dev/api/system/upgrade/check_fw') return ++state.fwChecks < 3 ? json(res, 202, null) : json(res, 200, { verified: true, fwv: 'v9' });
  if (path === '/dev/api/system/upgrade/install_fw') return json(res, 200, { installing: true });
  if (path === '/dev/api/keymgmt/create' || path === '/dev/api/keymgmt/derive') {
    return json(res, 200, { kid: 'NEW1', type: 'ATT,PKEY,ExDSA,' + body.type, label: body.label, created: 1738454400, updated: 1738454400, ...(body.return_pubkey ? { pubkey: b64([1, 2, 3]) } : {}) });
  }
  if (path === '/dev/api/keymgmt/import') return json(res, 200, { kid: 'IMP1' });
  if (path.startsWith('/dev/api/keymgmt/get/')) return json(res, 200, { type: 'ATT,PKEY,ExDSA,ED25519', label: 'git-signing', pubkey: b64([9, 9]), created: 1738454400, updated: 1738454400 });
  if (path.startsWith('/dev/api/keymgmt/list/')) {
    // /list/<offset>/<limit>[/pubkey]; a CRC-broken record takes a slot but is not listed
    const [offset, limit] = path.split('/').slice(5, 7).map(Number);
    const slots = state.keys.slice(offset, offset + limit);
    const list = slots.filter((k) => !k.broken).map((k) => (path.endsWith('/pubkey') ? { ...k, pubkey: b64([7]) } : k));
    return json(res, 200, { offset, deleted: 1, invalid: slots.length - list.length, total: state.keys.length, listed: slots.length, list });
  }
  if (path === '/dev/api/keymgmt/search') {
    // state.matches: a paged search - `offset` skips matches, a page holds at most
    // `limit` and at most state.pageCut of them (the device's 3-PQC-keys cut).
    if (state.matches) {
      const n = Math.min(body.limit, state.pageCut ?? body.limit);
      const list = state.matches.slice(body.offset, body.offset + n);
      return json(res, 200, { offset: body.offset, deleted: 0, invalid: 0, total: 99, listed: list.length, list });
    }
    return json(res, 200, { offset: body.offset, deleted: 0, invalid: 0, total: 9, listed: 1, list: [state.keys[0]] });
  }
  if (path === '/dev/api/crypto/exdsa/verify' || path === '/dev/api/crypto/hmac/verify' || path === '/dev/api/crypto/pqc/mldsa/verify') {
    return json(res, 200, { verified: Buffer.from(body.msg, 'base64').toString() === 'good' });   // 200 either way, as the device does
  }
  if (path === '/dev/api/crypto/cipher/encrypt') return json(res, 200, { ciphertext: b64([1]), iv: b64([2]), tag: b64([3]) });
  if (path === '/dev/api/crypto/ecdh') {
    if (body.hkdf_args) return json(res, 200, { hkdf: body.hkdf_args.map((_, i) => b64([i + 1])) });
    return json(res, 200, { ecdh: b64(new Uint8Array(48)) });   // a P-384 raw secret
  }
  if (path === '/dev/api/crypto/exdsa/sign' || path === '/dev/api/crypto/pqc/mldsa/sign') return json(res, 200, { sign: b64([7, 7]) });
  if (path === '/dev/api/crypto/cipher/wrap') return json(res, 200, { wrapped: b64(new Uint8Array(40)) });
  if (path === '/dev/api/crypto/hmac/hash') return json(res, 200, { mac: b64(new Uint8Array(32)) });
  if (path.startsWith('/dev/api/storage/unlock')) return json(res, 200);
  if (path === '/dev/api/crypto/pqc/xwing/encaps') return json(res, 200, { alg: 'X-Wing', ss: b64(new Uint8Array(32)), ct: b64(new Uint8Array(1120)) });
  if (path === '/dev/api/crypto/pqc/xwing/decaps') return json(res, 200, { alg: 'X-Wing', ss: b64(new Uint8Array(32)) });
  if (path === '/dev/api/crypto/hpke/seal') return json(res, 200, { mode: 'base', suite: '647a-0001-0003', kem: 'X-Wing', kdf: 'HKDF-SHA256', aead: 'CHACHA20-POLY1305', enc: b64([1, 2]), ct: b64([3, 4]) });
  if (path === '/dev/api/crypto/hpke/open') return json(res, 200, { mode: 'base', suite: '647a-0001-0003', plaintext: b64(Buffer.from('opened')) });
  if (path === '/dev/api/crypto/kdf') return json(res, 200, { okm: b64(new Uint8Array(body.len)) });
  if (path === '/dev/api/crypto/hmac/otp') {
    if (body.code === undefined) return json(res, 200, { code: '287082', step: 1 });
    return json(res, 200, body.code === '287082' ? { verified: true, step: 59321047 } : { verified: false });
  }
  if (path.startsWith('/dev/api/crypto/random/')) return json(res, 200, { rnd: b64(new Uint8Array(Number(path.split('/').pop()))) });
  const defragReport = { used: 114848, keys: 243, deleted: 46, deleted_size: 12352, invalid: 0, duplicates: 0, reclaimable: true, reclaimable_size: 12352, reserved: 'idle' };
  if (path === '/dev/api/system/defrag/check') return json(res, 200, defragReport);
  if (path === '/dev/api/system/defrag/start') return json(res, state.defragStatus ?? 202, defragReport);
  if (path.startsWith('/dev/api/logger/key')) {
    // /logger/key/<nonce base64url> signs the caller's nonce; without it, a nonce of the device's own
    const asked = path.split('/')[5];
    if (asked) return json(res, 200, { key: state.loggerKeyB64, nonce: b64(Buffer.from(asked, 'base64url')), nonce_signed: b64(new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, state.loggerPriv, Buffer.from(asked, 'base64url')))) });
    return json(res, 200, { key: state.loggerKeyB64, nonce: state.loggerNonce, nonce_signed: state.loggerNonceSig });
  }
  if (path.startsWith('/dev/api/logger/')) { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end(state.logText); }

  // ---- attest.encedo.com -------------------------------------------------------
  if (path === '/att/v1/validate') return json(res, 200, { status: 'valid', expired: false });
  if (path.startsWith('/att/v1/skid/')) return json(res, 200, { known: true });
  if (path === '/att/v1/pki') {
    const PKIs = JSON.parse(readFileSync(new URL('./attest-test-pki.json', import.meta.url), 'utf8'));
    return json(res, 200, { certificates: [PKIs.root, PKIs.attestation, PKIs.custody].map((pem) => ({ subject: 'CN', issuer: 'CN', not_after: 0, sha256: '', pem })) });
  }

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
  const t1 = await hem.authorizePassword('correct horse', 'keymgmt:list', { expSeconds: 120 });
  const p = jwtParse(t1);
  assert.equal(p.scope, 'keymgmt:list');
  const before = state.log.length;
  const t2 = await hem.authorizePassword(null, 'keymgmt:list');
  assert.equal(t2, t1, 'second call is served from the cache');
  assert.equal(state.log.length, before, 'no request for a cached scope');
  const t3 = await hem.authorizePassword(null, 'system:config');
  assert.equal(jwtParse(t3).scope, 'system:config', 'escalation reuses derived keys without a password');
});

test('a password can be used once and not kept, and tokens are cached either way', async () => {
  const hem = mk();
  await hem.authorizePassword('correct horse', 'keymgmt:list', { remember: false });
  // The token is cached, so the scope it was taken for needs nothing more.
  assert.ok(await hem.authorizePassword(null, 'keymgmt:list'));
  // Another scope has no token and no key to make one with.
  await assert.rejects(hem.authorizePassword(null, 'keymgmt:gen'), (e) => e.code === 'auth_password_required');
  assert.ok(await hem.authorizePassword('correct horse', 'keymgmt:gen', { remember: false }));

  // Remembered, the key answers for every scope that follows.
  const kept = mk();
  await kept.authorizePassword('correct horse', 'keymgmt:list');
  assert.ok(await kept.authorizePassword(null, 'keymgmt:gen'), 'a scope it has no token for still works');
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
  await hem.authorizePassword('correct horse', 'keymgmt:list', { expSeconds: 120 });
  await hem.authorizePassword(null, 'logger:get');
  assert.deepEqual(hem.tokens.map((t) => t.scope).sort(), ['keymgmt:list', 'logger:get']);
  assert.ok(hem.tokens.every((t) => typeof t.exp === 'number' && !('token' in t)), 'scope and expiry, nothing else');
  hem.clearCache();
  assert.deepEqual(hem.tokens, []);
});

test('authorizeRemote sends the scope and the optional ctx / note; the lifetime is the phone\'s', async () => {
  const hem = mk();
  await hem.authorizeRemote('system:config', { pollInterval: 5, ctx: 'session-7', note: 'Sign invoice 12/2026' });
  const sent = state.log.filter((e) => e.path === '/dev/api/auth/ext/request').at(-1).body;
  assert.equal(sent.scope, 'system:config');
  assert.equal(sent.ctx, 'session-7');
  assert.equal(sent.note, 'Sign invoice 12/2026');
  assert.ok(sent.epk, 'and the broker session key it belongs to');
  assert.equal('exp' in sent, false, 'ext/request has no exp: the authreply sets the token lifetime');
  hem.clearKeys();
  await hem.authorizeRemote('keymgmt:list', { pollInterval: 5 });
  const plain = state.log.filter((e) => e.path === '/dev/api/auth/ext/request').at(-1).body;
  assert.deepEqual(Object.keys(plain).sort(), ['epk', 'scope']);
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
  assert.deepEqual(again.got, { genuine: 'GEN' }, 're-registration sends the attestation only');
  assert.ok(state.log.some((l) => l.path === '/dev/api/system/config/attestation'), 'taken from config/attestation: the auth challenge carries none');
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

test('the firmware check answers null while the device is still at it, and waitFirmwareCheck polls through', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'system:upgrade');
  await hem.uploadFirmware(token, new Uint8Array([1, 2, 3]));
  assert.equal(await hem.checkFirmware(token), null, '202: not done');
  let pending = 0;
  const result = await hem.waitFirmwareCheck(token, { pollInterval: 5, onPending: () => pending++ });
  assert.deepEqual(result, { verified: true, fwv: 'v9' });
  assert.equal(pending, 1, 'one more 202 before the 200');
  assert.deepEqual(await hem.installFirmware(token), { installing: true });
});

test('uploads go under the only names the device takes (Node transport)', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'system:upgrade');
  await hem.uploadFirmware(token, new Uint8Array(1000));
  assert.equal(state.upload.bytes, 1000);
  assert.equal(state.upload.ct, 'application/octet-stream');
  assert.match(state.upload.disposition, /filename="firmware\.bin"/);
  await hem.uploadFirmware(token, Buffer.from(':10000000FFFF\n'));
  assert.match(state.upload.disposition, /filename="firmware\.hex"/, 'Intel HEX is told by its first byte');
  await hem.uploadFirmware(token, new Uint8Array([0x3a, 1]), { format: 'bin' });
  assert.match(state.upload.disposition, /filename="firmware\.bin"/, 'unless the caller says otherwise');
  await hem.uploadUi(token, new Uint8Array(10));
  assert.match(state.upload.disposition, /filename="webroot\.tar"/);
});

test('getVersion honours timeoutMs as a cancelled request', async () => {
  const hem = new HEM('http://127.0.0.1:9', { broker: `${base}/brk` });   // nothing listens on port 9
  await assert.rejects(hem.getVersion({ timeoutMs: 200 }), (e) => e instanceof HemError && (e.code === 'network' || e.code === 'timeout'));
});

// ---- audit log (format v2) -----------------------------------------------------------
// A file as the firmware writes it: a header certifying a per-file Ed25519 key
// with the device log key, every line signed with the per-file key, a key
// rotation at a day change (LOGGER_KEY_ROTATE naming the next key, then its header).
const ed = async (priv, bytes) => new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, priv, bytes));
const rawPub = async (kp) => new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));

async function buildLog() {
  const dev = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  state.loggerPriv = dev.privateKey;
  state.loggerKeyB64 = b64(await rawPub(dev));
  const proof = crypto.getRandomValues(new Uint8Array(32));   // what /api/logger/key signs without a nonce of ours
  state.loggerNonce = b64(proof);
  state.loggerNonceSig = b64(await ed(dev.privateKey, proof));

  const file1 = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const file2 = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pub1 = await rawPub(file1), pub2 = await rawPub(file2);
  const header = async (pub) => b64url(Buffer.concat([pub, await ed(dev.privateKey, pub)]));
  const signed = async (key, text) => text + b64url(await ed(key.privateKey, Buffer.from(text)));
  const lines = ['# Encedo nGINE FW v1.3.0'];
  lines.push(await signed(file1, `0|65000000|0|0|v2|${await header(pub1)}|`));
  lines.push(await signed(file1, `1|65000001|d|0|U|${b64url(Buffer.from('logger:get'))}|`));
  lines.push(await signed(file1, `2|65000002|33|1||${b64url(Uint8Array.of(5, 0, 0, 0))}|`));        // 5 events lost
  lines.push(await signed(file1, `3|65015180|32|0||${b64url(pub2)}|`));                            // day change
  lines.push(await signed(file2, `4|65015180|0|0|v2|${await header(pub2)}|`));
  lines.push(await signed(file2, `5|65015181|34|0|U|${b64url(Buffer.from('0rw'))}|`));
  state.logText = lines.join('\n') + '\n';
  return { dev, file1, file2, pub1, pub2, header, signed };
}

test('verifyLog checks a v2 file line by line and names the first failure', async () => {
  const { file1, file2, signed } = await buildLog();
  const good = await verifyLog(state.loggerKeyB64, state.logText);
  assert.deepEqual(good, { ok: true, lines: 6, headers: 2, rotations: 1, lost: 5, gaps: [] });
  assert.equal((await verifyLog(fromB64(state.loggerKeyB64), state.logText)).ok, true, 'the key as bytes too');
  assert.equal((await verifyLog(state.loggerKeyB64, state.logText.replace(/\n/g, '\r\n'))).ok, true, 'CRLF files too');

  const tampered = state.logText.replace(b64url(Buffer.from('0rw')), b64url(Buffer.from('1rw')));
  assert.deepEqual(await verifyLog(state.loggerKeyB64, tampered), { ok: false, lines: 5, headers: 2, rotations: 1, lost: 5, gaps: [], line: 7, reason: 'signature' });

  // A deleted line: the rest still verifies, the gap is reported and the file is not ok.
  const rows = state.logText.split('\n');
  const deleted = [...rows.slice(0, 3), ...rows.slice(4)].join('\n');
  const r = await verifyLog(state.loggerKeyB64, deleted);
  assert.equal(r.ok, false);
  assert.equal(r.reason, undefined, 'every line that is there verifies');
  assert.deepEqual(r.gaps, [{ after: 1, next: 3 }]);

  assert.equal((await verifyLog(state.loggerKeyB64, rows.slice(2).join('\n'))).reason, 'cut_front', 'a file cut at the front');
  const otherDevice = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  assert.equal((await verifyLog(b64(await rawPub(otherDevice)), state.logText)).reason, 'header', 'another device key');

  // A second header without the rotation line that announced its key.
  const noRotate = [...rows.slice(0, 4), await signed(file1, `3|65015180|d|0|U||`), ...rows.slice(5)].join('\n');
  assert.equal((await verifyLog(state.loggerKeyB64, noRotate)).reason, 'rotate');
  assert.equal((await verifyLog(state.loggerKeyB64, '# empty\n')).reason, 'no_header');
  assert.equal((await verifyLog(state.loggerKeyB64, rows[0] + '\n0|1|2|3\n')).reason, 'format');
  void file2;
});

test('the logger key is only worth something if the device signed our nonce', async () => {
  await buildLog();
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'logger:get');
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const answer = await hem.getLoggerKey(token, { nonce });
  assert.equal(state.log.at(-1).path, `/dev/api/logger/key/${b64url(nonce)}`, 'the nonce goes in the path, base64url');
  assert.equal(await verifyLoggerKey(answer, nonce), true);
  assert.equal(await verifyLoggerKey(await hem.getLoggerKey(token), nonce), false, 'a nonce of its own choosing proves nothing to us');
  assert.equal(await verifyLoggerKey(await hem.getLoggerKey(token)), true, 'though it is a valid signature');
  assert.equal(await verifyLoggerKey({ ...answer, key: state.spkB64 }, nonce), false, 'another key entirely');
  assert.equal(await verifyLoggerKey({ key: answer.key }), false, 'no proof at all');
  assert.equal(await verifyLoggerKey(undefined), false);
  await assert.rejects(hem.getLoggerKey(token, { nonce: new Uint8Array(16) }), (e) => e.code === 'invalid_arg');
});

test('verifyLogFile proves the key, fetches the file and verifies it', async () => {
  await buildLog();
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'logger:get');
  const r = await hem.verifyLogFile(token, '65000000');
  assert.equal(r.ok, true);
  assert.equal(r.keyProven, true);
  assert.equal(r.lines, 6);
  assert.equal(r.text, state.logText);
  const list = await hem.listLogFiles(token, { offset: 2, limit: 50 });
  void list;
  assert.equal(state.log.at(-1).path, '/dev/api/logger/list/2/50');
});

// ---- BIP39 master secret -------------------------------------------------------------

// The official BIP39 English vectors (Trezor test set).
test('listKeys pages by listed, splits the type and skips unreadable records', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'keymgmt:list');
  const first = await hem.listKeys(token, { limit: 2 });
  assert.equal(state.log.at(-1).path, '/dev/api/keymgmt/list/0/2');
  assert.equal(first.total, 3);
  assert.equal(first.listed, 2);
  assert.deepEqual(first.list.map((k) => k.kid), ['K1', 'K2']);
  assert.equal(first.list[0].label, 'git-signing');
  assert.equal(first.list[0].type, 'ED25519');
  assert.deepEqual(first.list[0].flags, ['ATT', 'PKEY', 'ExDSA']);
  assert.equal(Buffer.from(first.list[0].description).toString(), 'Commits and tags');
  assert.equal(first.list[0].created, 1738454400);
  assert.equal(first.list[1].updated, 1738454402);
  assert.equal(first.list[0].pubkey, null, 'no public key unless asked for');

  const second = await hem.listKeys(token, { offset: first.offset + first.listed, limit: 2, returnPubkey: true });
  assert.equal(state.log.at(-1).path, '/dev/api/keymgmt/list/2/2/pubkey');
  assert.deepEqual(second.list.map((k) => k.kid), ['K3']);
  assert.deepEqual([...second.list[0].pubkey], [7]);
  assert.equal(second.list[0].description, null, 'an empty description is null, not an empty array');

  state.keys[1].broken = true;
  const withHole = await hem.listKeys(token, { limit: 15 });
  assert.equal(withHole.listed, 3, 'the unreadable record takes its slot');
  assert.equal(withHole.invalid, 1);
  assert.deepEqual(withHole.list.map((k) => k.kid), ['K1', 'K3']);
  delete state.keys[1].broken;
});

test('searchKeys anchors the pattern on the base64 text and passes the filters', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'keymgmt:search');
  const sent = () => state.log.filter((e) => e.path === '/dev/api/keymgmt/search').at(-1).body;
  const enc = b64(Buffer.from('EXTAID'));
  const page = await hem.searchKeys(token, 'EXTAID');
  assert.deepEqual(sent(), { descr: '^' + enc, offset: 0, limit: 15 });
  assert.equal(page.list[0].type, 'ED25519');
  assert.equal(page.listed, 1);
  await hem.searchKeys(token, Buffer.from('EXTAID'), { match: 'suffix', offset: 15, type: 'ED25519', mode: 'ExDSA', returnPubkey: true });
  assert.deepEqual(sent(), { descr: enc + '$', offset: 15, limit: 15, type: 'ED25519', mode: 'ExDSA', return_pubkey: true });
  await hem.searchKeys(null, 'EXTAID', { match: 'contains' });
  assert.equal(sent().descr, enc);
});

test('listKeysAll and searchKeysAll walk every page, so nobody stops at the first 15', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', ['keymgmt:list', 'keymgmt:search']);
  const keys = state.keys;
  try {
    state.keys = Array.from({ length: 40 }, (_, i) => ({ kid: `L${i}`, type: 'PKEY,ECDH,CURVE25519', label: `k${i}` }));
    state.keys[16].broken = true;
    const listed = await Array.fromAsync(hem.listKeysAll(token));
    assert.equal(listed.length, 39, 'every readable key of 40, the broken one skipped');
    assert.equal(listed.at(-1).kid, 'L39');
    const listPaths = state.log.filter((e) => e.path.startsWith('/dev/api/keymgmt/list/')).slice(-3).map((e) => e.path);
    assert.deepEqual(listPaths, ['/dev/api/keymgmt/list/0/15', '/dev/api/keymgmt/list/15/15', '/dev/api/keymgmt/list/30/15'],
      'paged on listed (the broken record kept its slot), stopped at total');

    state.matches = Array.from({ length: 20 }, (_, i) => ({ kid: `S${i}`, type: 'PKEY,ECDH,CURVE25519', label: `s${i}` }));
    state.pageCut = 3;                       // pages end early, as with PQC keys and public keys
    const n = state.log.length;
    const found = await Array.fromAsync(hem.searchKeysAll(token, 'ETSEIC:', { returnPubkey: true }));
    assert.deepEqual(found.map((k) => k.kid), state.matches.map((k) => k.kid), 'all 20, in order, across short pages');
    const bodies = state.log.slice(n).filter((e) => e.path === '/dev/api/keymgmt/search').map((e) => e.body);
    assert.deepEqual(bodies.map((b) => b.offset), [0, 3, 6, 9, 12, 15, 18, 20], 'on from offset + listed until an empty page');
    assert.ok(bodies.every((b) => b.limit === 15 && b.return_pubkey === true && b.descr === '^' + b64(Buffer.from('ETSEIC:'))));

    state.matches = [];
    assert.deepEqual(await Array.fromAsync(hem.searchKeysAll(token, 'none')), [], 'nothing found is one request');
  } finally {
    state.keys = keys;
    delete state.matches;
    delete state.pageCut;
  }
});

test('key modes are checked against the type, as the device would', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'keymgmt:gen');
  const sent = (p = 'create') => state.log.filter((e) => e.path === `/dev/api/keymgmt/${p}`).at(-1).body;

  for (const type of ['ED25519', 'CURVE25519', 'ED448', 'MLKEM768', 'MLDSA65', 'AES256', 'SHA2-256']) {
    await hem.createKeyPair(token, 'k', type);
    assert.deepEqual(Object.keys(sent()).sort(), ['label', 'type'], `${type}: nothing it did not ask for`);
  }
  const ok = [['SECP256R1', 'ECDH,ExDSA'], ['SECP384R1', 'HPKE'], ['SECP256K1', 'ExDSA'], ['ED25519', 'ECDH'],
    ['CURVE25519', 'HPKE'], ['CURVE448', 'ECDH'], ['MLKEM1024', 'HPKE']];
  for (const [type, mode] of ok) {
    await hem.createKeyPair(token, 'k', type, { mode });
    assert.equal(sent().mode, mode, `${type} + ${mode}`);
  }
  const bad = [['SECP256K1', 'HPKE'], ['ED25519', 'HPKE'], ['CURVE25519', 'ExDSA'], ['ED448', 'ECDH'], ['MLDSA65', 'HPKE'], ['AES256', 'ECDH']];
  for (const [type, mode] of bad) {
    await assert.rejects(hem.createKeyPair(token, 'k', type, { mode }), (e) => e.code === 'bad_mode', `${type} + ${mode}`);
    await assert.rejects(hem.deriveKey(token, 'k', type, 'K1', { mode }), (e) => e.code === 'bad_mode');
  }
  await assert.rejects(hem.importPublicKey(token, 'k', 'CURVE25519', new Uint8Array(32), { mode: 'HPKE' }), (e) => e.code === 'bad_mode',
    'a public key needs no HPKE flag to be sealed to');

  const created = await hem.createKeyPair(token, 'signing', 'ED25519', { descr: 'git', returnPubkey: true });
  assert.deepEqual(sent(), { type: 'ED25519', label: 'signing', descr: b64(Buffer.from('git')), return_pubkey: true });
  assert.equal(created.kid, 'NEW1');
  assert.equal(created.type, 'ED25519');
  assert.deepEqual([...created.pubkey], [1, 2, 3]);

  await hem.deriveKey(token, 'tenant-7', 'AES256', 'K1', { hkdfSalt: 'tenant-7' });
  assert.deepEqual(sent('derive'), { type: 'AES256', label: 'tenant-7', kid: 'K1', hkdf_salt: b64(Buffer.from('tenant-7')) }, 'an HMAC parent: no peer');
  await hem.deriveKey(token, 'wg', 'CURVE25519', 'K2', { pubkey: new Uint8Array(32) });
  assert.equal(sent('derive').pubkey, b64(new Uint8Array(32)));

  await hem.importPublicKey(token, 'bob', 'ED25519', new Uint8Array([5, 6]), { descr: new Uint8Array([1]) });
  assert.deepEqual(sent('import'), { type: 'ED25519', label: 'bob', pubkey: b64([5, 6]), descr: b64([1]) });

  const info = await hem.getKeyPublicInfo(token, 'K1');
  assert.equal(info.kid, 'K1');
  assert.equal(info.type, 'ED25519');
  assert.deepEqual([...info.pubkey], [9, 9]);
});

test('verify endpoints answer 200 either way: the SDK reads verified', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'keymgmt:use:00112233445566778899aabbccddeeff');
  const kid = '00112233445566778899aabbccddeeff';
  const good = Buffer.from('good'), bad = Buffer.from('bad');
  assert.equal(await hem.exdsaVerify(token, kid, good, new Uint8Array(64)), true);
  assert.equal(await hem.exdsaVerify(token, kid, bad, new Uint8Array(64)), false, 'an invalid signature is false, not true');
  assert.equal(await hem.hmacVerify(token, kid, good, new Uint8Array(32)), true);
  assert.equal(await hem.hmacVerify(token, kid, bad, new Uint8Array(32)), false);
  assert.equal(await hem.mldsaVerify(token, kid, good, new Uint8Array(4)), true);
  assert.equal(await hem.mldsaVerify(token, kid, bad, new Uint8Array(4)), false);
});

test('the HKDF fields of a peer-key cipher are hkdf_ctx / hkdf_salt, checked before sending', async () => {
  const hem = mk();
  const kid = '00112233445566778899aabbccddeeff';
  const token = await hem.authorizePassword('correct horse', `keymgmt:use:${kid}`);
  await hem.cipherEncrypt(token, kid, Buffer.from('hi'), 'AES256-GCM', { pubkey: new Uint8Array(32), hkdfCtx: 'files:v1', hkdfSalt: new Uint8Array([1, 2]) });
  const sent = state.log.filter((e) => e.path === '/dev/api/crypto/cipher/encrypt').at(-1).body;
  assert.equal(sent.hkdf_ctx, b64(Buffer.from('files:v1')));
  assert.equal(sent.hkdf_salt, b64([1, 2]));
  assert.equal('ctx' in sent, false);
  await assert.rejects(hem.cipherEncrypt(token, kid, Buffer.from('hi'), 'AES256-GCM', { hkdfCtx: 'encedo-wrap:v1:' }), (e) => e.code === 'invalid_arg');
  await assert.rejects(hem.cipherEncrypt(token, kid, Buffer.from('hi'), 'AES256-GCM', { hkdfSalt: new Uint8Array(129) }), (e) => e.code === 'invalid_arg');
});

test('a raw ECDH secret is as long as the curve makes it; the peer is extKid or pubkey, as in deriveKey', async () => {
  const hem = mk();
  const kid = '00112233445566778899aabbccddeeff';
  const peerKid = 'ffeeddccbbaa99887766554433221100';
  const token = await hem.authorizePassword('correct horse', `keymgmt:use:${kid}`);
  const sent = () => state.log.filter((e) => e.path === '/dev/api/crypto/ecdh').at(-1).body;
  assert.equal((await hem.ecdh(token, kid, { extKid: peerKid })).length, 48, 'P-384');
  assert.deepEqual(sent(), { kid, ext_kid: peerKid });
  await hem.ecdh(token, kid, { pubkey: new Uint8Array(32), alg: 'HKDF-SHA2-256', hkdfSalt: new Uint8Array([1]), hkdfCtx: 'wg:v1', hkdfLen: 64 });
  assert.deepEqual(sent(), { kid, pubkey: b64(new Uint8Array(32)), alg: 'HKDF-SHA2-256', hkdf_salt: b64([1]), hkdf_ctx: b64(Buffer.from('wg:v1')), hkdf_len: 64 });
  await hem.ecdh(token, kid, { pubkey: new Uint8Array(32), alg: 'SHA2-256', hkdfCtx: 'ignored' });
  assert.deepEqual(sent(), { kid, pubkey: b64(new Uint8Array(32)), alg: 'SHA2-256' }, 'HKDF fields only with an HKDF-* alg');

  const n = state.log.length;
  const refused = (p, why) => assert.rejects(p, (e) => e.code === 'invalid_arg', why);
  await refused(hem.ecdh(token, kid, {}), 'no peer: ecdh has no meaning without one');
  await refused(hem.ecdh(token, kid), 'no options at all');
  await refused(hem.ecdh(token, kid, { extKid: peerKid, pubkey: new Uint8Array(32) }), 'both peers');
  await refused(hem.ecdh(token, kid, { pubkey: b64(new Uint8Array(32)) }), 'a base64 string is not key bytes');
  await refused(hem.ecdh(token, kid, { extKid: 'not-a-kid' }), 'extKid is 32 hex');
  await refused(hem.ecdh(token, kid, { pubkey: new Uint8Array(32), alg: 'HKDF-SHA2-256', hkdfLen: 15 }), 'hkdfLen below 16');
  await refused(hem.ecdh(token, kid, { pubkey: new Uint8Array(32), alg: 'HKDF-SHA2-256', hkdfLen: 16.5 }), 'hkdfLen a fraction');
  await refused(hem.ecdh(token, kid, { pubkey: new Uint8Array(32), alg: 'HKDF-SHA2-256', hkdfCtx: 'encedo-x' }), 'reserved context');
  await refused(hem.ecdh(token, kid, new Uint8Array(32)), 'the 1.3 positional peer (bytes)');
  await refused(hem.ecdh(token, kid, peerKid), 'the 1.3 positional peer (a KID)');
  await refused(hem.ecdh(token, kid, peerKid, { alg: 'SHA2-256' }), 'the 1.3 positional peer with options');
  assert.equal(state.log.length, n, 'every refusal before a request');

  const [enc, mac] = await hem.ecdhHkdf(token, kid, { pubkey: new Uint8Array(32), items: [{ hkdfCtx: 'enc', hkdfLen: 32 }, { hkdfCtx: 'mac' }] });
  assert.equal(sent().alg, 'HKDF-SHA2-256', 'the default hash');
  assert.deepEqual(sent().hkdf_args, [{ hkdf_ctx: b64(Buffer.from('enc')), hkdf_len: 32 }, { hkdf_ctx: b64(Buffer.from('mac')) }]);
  assert.deepEqual([...enc], [1]);
  assert.deepEqual([...mac], [2]);
  await hem.ecdhHkdf(token, kid, { extKid: peerKid, alg: 'HKDF-SHA2-512', items: [{}] });
  assert.equal(sent().ext_kid, peerKid);
  assert.equal(sent().alg, 'HKDF-SHA2-512');
  const m = state.log.length;
  await refused(hem.ecdhHkdf(token, kid, { pubkey: new Uint8Array(32), items: [] }), 'no items');
  await refused(hem.ecdhHkdf(token, kid, { pubkey: new Uint8Array(32), items: Array(9).fill({}) }), 'nine items');
  await refused(hem.ecdhHkdf(token, kid, { pubkey: new Uint8Array(32), alg: 'SHA2-256', items: [{}] }), 'not an HKDF alg');
  await refused(hem.ecdhHkdf(token, kid, { items: [{}] }), 'no peer');
  await refused(hem.ecdhHkdf(token, kid, { pubkey: new Uint8Array(32), items: [{ hkdfLen: 200 }] }), 'an item over 128');
  await refused(hem.ecdhHkdf(token, kid, new Uint8Array(32), 'HKDF-SHA2-256', [{}]), 'the 1.3 positional form');
  assert.equal(state.log.length, m, 'every refusal before a request');
});

test('a call in an older positional form throws instead of running with defaults', async () => {
  const hem = mk();
  const kid = '00112233445566778899aabbccddeeff';
  const token = await hem.authorizePassword('correct horse', `keymgmt:use:${kid}`);
  const n = state.log.length;
  const refused = (p, why) => assert.rejects(p, (e) => e.code === 'invalid_arg' && /MIGRATION/.test(e.message), why);
  await refused(hem.authorizePassword('correct horse', 'keymgmt:list', 900), 'expSeconds positionally would have become 300');
  await refused(hem.authorizePassword('correct horse', 'keymgmt:list', 900, { remember: false }), 'expSeconds before the options');
  await refused(hem.authorizeMaster('a b c', 'x', 300), 'authorizeMaster likewise');
  await refused(hem.exdsaSign(token, kid, 'm', 'SHA256WithECDSA'), 'alg positionally would have signed Ed25519');
  await refused(hem.exdsaVerify(token, kid, 'm', new Uint8Array(64), 'Ed25519'), 'exdsaVerify likewise');
  await refused(hem.hmacHash(token, kid, 'm', null, { extKid: kid }), 'hmacHash with alg before the options');
  await refused(hem.hmacVerify(token, kid, 'm', new Uint8Array(32), 'SHA2-256'), 'hmacVerify likewise');
  await refused(hem.xwingEncaps(token, kid, kid), 'xwingEncaps with a positional extKid');
  await refused(hem.xwingDecaps(token, kid, kid, new Uint8Array(1120)), 'xwingDecaps likewise');
  assert.equal(state.log.length, n, 'nothing reached the device');
  // The new forms with nothing optional still work.
  assert.ok(await hem.authorizePassword(null, 'keymgmt:gen'));
  assert.ok(await hem.authorizePassword(null, 'keymgmt:list', null), 'null options are no options');
});

test('signatures take bytes or text, a context as bytes, and deterministic ECDSA', async () => {
  const hem = mk();
  const kid = '00112233445566778899aabbccddeeff';
  const token = await hem.authorizePassword('correct horse', `keymgmt:use:${kid}`);
  const sent = (p) => state.log.filter((e) => e.path === `/dev/api/crypto/${p}`).at(-1).body;
  assert.deepEqual([...await hem.exdsaSign(token, kid, 'hello')], [7, 7]);
  assert.deepEqual(sent('exdsa/sign'), { kid, alg: 'Ed25519', msg: b64(Buffer.from('hello')) });
  await hem.exdsaSign(token, kid, new Uint8Array(32), { alg: 'ECDSA', det: true });
  assert.deepEqual(sent('exdsa/sign'), { kid, alg: 'ECDSA', msg: b64(new Uint8Array(32)), det: true });
  await hem.exdsaSign(token, kid, 'x', { alg: 'Ed25519ctx', ctx: 'app' });
  assert.equal(sent('exdsa/sign').ctx, b64(Buffer.from('app')), 'the context is encoded here, not by the caller');
  await hem.exdsaVerify(token, kid, 'good', new Uint8Array(64), { alg: 'Ed25519ctx', ctx: 'app' });
  assert.equal(sent('exdsa/verify').ctx, b64(Buffer.from('app')));

  await hem.mldsaSign(token, kid, new Uint8Array(64), { mode: 'ML-DSA-mu' });
  assert.deepEqual(sent('pqc/mldsa/sign'), { kid, msg: b64(new Uint8Array(64)), mode: 'ML-DSA-mu' });
  assert.equal(await hem.mldsaVerify(token, kid, 'good', new Uint8Array(4), { ctx: 'c', mode: 'ML-DSA' }), true);
  assert.deepEqual(sent('pqc/mldsa/verify'), { kid, msg: b64(Buffer.from('good')), sign: b64(new Uint8Array(4)), ctx: b64(Buffer.from('c')), mode: 'ML-DSA' });

  await hem.cipherWrap(token, kid, new Uint8Array(32), { alg: 'AES128', pubkey: new Uint8Array(32), hkdfCtx: 'psk' });
  assert.deepEqual(sent('cipher/wrap'), { kid, msg: b64(new Uint8Array(32)), alg: 'AES128', pubkey: b64(new Uint8Array(32)), hkdf_ctx: b64(Buffer.from('psk')) });
  await hem.cipherWrap(token, kid, new Uint8Array(32));
  assert.deepEqual(sent('cipher/wrap'), { kid, msg: b64(new Uint8Array(32)) }, 'AES256 by default, the device\'s');
  await assert.rejects(hem.hmacHash(token, kid, 'x', { alg: 'SHA2-256', pubkey: b64(new Uint8Array(32)) }), (e) => e.code === 'invalid_arg', 'a peer key is bytes');
});

test('one token for several scopes, cached for each of them', async () => {
  const hem = mk();
  const a = 'keymgmt:use:00112233445566778899aabbccddeeff', b = 'keymgmt:use:ffeeddccbbaa99887766554433221100';
  const before = state.log.length;
  const token = await hem.authorizePassword('correct horse', [a, b]);
  assert.deepEqual(jwtParse(token).scope, [a, b], 'the array goes to the device as an array');
  assert.equal(await hem.authorizePassword(null, b), token, 'a later single scope reuses it');
  assert.equal(await hem.authorizePassword(null, [b, a]), token, 'in any order');
  assert.equal(state.log.length - before, 2, 'one challenge and one exchange in all');
  assert.deepEqual(hem.tokens.map((t) => t.scope), [[a, b]]);

  const withCtx = await hem.authorizePassword(null, a, { ctx: 'job-7' });
  assert.notEqual(withCtx, token, 'a token with another ctx is another token');
  assert.equal(jwtParse(withCtx).ctx, 'job-7');
  for (const bad of [[], Array(9).fill(a).map((s, i) => s + i), [a, a], ['storage:disk0', 'storage:disk1:rw']]) {
    await assert.rejects(hem.authorizePassword(null, bad), (e) => e.code === 'invalid_arg', JSON.stringify(bad));
  }
});

test('attestation with our nonce, a disk unlocked read-only, and the init token cached', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'storage:disk0:rw');
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  await hem.getAttestation(token, { nonce });
  assert.equal(state.log.at(-1).path, `/dev/api/system/config/attestation/${b64url(nonce)}`);
  await assert.rejects(hem.getAttestation(token, { nonce: new Uint8Array(8) }), (e) => e.code === 'invalid_arg');
  await hem.unlockStorage(token, { mode: 'ro' });
  assert.equal(state.log.at(-1).path, '/dev/api/storage/unlock/ro');
  await hem.unlockStorage(token);
  assert.equal(state.log.at(-1).path, '/dev/api/storage/unlock');
  await assert.rejects(hem.unlockStorage(token, { mode: 'x' }), (e) => e.code === 'invalid_arg');
});

test('X-Wing and HPKE: two keys under one token, or a recipient outside the HEM', async () => {
  const hem = mk();
  const m = '00112233445566778899aabbccddeeff', x = 'ffeeddccbbaa99887766554433221100';
  const token = await hem.authorizePassword('correct horse', [`keymgmt:use:${m}`, `keymgmt:use:${x}`]);
  const sent = (p) => state.log.filter((e) => e.path === `/dev/api/crypto/${p}`).at(-1).body;
  const { alg, ss, ct } = await hem.xwingEncaps(token, m, { extKid: x });
  assert.equal(alg, 'X-Wing');
  assert.equal(ss.length, 32);
  assert.equal(ct.length, 1120);
  assert.deepEqual(sent('pqc/xwing/encaps'), { kid: m, ext_kid: x });
  assert.equal((await hem.xwingDecaps(token, m, ct, { extKid: x })).length, 32);
  assert.deepEqual(sent('pqc/xwing/decaps'), { kid: m, ext_kid: x, ct: b64(ct) });

  const sealed = await hem.hpkeSeal(token, { kid: m, extKid: x }, 'secret', { info: 'app:v1', aead: 'CHACHA20-POLY1305' });
  assert.deepEqual(sent('hpke/seal'), { kid: m, ext_kid: x, aead: 'CHACHA20-POLY1305', info: b64(Buffer.from('app:v1')), msg: b64(Buffer.from('secret')) });
  assert.equal(sealed.suite, '647a-0001-0003');
  assert.deepEqual([...sealed.enc], [1, 2]);
  await hem.hpkeSeal(token, { pubkey: new Uint8Array(32), kem: 'DHKEM-X25519' }, new Uint8Array([9]));
  assert.deepEqual(sent('hpke/seal'), { pubkey: b64(new Uint8Array(32)), kem: 'DHKEM-X25519', msg: b64([9]) });
  await assert.rejects(hem.hpkeSeal(token, { pubkey: b64(new Uint8Array(32)), kem: 'DHKEM-X25519' }, 'x'), (e) => e.code === 'invalid_arg');

  const plain = await hem.hpkeOpen(token, m, sealed.enc, sealed.ct, { extKid: x, info: 'app:v1', aead: 'CHACHA20-POLY1305' });
  assert.equal(Buffer.from(plain).toString(), 'opened');
  assert.deepEqual(sent('hpke/open'), { kid: m, ext_kid: x, aead: 'CHACHA20-POLY1305', info: b64(Buffer.from('app:v1')), enc: b64(sealed.enc), ct: b64(sealed.ct) });
});

test('kdf, one-time passwords and random bytes', async () => {
  const hem = mk();
  const kid = '00112233445566778899aabbccddeeff';
  const token = await hem.authorizePassword('correct horse', `keymgmt:use:${kid}`);
  const sent = (p) => state.log.filter((e) => e.path === `/dev/api/crypto/${p}`).at(-1).body;
  assert.equal((await hem.kdf(token, kid, 'HKDF', 32, { salt: 'tenant-7', info: 'enc' })).length, 32);
  assert.deepEqual(sent('kdf'), { kid, alg: 'HKDF', len: 32, salt: b64(Buffer.from('tenant-7')), info: b64(Buffer.from('enc')) });
  await hem.kdf(token, kid, 'SP800-108', 16, { info: new Uint8Array([1, 0, 2]) });
  assert.deepEqual(sent('kdf'), { kid, alg: 'SP800-108', len: 16, info: b64([1, 0, 2]) });
  await assert.rejects(hem.kdf(token, kid, 'SP800-108', 16, { salt: 's' }), (e) => e.code === 'invalid_arg');

  assert.deepEqual(await hem.otp(token, kid), { code: '287082', step: 1 });
  assert.deepEqual(sent('hmac/otp'), { kid, mode: 'TOTP' });
  await hem.otp(token, kid, { mode: 'HOTP', counter: 5, digits: 8 });
  assert.deepEqual(sent('hmac/otp'), { kid, mode: 'HOTP', digits: 8, counter: 5 });
  await assert.rejects(hem.otp(token, kid, { mode: 'HOTP' }), (e) => e.code === 'invalid_arg', 'HOTP needs a counter');
  await assert.rejects(hem.otp(token, kid, { counter: 1 }), (e) => e.code === 'invalid_arg', 'a counter is not TOTP');
  assert.deepEqual(await hem.otpVerify(token, kid, '287082', { window: 2 }), { verified: true, step: 59321047 });
  assert.deepEqual(sent('hmac/otp'), { kid, mode: 'TOTP', code: '287082', window: 2 });
  assert.deepEqual(await hem.otpVerify(token, kid, '000000'), { verified: false });

  assert.equal((await hem.random(token, 64)).length, 64);
  assert.equal(state.log.at(-1).path, '/dev/api/crypto/random/64');
  await assert.rejects(hem.random(token, 9000), (e) => e.code === 'invalid_arg');
});

test('defrag: a dry run, then a start that says whether the device restarts', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'system:config');
  const report = await hem.defragCheck(token);
  assert.equal(report.reclaimable, true);
  state.defragStatus = 202;
  assert.deepEqual(await hem.defragStart(token), { started: true, report });
  state.defragStatus = 200;
  assert.equal((await hem.defragStart(token)).started, false, 'nothing to reclaim: nothing written');
  state.defragStatus = 409;
  await assert.rejects(hem.defragStart(token), (e) => e.code === 'http_409' && e.data.invalid === 0, 'unreadable records: the report rides on the error');
});

test('bootstrap of a device out of the box: tls, and the EPA attestation key', async () => {
  const hem = mk();
  const { csr } = await hem.bootstrap({ att: { seed: new Uint8Array(32).fill(7), epoch: 0 } });
  assert.deepEqual([...csr], [0x30, 0x82]);
  const sent = state.log.at(-1);
  assert.equal(sent.auth, null, 'no token before personalisation');
  assert.deepEqual(sent.body, { att: { seed: b64(new Uint8Array(32).fill(7)), epoch: 0 } });
  assert.deepEqual(await hem.bootstrap({ tls: { pkey: 'K', crt: 'C' } }), { csr: null });
  await assert.rejects(hem.bootstrap({ att: { seed: new Uint8Array(16), epoch: 0 } }), (e) => e.code === 'invalid_arg');
  await assert.rejects(hem.bootstrap({}), (e) => e.code === 'invalid_arg');
});

// ---- attestation -------------------------------------------------------------------
// Tokens built the way the firmware builds them (api_system.c attestation_jwt_sign,
// hem_pop_*), signed with the device key of a TEST PKI (test/attest-test-pki.json).
const mockLog = () => state.log;   // the tests below name their own `state` (the verifier's)
const PKI = JSON.parse(readFileSync(new URL('./attest-test-pki.json', import.meta.url), 'utf8'));
const u16 = (b) => Buffer.concat([Buffer.from([b.length >> 8, b.length & 0xff]), Buffer.from(b)]);
const uuid4 = () => { const h = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('hex'); return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`; };

async function deviceToken({ state, key = null, pop = null, tamper = null, iat = Math.floor(Date.now() / 1000) }) {
  const priv = await crypto.subtle.importKey('pkcs8', Buffer.from(PKI.devicePkcs8, 'base64'), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', priv);
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  const header = { alg: 'ES256', typ: 'encedo-attest+jwt', kid: nodeCrypto.createHash('sha1').update(point).digest('hex'), jwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y } };
  const body = { iss: 'https://attest.encedo.com', aud: state.aud, iat, exp: iat + 300, nonce: b64(state.nonce), jti: uuid4(),
    device: { hwv: 'PPA rev 2.2', fwv: 'Encedo nGINE FW v1.3.0', blv: 'bl', assurance: 'hard', cc_mode: 0, policy: [] } };
  if (key) body.key = key;
  if (pop) body.pop = pop;
  if (tamper) tamper(body);
  const input = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(Buffer.from(JSON.stringify(body)))}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, Buffer.from(input)));
  return { jwt: `${input}.${b64url(sig)}`, point: new Uint8Array(point) };
}

test('Attest.prepare / hem.attest / Attest.verify: the token and a signature PoP', async () => {
  const { request, state } = await Attest.prepare({ aud: 'bank-7', kid: '00112233445566778899AABBCCDDEEFF', includeMetadata: true, pop: 'sig' });
  assert.equal(request.nonce.length, 32);
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'keymgmt:use:00112233445566778899AABBCCDDEEFF');
  await hem.attest(token, request);
  assert.deepEqual(mockLog().at(-1).body, { nonce: b64(request.nonce), aud: 'bank-7', kid: '00112233445566778899AABBCCDDEEFF', include_metadata: true, pop_args: {} });

  // Ed25519 key, pure EdDSA over prefix | aud | pubkey | nonce
  const ed = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const edPub = new Uint8Array(await crypto.subtle.exportKey('raw', ed.publicKey));
  const canon = Buffer.concat([u16(Buffer.from('encedo-attest-pop:v1:sig')), u16(Buffer.from('bank-7')), u16(edPub), u16(state.nonce)]);
  const edSig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, ed.privateKey, canon));
  const key = { kid: '00112233445566778899aabbccddeeff', type: 'ED25519', modes: ['ExDSA'], pubkey: { primary: b64(edPub) } };
  const { jwt, point } = await deviceToken({ state, key, pop: { signature: b64(edSig) } });

  const r = await Attest.verify(jwt, state);
  assert.deepEqual(r.failed, []);
  assert.equal(r.ok, true);
  assert.deepEqual(r.pop, { method: 'signature', result: 'ok' });
  assert.equal(r.expired, false);
  assert.deepEqual(r.point, point);
  assert.equal(r.skid, nodeCrypto.createHash('sha1').update(point).digest('hex'));
  assert.equal((await Attest.verify({ attestation: jwt }, state)).ok, true, 'the device reply works as well');
  assert.equal((await Attest.verify(jwt)).ok, true, 'without a state: the token for itself');

  const other = await Attest.prepare({ aud: 'bank-7', kid: key.kid, pop: 'sig' });
  assert.deepEqual((await Attest.verify(jwt, other.state)).failed, ['nonce', 'pop'], 'another challenge: wrong nonce, and the PoP covers the nonce');
  const forged = await deviceToken({ state, key, pop: { signature: b64(edSig) }, tamper: (b) => { b.aud = 'bank-8'; } });
  assert.deepEqual((await Attest.verify(forged.jwt, state)).failed, ['aud'], 'the PoP is over our aud, which the device signed');
  const parts = jwt.split('.');
  const resigned = `${parts[0]}.${b64url(Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(parts[1], 'base64url')), aud: 'x' })))}.${parts[2]}`;
  assert.ok((await Attest.verify(resigned)).failed.includes('signature'), 'a changed body breaks the device signature');
  const old = await deviceToken({ state, key, pop: { signature: b64(edSig) }, iat: Math.floor(Date.now() / 1000) - 3600 });
  const late = await Attest.verify(old.jwt, state);
  assert.equal(late.ok, true);
  assert.equal(late.expired, true, 'expired is reported, not failed');
});

test('Attest.verify: ECDSA signature PoP on P-384 / P-521 (compressed keys), the rest TBD', async () => {
  for (const [type, curve, hash, size] of [['SECP384R1', 'P-384', 'SHA-384', 48], ['SECP521R1', 'P-521', 'SHA-512', 66], ['SECP256R1', 'P-256', 'SHA-256', 32]]) {
    const { state } = await Attest.prepare({ aud: 'a', kid: '00112233445566778899aabbccddeeff', pop: 'sig' });
    const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: curve }, true, ['sign', 'verify']);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', k.publicKey));
    const compressed = Buffer.concat([Buffer.from([2 | (raw[raw.length - 1] & 1)]), raw.subarray(1, 1 + size)]);
    const canon = Buffer.concat([u16(Buffer.from('encedo-attest-pop:v1:sig')), u16(Buffer.from('a')), u16(compressed), u16(state.nonce)]);
    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash }, k.privateKey, canon));
    const key = { kid: state.kid, type, modes: ['ExDSA'], pubkey: { primary: b64(compressed) } };
    const r = await Attest.verify((await deviceToken({ state, key, pop: { signature: b64(sig) } })).jwt, state);
    assert.deepEqual(r.pop, { method: 'signature', result: 'ok' }, type);
  }
  const { state } = await Attest.prepare({ aud: 'a', kid: '00112233445566778899aabbccddeeff', pop: 'sig' });
  const key = { kid: state.kid, type: 'MLDSA65', modes: ['MLDSA'], pubkey: { primary: b64(new Uint8Array(1952)) } };
  const r = await Attest.verify((await deviceToken({ state, key, pop: { signature: b64(new Uint8Array(3309)) } })).jwt, state);
  assert.deepEqual(r.pop, { method: 'signature', result: 'unsupported' });
  assert.deepEqual(r.failed, ['pop_unsupported'], 'not checked is not ok');
});

test('Attest.verify: ECDH-MAC PoP on X25519 and P-256', async () => {
  for (const curve of ['CURVE25519', 'SECP256R1']) {
    const { request, state } = await Attest.prepare({ aud: 'vpn', kid: '00112233445566778899aabbccddeeff', pop: 'ecdh', curve });
    assert.deepEqual(request.popArgs.verifierEphPub, state.ephPub);
    // The device side, by node:crypto: its key pair, the shared secret with our ephemeral key, the MAC.
    let devPub, ss;
    if (curve === 'CURVE25519') {
      const kp = nodeCrypto.generateKeyPairSync('x25519');
      devPub = kp.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
      const eph = nodeCrypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), state.ephPub]), format: 'der', type: 'spki' });
      ss = nodeCrypto.diffieHellman({ privateKey: kp.privateKey, publicKey: eph });
    } else {
      const ecdh = nodeCrypto.createECDH('prime256v1');
      ecdh.generateKeys();
      devPub = ecdh.getPublicKey(null, 'compressed');
      ss = ecdh.computeSecret(Buffer.from(state.ephPub));       // our key comes compressed, as the API wants it
    }
    const info = Buffer.concat([u16(Buffer.from('encedo-attest-pop:v1:ecdh')), u16(Buffer.from('vpn')), u16(devPub)]);
    const macKey = Buffer.from(nodeCrypto.hkdfSync('sha256', ss, state.nonce, info, 32));
    const mac = nodeCrypto.createHmac('sha256', macKey).update(Buffer.concat([info, u16(state.nonce), u16(state.ephPub)])).digest();
    const key = { kid: state.kid, type: curve, modes: ['ECDH'], pubkey: { primary: b64(devPub) } };
    const r = await Attest.verify((await deviceToken({ state, key, pop: { mac: b64(mac) } })).jwt, state);
    assert.deepEqual(r.pop, { method: 'mac', result: 'ok' }, curve);
    assert.equal(r.ok, true);
    mac[0] ^= 1;
    assert.deepEqual((await Attest.verify((await deviceToken({ state, key, pop: { mac: b64(mac) } })).jwt, state)).pop, { method: 'mac', result: 'fail' });
  }
  await assert.rejects(Attest.prepare({ aud: 'a', kid: '00112233445566778899aabbccddeeff', pop: 'ecdh', curve: 'CURVE448' }), (e) => e.code === 'invalid_arg');
  await assert.rejects(Attest.prepare({ aud: 'a', pop: 'sig' }), (e) => e.code === 'invalid_arg', 'a PoP needs a key');
});

test('Attest.verifyDevice: the certificate holds the token key and chains to the pinned root', async () => {
  const { state } = await Attest.prepare({ aud: 'x' });
  const { jwt, point } = await deviceToken({ state });
  const r = await Attest.verify(jwt, state);
  const attest = new Attest(`${base}/att`);
  const cas = [PKI.root, PKI.attestation, PKI.custody];
  const ok = await attest.verifyDevice(r.point, PKI.device, { cas, rootSha256: PKI.rootSha256 });
  assert.deepEqual(ok, { ok: true, chain: ['#0123TESTDEVICE', 'Encedo TEST Custody CA', 'Encedo TEST Attestation CA', 'Encedo TEST Root CA'] });
  assert.equal((await attest.verifyDevice(point, Buffer.from(PKI.device, 'base64'), { cas, rootSha256: PKI.rootSha256 })).ok, true, 'DER bytes too');

  assert.equal((await attest.verifyDevice(r.point, PKI.device, { cas })).reason, 'root', 'the real Encedo root is pinned by default');
  assert.equal((await attest.verifyDevice(r.point, PKI.device, { cas: [PKI.root, PKI.custody], rootSha256: PKI.rootSha256 })).reason, 'issuer');
  const wrongKey = new Uint8Array(point); wrongKey[5] ^= 1;
  assert.equal((await attest.verifyDevice(wrongKey, PKI.device, { cas, rootSha256: PKI.rootSha256 })).reason, 'key', 'a certificate for another key');
  const tampered = Buffer.from(PKI.device, 'base64'); tampered[tampered.length - 80] ^= 1;   // inside the signature
  assert.equal((await attest.verifyDevice(r.point, tampered, { cas, rootSha256: PKI.rootSha256 })).reason, 'signature');
  assert.equal((await attest.verifyDevice(r.point, 'not a certificate', { cas })).reason, 'certificate');

  // Without cas the CA certificates come from attest.encedo.com /v1/pki, once.
  const before = mockLog().length;
  assert.equal((await attest.verifyDevice(r.point, PKI.device, { rootSha256: PKI.rootSha256 })).ok, true);
  await attest.verifyDevice(r.point, PKI.device, { rootSha256: PKI.rootSha256 });
  assert.equal(mockLog().slice(before).filter((l) => l.path === '/att/v1/pki').length, 1);
});

test('Attest level 2: validate and skidKnown at attest.encedo.com', async () => {
  const attest = new Attest(`${base}/att`);
  assert.deepEqual(await attest.validate({ attestation: 'J.W.T' }, { crt: new Uint8Array([1, 2]) }), { status: 'valid', expired: false });
  assert.deepEqual(mockLog().at(-1).body, { jwt: 'J.W.T', crt: b64([1, 2]) });
  assert.equal(await attest.skidKnown('ABCDEF0123456789abcdef0123456789abcdef01'), true);
  assert.equal(mockLog().at(-1).path, '/att/v1/skid/abcdef0123456789abcdef0123456789abcdef01');
  await assert.rejects(attest.skidKnown('xyz'), (e) => e.code === 'invalid_arg');
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
  assert.equal(r.instanceid, 'INST-1');
  assert.equal(await hem.authorizePassword(null, 'system:config'), r.token, 'the init token is cached: no second sign-in');

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
  await hem.authorizeMaster(mnemonic, 'legacy-scope', { legacy: true });
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
