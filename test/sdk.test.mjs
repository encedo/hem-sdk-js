// End-to-end test of hem-sdk.js against an in-process mock of the device and
// the broker. Run: node --test test/sdk.test.mjs
//
// The mock speaks the wire format the SDK expects (see the PHP reference in
// hem-api-tester for the device side); it verifies the eJWT the SDK signs, so
// the password path is checked cryptographically, not only for shape.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { HEM, Broker, HemError, jwtParse, verifyLog } from '../hem-sdk.js';

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
  if (path === '/dev/api/system/config' && req.method === 'GET') return json(res, 200, { eid: state.eid, user: 'Ann', email: 'ann@example.com', hostname: 'my.ence.do' });
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
  if (path === '/dev/api/auth/ext/request') return json(res, 200, { challenge: 'CH', epk: body.epk, scope: body.scope });
  if (path === '/dev/api/auth/ext/token') return json(res, 200, { token: fakeJwt({ scope: 'remote', exp: Math.floor(Date.now() / 1000) + 300 }) });
  if (path === '/dev/api/auth/ext/init') return json(res, 200, { eid: state.eid, request: 'REQUEST-JWT' });
  if (path === '/dev/api/auth/ext/validate') return json(res, 200, { confirmed: body.pid });
  if (path === '/dev/api/auth/ext/mac') return json(res, 200, { nonce: 'N', mac: 'M', eid: state.eid });
  if (path === '/dev/api/system/upgrade/upload_fw') return json(res, 200, { bytes: raw.length, ct: req.headers['content-type'] });
  if (path === '/dev/api/logger/key') return json(res, 200, { key: state.loggerKeyB64 });
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
  if (path.startsWith('/brk/domain/register/')) return json(res, 200, { emp: 'E', key: 'K', crt: 'C', prefix: path.split('/').pop(), got: body });
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

test('verifyLogEntry fetches key and file and verifies them', async () => {
  const hem = mk();
  const token = await hem.authorizePassword('correct horse', 'logger:get');
  const r = await hem.verifyLogEntry(token, 7);
  assert.equal(r.ok, true);
  assert.equal(r.lines, 4);
  assert.equal(r.text, state.logText);
});
