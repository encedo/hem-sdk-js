// hem-sdk-js against a real, personalised HEM (PPA, firmware 1.3) - what the mock in
// sdk.test.mjs cannot show. It makes its own keys (label SDK-TEST-*, description
// "SDK-TEST:...") and deletes them at the end; it does not reboot, wipe, upgrade,
// reclaim key storage, bootstrap or unlock a disk. The CA certificates come from
// pki.encedo.com.
//
//   node test/device.mjs [https://my.ence.do] [user password]
//
// The defaults are hem-api-tester's (config.php), which personalises the device
// with all three policies on; without raw_ecdh_enabled the raw ECDH step
// reports the 403.
import nodeCrypto from 'node:crypto';
import { HEM, Attest, HemError, verifyLoggerKey, jwtParse } from '../hem-sdk.js';

const URL_ = process.argv[2] ?? 'https://my.ence.do';
const PASS = process.argv[3] ?? 'example passphrase';
const hem = new HEM(URL_);
const results = [];
const made = [];
const t0 = Date.now();
async function step(name, fn) {
  try {
    const note = await fn();
    results.push([name, 'PASS', note ?? '']);
    console.log(`PASS  ${name}${note ? '  - ' + note : ''}`);
  } catch (e) {
    const msg = e instanceof HemError ? `${e.code} ${e.message}` : (e?.stack ?? String(e)).split('\n').slice(0, 2).join(' | ');
    results.push([name, 'FAIL', msg]);
    console.log(`FAIL  ${name}  - ${msg}`);
  }
}
const ok = (cond, msg) => { if (!cond) throw new Error(msg); };
const eq = (a, b, msg) => ok(Buffer.from(a).equals(Buffer.from(b)), msg ?? 'bytes differ');
const tok = (scope) => hem.authorizePassword(PASS, scope, { expSeconds: 600 });
const use = (...kids) => tok(kids.length === 1 ? `keymgmt:use:${kids[0]}` : kids.map((k) => `keymgmt:use:${k}`));
const k = {};
async function create(name, type, opts = {}) {
  const key = await hem.createKeyPair(await tok('keymgmt:gen'), `SDK-TEST-${name}`, type, { descr: `SDK-TEST:${name}`, ...opts });
  made.push(key.kid);
  k[name] = key;
  return key;
}

console.log(`hem-sdk-js device test, ${URL_}, ${new Date().toISOString()}\n`);
let cfg;
await step('getStatus / getVersion (with token: sd_csd)', async () => {
  const st = await hem.getStatus({ timeoutMs: 8000 });
  ok(!('inited' in st), 'device not personalised');
  const v = await hem.getVersion({ token: await tok('system:config') });
  return `${v.fwv}, ${v.blv}, sd_csd ${v.sd_csd ? 'yes' : 'no'}`;
});
await step('getConfig (policy)', async () => { cfg = await hem.getConfig(await tok('system:config')); return `policy [${cfg.policy}]`; });
await step('scope array: one token, cached for each scope', async () => {
  hem.clearCache();
  const t = await hem.authorizePassword(PASS, ['keymgmt:list', 'keymgmt:get'], { expSeconds: 600 });
  ok(Array.isArray(jwtParse(t).scope), 'not an array token');
  ok(await hem.authorizePassword(null, 'keymgmt:get') === t, 'not reused');
});
await step('selftest', async () => { const r = await hem.selftest(await tok('system:config')); return `fls ${r.fls_state}, repo ${JSON.stringify(r.repo_stats)}`; });
await step('defragCheck', async () => { const r = await hem.defragCheck(await tok('system:config')); return `reclaimable ${r.reclaimable} (${r.reclaimable_size} B), keys ${r.keys}`; });
await step('random', async () => { const r = await hem.random(await tok('keymgmt:list'), 64); ok(r.length === 64, 'length'); });

// --- keys -----------------------------------------------------------------------------
await step('create keys (modes, returnPubkey)', async () => {
  await create('ed', 'ED25519', { returnPubkey: true });
  ok(k.ed.type === 'ED25519' && k.ed.flags.includes('ATT') && k.ed.pubkey?.length === 32, 'ed entry');
  await create('p256', 'SECP256R1', { mode: 'ECDH,ExDSA', returnPubkey: true });
  ok(k.p256.pubkey.length === 33, 'p256 compressed');
  await create('x', 'CURVE25519', { returnPubkey: true });
  await create('xh', 'CURVE25519', { mode: 'HPKE', returnPubkey: true });
  ok(k.xh.flags.includes('HPKE'), 'HPKE flag');
  await create('kem', 'MLKEM768', { returnPubkey: true });
  await create('dsa', 'MLDSA44');
  await create('aes', 'AES256');
  await create('hmac', 'SHA2-256');
  await create('otp', 'SHA1');
  return `${made.length} keys`;
});
await step('getKeyPublicInfo', async () => {
  const i = await hem.getKeyPublicInfo(await tok('keymgmt:get'), k.p256.kid);
  eq(i.pubkey, k.p256.pubkey, 'pubkey differs');
  ok(Buffer.from(i.description).toString() === 'SDK-TEST:p256', 'descr');
});
await step('listKeys pages on listed to total', async () => {
  const t = await tok('keymgmt:list');
  let page = await hem.listKeys(t), n = page.list.length, pages = 1;
  while (page.offset + page.listed < page.total) { page = await hem.listKeys(t, { offset: page.offset + page.listed }); n += page.list.length; pages++; }
  const mine = n;
  return `${page.total} records, ${mine} listed over ${pages} pages, invalid ${page.invalid}`;
});
await step('listKeysAll / searchKeysAll match a hand-paged walk', async () => {
  const t = await hem.authorizePassword(null, ['keymgmt:list', 'keymgmt:search']);
  let page = await hem.listKeys(t), byHand = [...page.list];
  while (page.offset + page.listed < page.total) { page = await hem.listKeys(t, { offset: page.offset + page.listed }); byHand.push(...page.list); }
  const all = await Array.fromAsync(hem.listKeysAll(t));
  ok(all.map((e) => e.kid).join() === byHand.map((e) => e.kid).join(), `listKeysAll ${all.length} vs by hand ${byHand.length}`);
  const found = await Array.fromAsync(hem.searchKeysAll(t, 'SDK-TEST:', { returnPubkey: true }));
  const first = await hem.searchKeys(t, 'SDK-TEST:');
  ok(found.length >= first.list.length && found.length >= 9, `searchKeysAll ${found.length}, first page ${first.list.length}`);
  return `list ${all.length}, search SDK-TEST: ${found.length}`;
});
await step('listKeys returnPubkey (policy pubkey_in_list)', async () => {
  const p = await hem.listKeys(await tok('keymgmt:list'), { returnPubkey: true });
  return `pubkeys: ${p.list.filter((e) => e.pubkey).length}/${p.list.length} (policy ${cfg?.policy?.includes('pubkey_in_list') ? 'on' : 'off'})`;
});
await step('searchKeys prefix / suffix / contains / type filter', async () => {
  const t = await tok('keymgmt:search');
  const pre = await hem.searchKeys(t, 'SDK-TEST:');
  const suf = await hem.searchKeys(t, ':p256', { match: 'suffix' });
  const con = await hem.searchKeys(t, 'TEST:ml', { match: 'contains' });
  const typ = await hem.searchKeys(t, 'SDK-TEST:', { type: 'CURVE25519', mode: 'HPKE' });
  ok(pre.list.length >= 9, `prefix ${pre.list.length}`);
  ok(suf.list.length === 1 && suf.list[0].kid === k.p256.kid, 'suffix');
  ok(con.list.length === 0 || con.list.every((e) => Buffer.from(e.description).toString().includes('TEST:ml')), 'contains');
  ok(typ.list.length === 1 && typ.list[0].kid === k.xh.kid, 'type+mode filter');
  return `prefix ${pre.list.length} (listed ${pre.listed}), suffix 1, type+mode 1`;
});
await step('updateKey (and remove description)', async () => {
  await hem.updateKey(await tok('keymgmt:upd'), k.aes.kid, 'SDK-TEST-aes2', null);
  const i = await hem.getKeyPublicInfo(await tok('keymgmt:get'), k.aes.kid);
  ok(i.label === 'SDK-TEST-aes2' && i.description === null, 'not updated');
});
await step('importPublicKey + deriveKey (ECDH peer, HMAC parent)', async () => {
  const peer = nodeCrypto.generateKeyPairSync('x25519');
  const peerPub = peer.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const imp = await hem.importPublicKey(await tok('keymgmt:imp'), 'SDK-TEST-imp', 'CURVE25519', new Uint8Array(peerPub), { descr: 'SDK-TEST:imp' });
  made.push(imp.kid); k.imp = imp;
  const d1 = await hem.deriveKey(await tok('keymgmt:derive'), 'SDK-TEST-der', 'AES256', k.x.kid, { pubkey: new Uint8Array(peerPub), hkdfSalt: 's' });
  made.push(d1.kid);
  const d2 = await hem.deriveKey(await tok('keymgmt:derive'), 'SDK-TEST-der2', 'SHA2-256', k.hmac.kid, { hkdfSalt: 'tenant-7' });
  made.push(d2.kid);
  ok(!d1.flags.includes('ATT') && d2.type === 'SHA2-256', 'derived flags');
});

// --- crypto ---------------------------------------------------------------------------
await step('exdsaSign / exdsaVerify Ed25519 (true / false, ctx)', async () => {
  const t = await use(k.ed.kid);
  const sig = await hem.exdsaSign(t, k.ed.kid, 'hello');
  ok(await hem.exdsaVerify(t, k.ed.kid, 'hello', sig) === true, 'valid not true');
  ok(await hem.exdsaVerify(t, k.ed.kid, 'hellO', sig) === false, 'invalid not false');
  const pub = await crypto.subtle.importKey('raw', k.ed.pubkey, 'Ed25519', false, ['verify']);
  ok(await crypto.subtle.verify('Ed25519', pub, sig, Buffer.from('hello')), 'WebCrypto rejects it');
  const sc = await hem.exdsaSign(t, k.ed.kid, 'hello', { alg: 'Ed25519ctx', ctx: 'app' });
  ok(await hem.exdsaVerify(t, k.ed.kid, 'hello', sc, { alg: 'Ed25519ctx', ctx: 'app' }), 'ctx verify');
});
await step('ECDSA P-256 r||s, det, prehashed', async () => {
  const t = await use(k.p256.kid);
  const a = await hem.exdsaSign(t, k.p256.kid, 'msg', { alg: 'SHA256WithECDSA', det: true });
  const b = await hem.exdsaSign(t, k.p256.kid, 'msg', { alg: 'SHA256WithECDSA', det: true });
  eq(a, b, 'det signatures differ');
  ok(a.length === 64, 'not r||s');
  const ecdh = nodeCrypto.createECDH('prime256v1');
  const unc = ecdh.constructor.convertKey(Buffer.from(k.p256.pubkey), 'prime256v1', null, null, 'uncompressed');
  const pub = await crypto.subtle.importKey('raw', unc, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  ok(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, a, Buffer.from('msg')), 'WebCrypto rejects r||s');
  const dig = nodeCrypto.createHash('sha256').update('msg').digest();
  const p = await hem.exdsaSign(t, k.p256.kid, dig, { alg: 'ECDSA' });
  ok(await hem.exdsaVerify(t, k.p256.kid, dig, p, { alg: 'ECDSA' }), 'prehashed verify');
});
await step('ecdh: HKDF, ecdhHkdf, raw per policy, peer as KID', async () => {
  const t = await use(k.x.kid);
  const peer = nodeCrypto.generateKeyPairSync('x25519');
  const peerPub = new Uint8Array(peer.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
  const xPub = nodeCrypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), k.x.pubkey]), format: 'der', type: 'spki' });
  const ss = nodeCrypto.diffieHellman({ privateKey: peer.privateKey, publicKey: xPub });
  const okm = await hem.ecdh(t, k.x.kid, { pubkey: peerPub, alg: 'HKDF-SHA2-256', hkdfSalt: 'salt', hkdfCtx: 'ctx', hkdfLen: 32 });
  eq(okm, Buffer.from(nodeCrypto.hkdfSync('sha256', ss, 'salt', 'ctx', 32)), 'HKDF differs from local');
  const [a, b] = await hem.ecdhHkdf(t, k.x.kid, { pubkey: peerPub, items: [{ hkdfCtx: 'enc' }, { hkdfCtx: 'mac', hkdfLen: 16 }] });
  eq(a, Buffer.from(nodeCrypto.hkdfSync('sha256', ss, Buffer.alloc(0), 'enc', 32)), 'hkdf_args[0]');
  ok(b.length === 16, 'hkdf_args[1] length');
  const h = await hem.ecdh(t, k.x.kid, { pubkey: peerPub, alg: 'SHA2-256' });
  eq(h, nodeCrypto.createHash('sha256').update(ss).digest(), 'digest');
  let raw;
  try { raw = await hem.ecdh(t, k.x.kid, { pubkey: peerPub }); eq(raw, ss, 'raw'); } catch (e) { if (e.code !== 'http_403') throw e; raw = '403 (policy off)'; }
  const t2 = await use(k.x.kid, k.imp.kid);
  await hem.ecdh(t2, k.x.kid, { extKid: k.imp.kid, alg: 'SHA2-256' });
  return `raw: ${typeof raw === 'string' ? raw : 'ok'}`;
});
await step('hmacHash / hmacVerify true / false', async () => {
  const t = await use(k.hmac.kid);
  const mac = await hem.hmacHash(t, k.hmac.kid, 'data');
  ok(await hem.hmacVerify(t, k.hmac.kid, 'data', mac) === true, 'valid');
  ok(await hem.hmacVerify(t, k.hmac.kid, 'datA', mac) === false, 'invalid not false');
});
await step('cipher GCM / CBC / ChaCha20 + peer HKDF fields', async () => {
  const t = await use(k.aes.kid);
  for (const alg of ['AES256-GCM', 'AES128-CBC', 'CHACHA20-POLY1305']) {
    const e = await hem.cipherEncrypt(t, k.aes.kid, 'plain text', alg, { aad: alg.includes('CBC') ? null : Buffer.from('hdr') });
    const p = await hem.cipherDecrypt(t, k.aes.kid, e.ciphertext, alg, { iv: e.iv, tag: e.tag, aad: alg.includes('CBC') ? null : Buffer.from('hdr') });
    ok(Buffer.from(p).toString() === 'plain text', alg);
  }
  const tx = await use(k.x.kid);
  const e = await hem.cipherEncrypt(tx, k.x.kid, 'peer', 'AES256-GCM', { pubkey: k.x.pubkey, hkdfCtx: 'files:v1' });
  const p = await hem.cipherDecrypt(tx, k.x.kid, e.ciphertext, 'AES256-GCM', { pubkey: k.x.pubkey, hkdfCtx: 'files:v1', iv: e.iv, tag: e.tag });
  ok(Buffer.from(p).toString() === 'peer', 'peer mode');
  let wrongCtx = false;
  try { await hem.cipherDecrypt(tx, k.x.kid, e.ciphertext, 'AES256-GCM', { pubkey: k.x.pubkey, hkdfCtx: 'files:v2', iv: e.iv, tag: e.tag }); } catch (er) { wrongCtx = er.code === 'http_406'; }
  ok(wrongCtx, 'another hkdfCtx still decrypts: the context is not used');
});
await step('cipherWrap / cipherUnwrap', async () => {
  const t = await use(k.aes.kid);
  const keyMat = crypto.getRandomValues(new Uint8Array(32));
  const w = await hem.cipherWrap(t, k.aes.kid, keyMat);
  ok(w.length === 40, 'wrap length');
  eq(await hem.cipherUnwrap(t, k.aes.kid, w), keyMat);
});
await step('ML-KEM encaps / decaps', async () => {
  const t = await use(k.kem.kid);
  const { ss, ct, alg } = await hem.mlkemEncaps(t, k.kem.kid);
  eq(await hem.mlkemDecaps(t, k.kem.kid, ct), ss);
  return alg;
});
await step('ML-DSA sign / verify (ctx, false)', async () => {
  const t = await use(k.dsa.kid);
  const s = await hem.mldsaSign(t, k.dsa.kid, 'doc', { ctx: 'app' });
  ok(await hem.mldsaVerify(t, k.dsa.kid, 'doc', s, { ctx: 'app' }) === true, 'valid');
  ok(await hem.mldsaVerify(t, k.dsa.kid, 'doc', s) === false, 'wrong ctx not false');
  const d = nodeCrypto.createHash('sha256').update('doc').digest();
  const h = await hem.mldsaSign(t, k.dsa.kid, d, { mode: 'HashML-DSA-SHA256' });
  ok(await hem.mldsaVerify(t, k.dsa.kid, d, h, { mode: 'HashML-DSA-SHA256' }), 'HashML-DSA');
});
await step('X-Wing encaps / decaps (scope array)', async () => {
  const t = await use(k.kem.kid, k.x.kid);
  const { ss, ct } = await hem.xwingEncaps(t, k.kem.kid, { extKid: k.x.kid });
  eq(await hem.xwingDecaps(t, k.kem.kid, ct, { extKid: k.x.kid }), ss);
});
await step('HPKE seal / open (HEM key, and pubkey outside)', async () => {
  const t = await use(k.xh.kid);
  const s = await hem.hpkeSeal(t, { kid: k.xh.kid }, 'for the inbox', { info: 'app:v1' });
  ok(Buffer.from(await hem.hpkeOpen(t, k.xh.kid, s.enc, s.ct, { info: 'app:v1' })).toString() === 'for the inbox', 'open');
  const s2 = await hem.hpkeSeal(t, { pubkey: k.xh.pubkey, kem: 'DHKEM-X25519' }, 'outside', { aead: 'CHACHA20-POLY1305' });
  ok(Buffer.from(await hem.hpkeOpen(t, k.xh.kid, s2.enc, s2.ct, { aead: 'CHACHA20-POLY1305' })).toString() === 'outside', 'open pubkey-sealed');
  return s.suite;
});
await step('kdf HKDF / SP800-108', async () => {
  const t = await use(k.hmac.kid);
  const a = await hem.kdf(t, k.hmac.kid, 'HKDF', 32, { salt: 's', info: 'i' });
  const b = await hem.kdf(t, k.hmac.kid, 'SP800-108', 48, { info: 'label' });
  ok(a.length === 32 && b.length === 48, 'lengths');
});
await step('otp / otpVerify TOTP and HOTP', async () => {
  const t = await use(k.otp.kid);
  const { code, step: s } = await hem.otp(t, k.otp.kid);
  const v = await hem.otpVerify(t, k.otp.kid, code);
  ok(v.verified && v.step === s, 'TOTP verify');
  ok((await hem.otpVerify(t, k.otp.kid, code === '000000' ? '000001' : '000000', { window: 0 })).verified === false, 'wrong code');
  const h = await hem.otp(t, k.otp.kid, { mode: 'HOTP', counter: 5 });
  ok((await hem.otpVerify(t, k.otp.kid, h.code, { mode: 'HOTP', counter: 3, window: 3 })).step === 5, 'HOTP look-ahead');
});

// --- attestation ----------------------------------------------------------------------
// both custody CAs: a PPA's certificate comes from the Custody CA, an EPA's from the EPA Custody CA
const cas = await Promise.all(['root-ca.pem', 'attestation-ca.pem', 'custody-ca.pem', 'epa-custody-ca.pem']
  .map(async (f) => (await fetch(`https://pki.encedo.com/${f}`)).text()));
let attCrt = null;
await step('getAttestation with our nonce', async () => {
  const a = await hem.getAttestation(await tok('keymgmt:list'), { nonce: crypto.getRandomValues(new Uint8Array(32)) });
  attCrt = a.crt ?? null;
  ok(a.genuine.split('.').length === 4, 'genuine not nonce-bound');
  return `crt ${attCrt ? 'yes' : 'no (not provisioned)'}`;
});
for (const [name, pop, curve, key] of [['device only', null, null, null], ['Ed25519 sig PoP', 'sig', null, 'ed'], ['P-256 sig PoP', 'sig', null, 'p256'], ['X25519 ECDH-MAC PoP', 'ecdh', 'CURVE25519', 'x'], ['P-256 ECDH-MAC PoP', 'ecdh', 'SECP256R1', 'p256'], ['ML-DSA PoP (TBD)', 'sig', null, 'dsa']]) {
  await step(`attest + Attest.verify: ${name}`, async () => {
    const kid = key ? k[key].kid : null;
    const { request, state } = await Attest.prepare({ aud: 'sdk-test', kid, pop, curve });
    const jwt = await hem.attest(kid ? await use(kid) : await tok('keymgmt:list'), request);
    const r = await Attest.verify(jwt, state);
    if (key === 'dsa') { ok(r.pop.result === 'unsupported' && r.failed.join() === 'pop_unsupported', `got ${r.failed}`); return 'pop_unsupported as designed'; }
    ok(r.ok, `failed: ${r.failed}`);
    if (pop) ok(r.pop.result === 'ok', 'pop');
    if (!key && attCrt) {
      const d = await new Attest().verifyDevice(r.point, attCrt, { cas });
      ok(d.ok, `chain: ${d.reason}`);
      return `chain ${d.chain.join(' <- ')}`;
    }
    return r.pop.method ? `${r.pop.method} ok` : `skid ${r.skid}`;
  });
}

// --- audit log ------------------------------------------------------------------------
await step('getLoggerKey with our nonce, listLogFiles, verifyLogFile (v2)', async () => {
  const t = await tok('logger:get');
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  ok(await verifyLoggerKey(await hem.getLoggerKey(t, { nonce }), nonce), 'key not proven');
  const l = await hem.listLogFiles(t);
  ok(l.id.length > 0, 'no log files');
  const newest = [...l.id].sort().at(-1);
  const r = await hem.verifyLogFile(t, newest);
  let cur = 'no current';
  if (l.current) { try { await hem.getLogFile(t, l.current); cur = 'current readable?!'; } catch (e) { cur = `current ${e.code}`; } }
  ok(r.keyProven, 'keyProven');
  return `${l.total} files, newest ${newest}: ok ${r.ok}, ${r.lines} lines, ${r.headers} headers, gaps ${r.gaps.length}${r.reason ? ', ' + r.reason + '@' + r.line : ''}; ${cur}`;
});

// --- clean up -------------------------------------------------------------------------
await step(`deleteKey x${made.length} (cleanup)`, async () => {
  const t = await tok('keymgmt:del');
  for (const kid of made) await hem.deleteKey(t, kid);
  const left = await hem.searchKeys(await tok('keymgmt:search'), 'SDK-TEST:');
  ok(left.list.length === 0, `${left.list.length} left`);
});

const fails = results.filter((r) => r[1] === 'FAIL');
console.log(`\n${results.length - fails.length}/${results.length} passed in ${Math.round((Date.now() - t0) / 1000)} s`);
process.exit(fails.length ? 1 : 0);
