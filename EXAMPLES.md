# hem-sdk-js — Examples

Commented, copy-pasteable usage for every HEM SDK operation. For a high-level
overview see [README.md](./README.md).

All examples assume:

```js
import { HEM, HemError } from './hem-sdk.js';

const hem = new HEM('https://abc.ence.do', {
  // broker: 'https://api.encedo.com',  // notification broker (default)
  // debug: true,                        // log every request/response
});
```

Conventions:
- Binary inputs/outputs are `Uint8Array`. The SDK handles base64 internally.
- `*Verify` methods resolve to `true` or throw `HemError` on an invalid result.
- A JWT `token` is scoped — see the scope table in the README.

---

## 1. Checkin

Run once after construction, before anything else. Tests the HSM + broker
connection and synchronises clocks. The device's answer says whether a newer
firmware or UI image exists.

```js
const health = await hem.hemCheckin();     // { status, newfws?, newuis?, ... }
if (health.newfws) console.log('firmware update available:', health.newfws);
```

Behind an air gap the broker is unreachable and this throws `broker_error`
(or `network`). Catch it and carry on: password authentication and every
device-only operation still work.

```js
let online = true;
try { await hem.hemCheckin(); } catch (e) { if (e instanceof HemError) online = false; else throw e; }
```

## 1a. The broker

Every call to `api.encedo.com` is a method of `Broker`, one per endpoint.
`HEM` builds one from the `broker` option and composes it into the multi-step
flows below; `hem.broker` is there for the calls a page makes on its own.

```js
import { Broker } from './hem-sdk.js';

const broker = new Broker('https://api.encedo.com');
const hem = new HEM('https://abc.ence.do', { broker });   // a URL works too

const { prefix } = await hem.broker.domainPredefs();       // ['my', 'dev', ...]
const taken = await hem.broker.domainTaken('my');          // true / false
```

---

## 2. Authentication

### Password login

PBKDF2 + X25519 ECDH happen locally; the device returns a scoped JWT.

```js
// First call derives the X25519 key from the password (cached afterwards).
const listToken = await hem.authorizePassword('my-password', 'keymgmt:list');

// Escalate to another scope — pass null to reuse the cached derived key,
// so the password is not needed (and not re-derived) again.
const useToken = await hem.authorizePassword(null, `keymgmt:use:${kid}`);

// expSeconds — requested token lifetime (default 300).
const longToken = await hem.authorizePassword('my-password', 'keymgmt:list', 3600);
```

### Mobile-push login (remote)

No password — the mobile app signs the challenge. Requires `hemCheckin()` first.

```js
const ac = new AbortController();
usePasswordButton.onclick = () => ac.abort();   // "Use password instead"

try {
  const token = await hem.authorizeRemote('keymgmt:list', {
    pollInterval: 2000,                       // ms between broker polls
    pollTimeout: 60000,                       // give up after this long
    onPending: () => console.log('waiting for mobile approval…'),
    onEvent: (eventid) => console.log('broker event', eventid),
    signal: ac.signal,
  });
} catch (e) {
  // aborted | timeout: the event has been withdrawn from the broker, so the
  // phone stops showing it. denied: the user refused on the phone.
  if (e.code === 'aborted' || e.code === 'timeout') showPasswordForm();
  else if (e.code === 'denied') showMessage('Access denied by mobile app');
  else throw e;
}
```

Offer the phone only when one is paired — no token needed to ask:

```js
if (await hem.hasExtAuth()) startRemoteLogin(); else showPasswordForm();
```

### The master secret

A device's master identity is 256 bits from the CSPRNG. Those 32 bytes **are**
the master X25519 private key, and the same 32 bytes are what the 24 words
encode — so the words are the key, and any BIP39 tool decodes them back.

```js
import { generateMnemonic, mnemonicToEntropy, validateMnemonic } from './hem-sdk.js';

const mnemonic = await generateMnemonic();     // 24 words; show them, print them
// ... the person writes them down ...
const token = await hem.authorizeMaster(mnemonic, 'system:config');
```

A mistyped word is caught before any request, and the error says which:

```js
try {
  await hem.authorizeMaster(typed, 'system:config');
} catch (e) {
  if (e.code === 'mnemonic_invalid') showError(`Word ${e.data.word} is not a BIP39 word.`);
  else if (e.code === 'mnemonic_checksum') showError('One of the words is wrong or out of order.');
  else throw e;
}
```

A device personalised by the **v1 Manager** has a master key derived the old
way (the BIP39 seed at a one-nibble offset). Only for those:

```js
await hem.authorizeMaster(mnemonic, 'system:config', 300, { legacy: true });
```

### Device initialization (provisioning)

One-time provisioning of a factory-fresh device. Pass the master secret as
`{ mnemonic }`; `masterkey` / `userkey` are written into the config
automatically — you only supply the metadata.

```js
const mnemonic = await generateMnemonic();
const result = await hem.initialize({ mnemonic }, 'user-passphrase', {
  user: 'John Doe',
  email: 'john@example.com',
  hostname: 'abc.ence.do',
  trusted_ts: true,
  trusted_backend: true,
  allow_keysearch: true,
  gen_csr: true,
  origin: '*',
});
```

A password string is still accepted where a caller wants one:
`hem.initialize('admin-passphrase', 'user-passphrase', cfg)`.

### Register a mobile authenticator (pairing)

Full pairing flow. The SDK builds the QR payload; **rendering the QR image is
the caller's job** — `onQrCode` receives the exact JSON string to encode.

```js
const token = await hem.authorizePassword('my-password', 'system:config');

await hem.registerExtAuth(token, {
  onQrCode: (qrText, qrPayload) => {
    // qrText  — exact JSON string the mobile app must scan
    // qrPayload — same data as an object { link, hash, user, email, hostname }
    renderQrCode(qrText);                   // e.g. a QR library, or quickchart.io
  },
  pollInterval: 5000,
  pollTimeout: 60000,
  onPending: () => console.log('waiting for the QR to be scanned…'),
});
```

### List and remove paired authenticators

```js
const token = await hem.authorizePassword('my-password', 'system:config');

const phones = await hem.listExtAuth(token);      // [{ pid, ... }]
await hem.deleteExtAuth(token, phones[0].pid);    // unpair on the broker
```

A paired phone also exists in the device's keychain as a key whose description,
as base64, reads `'RVhUQUlE' + pid` — `base64('EXTAID')` with the pid (itself
base64) written straight after it. `searchKeys` takes the field's bytes, so
decode that string before searching; remove the entry too when unpairing:

```js
const field = Uint8Array.from(atob('RVhUQUlE' + phones[0].pid), (c) => c.charCodeAt(0));
const entries = await hem.searchKeys(listToken, field);
for (const k of entries) await hem.deleteKey(delToken, k.kid);
```

`getExtAuthMac(token)` returns the `{ nonce, mac, eid, epk }` the two calls
above hand to `hem.broker.subscribersList` / `subscribersDelete`, should a
page need the raw exchange.

### Provisioning and a `*.ence.do` name (PPA)

A factory-fresh PPA needs a certificate from the broker before TLS works.
`provision()` reads the attestation, has the broker sign the CSR it carries and
installs the result; on a provisioned device it resolves `null` and does
nothing.

```js
const cert = await hem.provision();               // null when already provisioned
```

Registering a hostname asks the device for a CSR, registers
`<prefix>.ence.do` with the broker and installs the TLS block it returns:

```js
const token = await hem.authorizePassword('my-password', 'system:config');
const { prefix } = await hem.broker.domainPredefs();
if (!(await hem.broker.domainTaken('alice'))) {
  const tls = await hem.registerDomain(token, 'alice', { ip: '192.168.7.1' });
}
// Re-issue for an existing registration, without a new CSR:
await hem.registerDomain(token, 'alice', { newCertificate: false });

// A name of the owner's own is confirmed by e-mail first: the broker answers
// 201 with an id, and registerDomain polls it until the click. `onPending`
// gets 'pending' and then 'email_confirmed', so a page can say what to do.
await hem.registerDomain(token, 'alice', { ip: '192.168.7.1', onPending: (status) => console.log(status) });
// The same polling on its own, after a domainRegister() that answered { id }:
const tls = await hem.broker.waitDomain(id, { onPending: (status) => console.log(status) });
```

---

## 3. Key management

Every key comes back in one shape (`HemKey`):
`{ kid, label, type, flags, description, created, updated, pubkey, der }`.
`type` is the key type alone ('ED25519'); the device's flags are split into
`flags` (['ATT', 'PKEY', 'ExDSA']). `description`, `pubkey` and `der` are bytes
or null. A description goes in as bytes too (a string is taken as UTF-8).

```js
const token = await hem.authorizePassword('my-password', 'keymgmt:list');

// One page: at most 15 slots. Read on from offset + listed until it reaches
// total - an unreadable record takes a slot without being in `list`, and a
// page with public keys ends after 3 PQC keys.
const keys = [];
for (let offset = 0, page; ; offset = page.offset + page.listed) {
  page = await hem.listKeys(token, { offset });
  keys.push(...page.list);
  if (!page.listed || page.offset + page.listed >= page.total) break;
}

// With public keys - only on a device personalised with the pubkey_in_list policy:
const withKeys = await hem.listKeys(token, { returnPubkey: true });
```

```js
// Search the description bytes. The SDK base64-encodes the pattern and adds
// the anchor: '^' for a prefix (default), '$' for a suffix, none for anywhere.
const found = await hem.searchKeys(token, 'CCTEST:');                       // { list, listed, ... }
const wgPeers = await hem.searchKeys(token, new Uint8Array([0x57, 0x47, 0x3a]), { match: 'contains' });
const signers = await hem.searchKeys(token, 'git', { type: 'ED25519', mode: 'ExDSA' });

// Paginate: `total` counts every record, not the matches - read on until a page is empty.
for (let offset = 0, page; ; offset += page.listed) {
  page = await hem.searchKeys(token, 'CCTEST:', { offset });
  if (!page.listed) break;
}

// No token at all - allowed when the device has allow_keysearch and the
// prefix is at least 6 bytes. No public keys then.
const anon = await hem.searchKeys(null, 'CCTEST:');
```

```js
// Create (scope: keymgmt:gen). The mode is checked against the type before the
// request: a mode that does not fit throws bad_mode.
const genToken = await hem.authorizePassword('my-password', 'keymgmt:gen');
const key = await hem.createKeyPair(genToken, 'My signing key', 'ED25519', { descr: 'purpose: document signing' });

// The NIST curves can sign AND agree, so they are told which; HPKE makes an HPKE-only key pair.
const nist = await hem.createKeyPair(genToken, 'Work P-384', 'SECP384R1', { mode: 'ECDH,ExDSA', returnPubkey: true });
const hpke = await hem.createKeyPair(genToken, 'Inbox', 'CURVE25519', { mode: 'HPKE' });

// Derive (scope: keymgmt:derive) from ECDH with a peer key ...
const derived = await hem.deriveKey(genToken, 'Shared with Bob', 'AES256', myX25519Kid, { pubkey: bobX25519 /* Uint8Array */ });
// ... or, with no peer, from a stored HMAC key: a key hierarchy from one secret.
const tenant = await hem.deriveKey(genToken, 'tenant-7', 'AES256', hmacKid, { hkdfSalt: 'tenant-7' });
```

```js
// Import a public key (scope: keymgmt:imp), exactly the size of its type.
const impToken = await hem.authorizePassword('my-password', 'keymgmt:imp');
const imported = await hem.importPublicKey(impToken, 'Peer key', 'ED25519', rawPubKeyBytes, { descr: 'peer' });

// NIST curves take a COMPRESSED SEC1 point (0x02/0x03 || X) and a mode:
const nistPeer = await hem.importPublicKey(impToken, 'Peer P-384', 'SECP384R1', compressedPoint /* 49 B */, { mode: 'ECDH' });

// Update label/description (scope: keymgmt:upd); no description removes it.
const updToken = await hem.authorizePassword('my-password', 'keymgmt:upd');
await hem.updateKey(updToken, kid, 'Renamed key', 'new description');

// Metadata and public part of one key - never private material (scope: keymgmt:get)
const getToken = await hem.authorizePassword('my-password', 'keymgmt:get');
const info = await hem.getKeyPublicInfo(getToken, kid);       // HemKey, with pubkey (or der for a certificate)

// Delete (scope: keymgmt:del)
const delToken = await hem.authorizePassword('my-password', 'keymgmt:del');
await hem.deleteKey(delToken, kid);
```

---

## 4. Cryptography

All `/crypto/*` operations need a `keymgmt:use:<KID>` token for the key they
name, and TLS. Data goes in as bytes (a string is taken as UTF-8) and comes
back as bytes; `msg` is at most 2048 bytes.

```js
const token = await hem.authorizePassword('my-password', `keymgmt:use:${kid}`);
const data = new TextEncoder().encode('message to protect');

// Two keys in one operation (X-Wing, HPKE with ext_kid), or several operations
// on one sign-in: one token with an array of scopes, cached for each of them.
const both = await hem.authorizePassword('my-password', [`keymgmt:use:${kemKid}`, `keymgmt:use:${x25519Kid}`]);
```

### EdDSA / ECDSA signing

```js
const sig = await hem.exdsaSign(token, kid, data);                   // Ed25519 by default
const sig2 = await hem.exdsaSign(token, kid, 'text works too');

// ECDSA comes back as raw r ‖ s (JWS / WebCrypto form). `det: true` makes it
// deterministic (RFC 6979); alg 'ECDSA' signs a digest the caller made.
const es256 = await hem.exdsaSign(token, p256Kid, data, 'SHA256WithECDSA', { det: true });
const pre = await hem.exdsaSign(token, p256Kid, digest32, 'ECDSA');

// A context for Ed25519ctx / Ed25519ph / Ed448, as bytes or text:
const sig3 = await hem.exdsaSign(token, kid, data, 'Ed25519ctx', { ctx: 'my-app' });

// Verify (a key pair or an imported public key). The device answers 200 either
// way and the SDK returns its verdict: false is an invalid signature.
if (!(await hem.exdsaVerify(token, kid, data, sig))) throw new Error('bad signature');
```

### ECDH

```js
// The peer is raw key bytes, or the KID of a key already in the HEM.
// Without alg: the raw secret, as long as the curve - only on a device
// personalised with the raw_ecdh_enabled policy (403 otherwise).
const secret = await hem.ecdh(token, kid, peerPubKeyBytes);           // Uint8Array
const secret2 = await hem.ecdh(token, kid, peerKid);                  // both operands in the HEM

// A digest of it, or HKDF over it:
const hashed = await hem.ecdh(token, kid, peerPubKeyBytes, { alg: 'SHA2-256' });
const okm = await hem.ecdh(token, kid, peerPubKeyBytes, { alg: 'HKDF-SHA2-256', hkdfSalt: salt, hkdfCtx: 'wg:v1', hkdfLen: 32 });

// Several keys from one agreement; the shared secret never leaves the device:
const [encKey, macKey] = await hem.ecdhHkdf(token, kid, peerPubKeyBytes, 'HKDF-SHA2-256',
  [{ hkdfCtx: 'enc', hkdfLen: 32 }, { hkdfCtx: 'mac', hkdfLen: 32 }]);
```

### Indirect operations (ECDH-derived keys)

`hmacHash`, `hmacVerify`, `cipherEncrypt`, `cipherDecrypt`, `cipherWrap` and
`cipherUnwrap` all accept `extKid` (a key in the HEM) or `pubkey` (raw bytes).
Either one makes the device run ECDH between `kid` and that peer key and use
the result as the operation's key, so the key actually in use never exists
outside the HEM. Pass one or the other, never both; the peer key is of the
same type as `kid`. The cipher calls derive the key by HKDF, shaped by
`hkdfCtx` and `hkdfSalt` (1..128 bytes each), which must be repeated to get
the same key back.

Naming **the key's own public key** is legal and gives a self-ECDH key — a key
derived from a private key that cannot be recomputed by anyone holding only
public material. That is what lets a device authenticate its own stored
configuration without a separate secret.

### HMAC

```js
const mac = await hem.hmacHash(token, kid, data, 'SHA2-256');      // Uint8Array
const ok = await hem.hmacVerify(token, kid, data, mac, 'SHA2-256'); // true / false

// MAC key = ECDH(kid, myOwnPubKey) — never leaves the device. The peer modes need alg.
const mac2 = await hem.hmacHash(token, kid, data, 'SHA2-256', { pubkey: myPubKeyBytes });
await hem.hmacVerify(token, kid, data, mac2, 'SHA2-256', { pubkey: myPubKeyBytes });
```

### Symmetric encryption

`alg` is `AES128-CBC` … `AES256-GCM`, or `CHACHA20-POLY1305` (a 256-bit key:
an `AES256` key in the HEM). There is no ECB.

The IV is generated by the device (CBC 16 B, GCM and ChaCha20 12 B), and GCM /
ChaCha20-Poly1305 add a 16-byte tag — both come back with the ciphertext and
both must be handed to `cipherDecrypt`.

```js
const { ciphertext, iv, tag } = await hem.cipherEncrypt(token, kid, data, 'AES256-GCM');
const plaintext = await hem.cipherDecrypt(token, kid, ciphertext, 'AES256-GCM', { iv, tag });

// With additional authenticated data, and a key derived from a peer's key:
const enc = await hem.cipherEncrypt(token, kid, data, 'CHACHA20-POLY1305',
  { extKid: peerKid, hkdfCtx: 'files:v1', aad: headerBytes });
```

### Key wrapping

AES key wrap (RFC 3394): deterministic, n bytes in, n + 8 out (16..2048, a
multiple of 8). The KEK is `AES256` unless `alg` says otherwise.

```js
const wrapped   = await hem.cipherWrap(token, kid, keyMaterialBytes);
const unwrapped = await hem.cipherUnwrap(token, kid, wrapped);

// Under a self-ECDH KEK, domain-separated by hkdfCtx. Every option must be
// repeated on unwrap — a different context derives a different KEK.
const opts = { pubkey: myPubKeyBytes, hkdfCtx: 'ENC-WG-PSK-v1' };
const psk      = await hem.cipherWrap(token, kid, pskBytes, opts);
const pskPlain = await hem.cipherUnwrap(token, kid, psk, opts);
```

### Post-quantum (ML-KEM / ML-DSA)

```js
// ML-KEM: encapsulate to a key in the HEM (made there, or imported), decapsulate with one made there.
const { alg, ss, ct } = await hem.mlkemEncaps(token, kemKid);
const ss2 = await hem.mlkemDecaps(token, kemKid, ct);     // ss2 equals ss

// ML-DSA: the message itself, or (mode) a digest or μ for data over 2 KB.
const sig = await hem.mldsaSign(token, dsaKid, data, { ctx: 'my-app' });
await hem.mldsaVerify(token, dsaKid, data, sig, { ctx: 'my-app' });   // true / false
const sigH = await hem.mldsaSign(token, dsaKid, sha512Digest, { mode: 'HashML-DSA-SHA512' });
```

### X-Wing and HPKE

```js
// Both operations take two keys for X-Wing (an MLKEM768 and a CURVE25519 key):
// one token with both scopes.
const t2 = await hem.authorizePassword('my-password', [`keymgmt:use:${kemKid}`, `keymgmt:use:${xKid}`]);
const { ss, ct } = await hem.xwingEncaps(t2, kemKid, xKid);       // ct: 1120 bytes
const ss2 = await hem.xwingDecaps(t2, kemKid, xKid, ct);

// HPKE (RFC 9180), Base mode, one message: to a key of the HEM ...
const sealed = await hem.hpkeSeal(token, { kid: inboxKid }, 'for the inbox', { info: 'app:v1' });
// ... or to anyone's public key - any valid token will do then.
const out = await hem.hpkeSeal(token, { pubkey: bobX25519, kem: 'DHKEM-X25519' }, data);
// Open with a key pair made with mode 'HPKE'; suite, info and aad as sealed.
const plain = await hem.hpkeOpen(token, inboxKid, sealed.enc, sealed.ct, { info: 'app:v1' });
```

### KDF, one-time passwords, random

```js
// Bytes out of a stored HMAC key (keep them in the HEM with deriveKey() instead):
const okm = await hem.kdf(token, hmacKid, 'HKDF', 32, { salt: 'tenant-7', info: 'enc' });
const k = await hem.kdf(token, hmacKid, 'SP800-108', 32, { info: labelZeroContext });

// TOTP / HOTP on a stored SHA1 seed; the seed never leaves the HEM.
const { code, step } = await hem.otp(token, otpKid);                      // TOTP, device clock
const r = await hem.otpVerify(token, otpKid, '287082', { window: 1 });   // { verified, step }
// The device remembers no used codes: refuse a step not larger than the last one accepted.

const nonce = await hem.random(token, 32);
```

---

## 5. System

```js
// No auth required:
const version = await hem.getVersion();   // { hwv, fwv, fwk, fws, fwc, blv, blk, bls, blc, uis }
const status  = await hem.getStatus();

// Auth required (scope: system:config):
const token = await hem.authorizePassword('my-password', 'system:config');
const config = await hem.getConfig(token);
await hem.setConfig(token, { user: 'New Name' });          // { updated: true }

// Device attestation — any valid token is accepted
const attestation = await hem.getAttestation(token);       // { genuine, crt | csr, ... }
// Bound to this request with a nonce of ours (32..64 B):
const fresh = await hem.getAttestation(token, { nonce: crypto.getRandomValues(new Uint8Array(32)) });

// Lifecycle: system:config does all three (reboot also takes system:upgrade /
// system:shutdown, shutdown system:shutdown)
await hem.selftest(token);
await hem.reboot(token);
await hem.shutdown(token);

// Key storage reclaim: deleted keys leave holes until one runs (at the next boot).
const report = await hem.defragCheck(token);              // { reclaimable, reclaimable_size, ... }
if (report.reclaimable) await hem.defragStart(token);     // { started: true }: the device restarts

// A device out of the box, no token: HTTPS, and on an EPA its attestation key.
const { csr } = await hem.bootstrap({ att: { seed: moduleSeed /* 32 B */, epoch: 0 } });
```

---

## 6. Firmware / UI upgrade

Scope: `system:upgrade`. The SDK takes a raw `Uint8Array` — obtaining it is up
to the caller.

```js
const token = await hem.authorizePassword('my-password', 'system:upgrade');

// --- Get the firmware bytes ---

// a) From a local file (Node.js):
import { readFile } from 'node:fs/promises';
const fwBytes = new Uint8Array(await readFile('./encedo_fw.hex'));

// b) From a URL (browser or Node):
const fwBytes2 = new Uint8Array(await (await fetch(fwUrl)).arrayBuffer());

// c) From a file picker (browser):
// const fwBytes3 = new Uint8Array(await fileInput.files[0].arrayBuffer());

// d) The image the check-in announced, straight from the broker:
const { newfws } = await hem.hemCheckin();
const fwBytes4 = await hem.broker.download('firmware', newfws);   // Uint8Array

// --- Upgrade flow ---
// The device takes firmware.bin or firmware.hex only; the SDK picks the name
// from the content (Intel HEX starts with ':'), or pass { format: 'hex' }.
await hem.uploadFirmware(token, fwBytes, {
  onProgress: (loaded, total) => bar.value = loaded / total,   // browser only
  // signal: ac.signal,
});
await hem.waitFirmwareCheck(token);           // the device verifies in the background; this polls until it is done
await hem.installFirmware(token);             // device reboots afterwards

// UI bundle (sent as webroot.tar) — same pattern
await hem.uploadUi(token, uiBytes);
await hem.waitUiCheck(token);
await hem.installUi(token);
```

---

## 7. Storage

The disk (disk0 / disk1) is selected by the token's scope, not an argument.

```js
const token = await hem.authorizePassword('my-password', 'storage:disk0:rw');
await hem.lockStorage(token);
await hem.unlockStorage(token);                  // writable: the scope ends in :rw
await hem.unlockStorage(token, { mode: 'ro' });  // read-only all the same
```

---

## 8. Audit log

Scope: `logger:get`.

```js
const token = await hem.authorizePassword('my-password', 'logger:get');

// The device log key, with its signature over a nonce of ours: proof the device holds it now.
const nonce = crypto.getRandomValues(new Uint8Array(32));
const loggerKey = await hem.getLoggerKey(token, { nonce });   // { key, nonce, nonce_signed }
const proven = await verifyLoggerKey(loggerKey, nonce);

// One file per power-up; the one being written is `current`, not listed (and 409 if asked for).
const { id: ids, total, current } = await hem.listLogFiles(token, { offset: 0 });
const text = await hem.getLogFile(token, ids[0]);              // the file, text
```

Format v2 (firmware 1.3): every line is signed (Ed25519) with a per-file key,
and each file opens with a header that certifies that key with the device log
key. Verify before showing a file as evidence:

```js
const r = await hem.verifyLogFile(token, ids[0]);   // proves the key, fetches, verifies
if (!r.ok) console.warn(r.reason ? `line ${r.line}: ${r.reason}` : `deleted lines: ${JSON.stringify(r.gaps)}`);
// reason: format | cut_front | no_header | header | rotate | signature; gaps: deleted lines

// Or, with data already in hand (pure Web Crypto, no device call):
import { verifyLog, verifyLoggerKey } from './hem-sdk.js';
const result = await verifyLog(loggerKey.key, text);  // { ok, lines, headers, rotations, lost, gaps }
```

Share a key's share-code by e-mail through the broker:

```js
await hem.broker.shareEmailPubkey('bob@example.com', shareCode);   // shareCode: the object the share page built
```

---

## Attestation

A HEM signs who it is, and one of its keys with a proof that it holds the
private half, in a JWT. Checking it has three levels:

```js
import { HEM, Attest } from './hem-sdk.js';

// The verifier makes a challenge; the HEM answers it.
const { request, state } = await Attest.prepare({ aud: 'bank.example', kid, pop: 'sig' });
const jwt = await hem.attest(await hem.authorizePassword(pw, `keymgmt:use:${kid}`), request);

// 1. The token itself: device signature, kid, claims, our nonce, the key's PoP. No network.
const r = await Attest.verify(jwt, state);   // { ok, failed, expired, skid, point, claims, pop }
if (!r.ok) throw new Error(`attestation: ${r.failed.join(', ')}`);

// 1_ext. The device certificate carries that key and chains to the Encedo Root CA
//        (pinned by its SHA-256); the CA certificates are fetched once.
const attest = new Attest();                  // https://attest.encedo.com
const { crt } = await hem.getAttestation(token);
const dev = await attest.verifyDevice(r.point, crt);   // { ok, chain }

// 2. attest.encedo.com: the registry of issued certificates and the revocation lists.
const { status } = await attest.validate(jwt, { crt });   // valid | valid_unverified | invalid
const known = await attest.skidKnown(r.skid);              // only the SKID leaves the client
```

An ECDH PoP (keys that agree, not sign) needs the key's curve:
`Attest.prepare({ aud, kid, pop: 'ecdh', curve: 'CURVE25519' })`. Checked
here: signatures of P-256/384/521 and Ed25519, ECDH-MAC of P-256/384/521 and
X25519. Ed448, secp256k1, ML-DSA, X448, ML-KEM and HPKE PoPs are TBD; a token
asking for one is not `ok` here (`pop_unsupported`) — level 2 or the
`attest_verify` CLI check them. An EPA has no device certificate yet: level 1
and level 2 only.

---

## Error handling

```js
try {
  await hem.listKeys(token);
} catch (e) {
  if (e instanceof HemError) {
    console.error('HEM error:', e.code, e.status, e.data);
    // codes: network, timeout, aborted, http_<status>, checkin_error,
    //        broker_error, auth_failed, auth_password_required, denied,
    //        sign_error, verify_failed, ecdh_error, hmac_error, cipher_error,
    //        pqc_error, ext_register_error, domain_error, mnemonic_invalid,
    //        mnemonic_checksum
  } else {
    throw e;
  }
}
```

## Logout / cleanup

```js
hem.clearCache();   // drop cached JWT tokens
hem.clearKeys();    // drop cached derived X25519 keys AND all tokens — on logout
```

## Reading a token

```js
import { jwtParse } from './hem-sdk.js';
const { scope, exp, sub } = jwtParse(token) ?? {};
```
