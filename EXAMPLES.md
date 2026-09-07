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

```js
const token = await hem.authorizePassword('my-password', 'keymgmt:list');

// List — one page at a time. `total` is the size of the whole repository,
// so a caller knows whether to ask for the next page.
// list: [{ kid, label, type, created, updated, description }]
const { list, total } = await hem.listKeys(token, 0, 50);
const all = list.length < total ? list.concat((await hem.listKeys(token, list.length, 50)).list) : list;
```

```js
// Search by description prefix. Pass the plain pattern — the SDK base64-encodes
// it and prepends the '^' anchor the device expects.
const found = await hem.searchKeys(token, 'CCTEST:');

// A binary pattern works too, for descriptions that are not text:
const wgPeers = await hem.searchKeys(token, new Uint8Array([0x57, 0x47, 0x3a, 0x70, 0x72, 0x3a]));

// Paginate: the device returns at most `limit` entries (its default is 15).
const page = [];
for (let offset = 0; ; offset += 50) {
  const batch = await hem.searchKeys(token, 'CCTEST:', offset, 50);
  page.push(...batch);
  if (batch.length < 50) break;
}

// No token at all — allowed when the device is configured with allow_keysearch
// and the pattern is at least 6 bytes.
const anon = await hem.searchKeys(null, 'CCTEST:');
```

```js
// Create a key pair (scope: keymgmt:gen). descr must be base64.
const genToken = await hem.authorizePassword('my-password', 'keymgmt:gen');
const { kid } = await hem.createKeyPair(genToken, 'My signing key', 'ED25519',
  btoa('purpose: document signing'));

// The NIST curves can sign AND agree, so they need to be told which:
const nistKid = await hem.createKeyPair(genToken, 'Work P-384', 'SECP384R1',
  btoa('purpose: both'), 'ECDH,ExDSA');

// Derive a key from an existing ECDH key + a peer public key
const derived = await hem.deriveKey(genToken, 'Derived key', 'ED25519',
  btoa('derived'), ecdhKid, peerPubKeyBase64);
```

```js
// Import an external public key (scope: keymgmt:imp)
const impToken = await hem.authorizePassword('my-password', 'keymgmt:imp');
const imported = await hem.importPublicKey(impToken, 'Peer key', 'ED25519',
  rawPubKeyBytes /* Uint8Array */, btoa('peer'));

// NIST ECC (SECP256R1/384R1/521R1, SECP256K1) additionally REQUIRE a usage mode
// ('ECDH', 'ExDSA' or 'ECDH,ExDSA') and take a COMPRESSED SEC1 point (0x02/0x03||X):
const nist = await hem.importPublicKey(impToken, 'Peer P-384', 'SECP384R1',
  compressedPoint /* Uint8Array, 49 B */, btoa('peer'), 'ECDH');

// Update label/description (scope: keymgmt:upd)
const updToken = await hem.authorizePassword('my-password', 'keymgmt:upd');
await hem.updateKey(updToken, kid, 'Renamed key', btoa('new description'));

// Get public key metadata: { type, pubkey, updated } (scope: keymgmt:get)
const getToken = await hem.authorizePassword('my-password', 'keymgmt:get');
const pub = await hem.getPubKey(getToken, kid);

// Delete (scope: keymgmt:del)
const delToken = await hem.authorizePassword('my-password', 'keymgmt:del');
await hem.deleteKey(delToken, kid);
```

---

## 4. Cryptography

All `/crypto/*` operations need a `keymgmt:use:<KID>` token.

```js
const token = await hem.authorizePassword('my-password', `keymgmt:use:${kid}`);
const data = new TextEncoder().encode('message to protect');
```

### EdDSA / ECDSA signing

```js
// Sign a string (UTF-8 encoded internally)
const sig1 = await hem.exdsaSign(token, kid, 'hello world');

// Sign raw bytes — use this for OpenPGP / TLS / JWT etc.
const sig2 = await hem.exdsaSignBytes(token, kid, data);          // Uint8Array

// Verify (against an imported public key). Resolves true or throws.
await hem.exdsaVerify(token, kid, data, sig2);

// Other algorithms — pass a base64 ctx for Ed25519ctx / Ed448
const sig3 = await hem.exdsaSignBytes(token, kid, data, 'Ed25519ctx', btoa('ctx'));
```

### ECDH

```js
// Curve25519 ECDH on the device — returns the raw 32-byte shared secret.
const secret = await hem.ecdh(token, kid, peerPubKeyBase64);       // Uint8Array

// Two-KID variant: the peer public key is already imported in the HSM (extKid);
// both operands stay in-device, only the 32-byte shared secret comes back.
const secret2 = await hem.ecdhKid(token, kid, extKid);            // Uint8Array

// alg hashes the result. Omit it whenever you need the raw secret — a Noise or
// TLS handshake will not match a digest.
const hashed = await hem.ecdh(token, kid, peerPubKeyBase64, { alg: 'SHA2-256' });
```

### Indirect operations (ECDH-derived keys)

`hmacHash`, `hmacVerify`, `cipherEncrypt`, `cipherDecrypt`, `cipherWrap` and
`cipherUnwrap` all accept `extKid` or `pubkey`. Either one makes the device run
ECDH between `kid` and that peer key and use the shared secret as the
operation's key, so the key actually in use never exists outside the HSM. Pass
one or the other, never both, and the peer key must be of the same type as `kid`.

Naming **the key's own public key** is legal and gives a self-ECDH key — a key
derived from a private key that cannot be recomputed by anyone holding only
public material. That is what lets a device authenticate its own stored
configuration without a separate secret.

### HMAC

```js
const mac = await hem.hmacHash(token, kid, data, 'SHA2-256');      // Uint8Array
await hem.hmacVerify(token, kid, data, mac, 'SHA2-256');           // true / throws

// MAC key = ECDH(kid, myOwnPubKey) — never leaves the device.
const mac2 = await hem.hmacHash(token, kid, data, 'SHA2-256', { pubkey: myPubKeyBase64 });
await hem.hmacVerify(token, kid, data, mac2, 'SHA2-256', { pubkey: myPubKeyBase64 });
```

`data` is limited to 2048 bytes, as is every other `/crypto/*` payload.

### Symmetric encryption

`alg` is `<type>-<mode>`, e.g. `AES256-CBC`, `AES256-GCM`, `AES256-ECB`.
For ECB the plaintext length must be a multiple of 16 bytes.

The IV is generated by the device, and GCM adds an authentication tag — both
come back with the ciphertext and both must be handed to `cipherDecrypt`.

```js
const { ciphertext, iv, tag } = await hem.cipherEncrypt(token, kid, data, 'AES256-GCM');
const plaintext = await hem.cipherDecrypt(token, kid, ciphertext, 'AES256-GCM', { iv, tag });

// With additional authenticated data, and a key derived from a peer's key:
const enc = await hem.cipherEncrypt(token, kid, data, 'AES256-GCM',
  { extKid: peerKid, aad: headerBytes });
```

### Key wrapping

NIST AES key wrap: deterministic, 32 bytes in → 40 bytes out.

```js
const wrapped   = await hem.cipherWrap(token, kid, 'AES256', keyMaterialBytes);
const unwrapped = await hem.cipherUnwrap(token, kid, 'AES256', wrapped);

// Wrapped under a self-ECDH KEK, domain-separated by ctx (max 64 bytes).
// Every option must be repeated verbatim on unwrap — a different ctx derives a
// different KEK and the unwrap fails.
const opts = { pubkey: myPubKeyBase64, ctx: 'ENC-WG-PSK-v1' };
const psk        = await hem.cipherWrap(token, kid, 'AES256', pskBytes, opts);
const pskPlain   = await hem.cipherUnwrap(token, kid, 'AES256', psk, opts);
```

### Post-quantum (ML-KEM / ML-DSA)

```js
// ML-KEM key encapsulation
const { ss, ct } = await hem.mlkemEncaps(token, kemKid);  // ss = shared secret
const ss2 = await hem.mlkemDecaps(token, kemKid, ct);     // ss2 equals ss

// ML-DSA signatures
const sig = await hem.mldsaSign(token, dsaKid, data);
await hem.mldsaVerify(token, dsaKid, data, sig);          // true / throws
```

---

## 5. System

```js
// No auth required:
const version = await hem.getVersion();   // { hwv, blv, fwv, fws, conf }
const status  = await hem.getStatus();

// Auth required (scope: system:config):
const token = await hem.authorizePassword('my-password', 'system:config');
const config = await hem.getConfig(token);
await hem.setConfig(token, { user: 'New Name' });          // { updated: true }

// Device attestation — any valid token is accepted
const attestation = await hem.getAttestation(token);       // { genuine, ... }

// Lifecycle — any valid token
await hem.reboot(token);
await hem.shutdown(token);
await hem.selftest(token);
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
await hem.usbMode(token);
await hem.uploadFirmware(token, fwBytes, 'firmware.bin', {
  onProgress: (loaded, total) => bar.value = loaded / total,   // browser only
  // signal: ac.signal,
});
await hem.checkFirmware(token);               // verify the uploaded image
await hem.installFirmware(token);             // device reboots afterwards

// UI bundle — same pattern
await hem.uploadUi(token, uiBytes);
await hem.checkUi(token);
await hem.installUi(token);
```

---

## 7. Storage

The disk (disk0 / disk1) is selected by the token's scope, not an argument.

```js
const token = await hem.authorizePassword('my-password', 'storage:disk0:rw');
await hem.lockStorage(token);
await hem.unlockStorage(token);
```

---

## 8. Audit log

Scope: `logger:get`.

```js
const token = await hem.authorizePassword('my-password', 'logger:get');

const signerKey = await hem.getLoggerKey(token);   // { key }: Ed25519 key that signs log entries
const page      = await hem.listLog(token, 0);     // entries from offset 0
const entry     = await hem.getLogEntry(token, entryId);   // the log file, text
```

Each log file carries its own integrity chain: signed key lines and an HMAC on
every line. Verify before showing it as evidence:

```js
const { ok, lines, line, reason, text } = await hem.verifyLogEntry(token, entryId);
if (!ok) console.warn(`log ${entryId} fails at entry ${line}: ${reason}`);   // signature | sequence | no_key | hmac

// Or, with data already in hand (pure Web Crypto, no device call):
import { verifyLog } from './hem-sdk.js';
const result = await verifyLog(signerKey.key, text);
```

Share a key's share-code by e-mail through the broker:

```js
await hem.broker.shareEmailPubkey('bob@example.com', shareCode);   // shareCode: the object the share page built
```

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
