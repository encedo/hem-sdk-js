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
connection and synchronises clocks.

```js
await hem.hemCheckin();
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
const token = await hem.authorizeRemote('keymgmt:list', {
  pollInterval: 2000,                       // ms between broker polls
  pollTimeout: 60000,                       // give up after this long
  onPending: () => console.log('waiting for mobile approval…'),
  // signal: abortController.signal,        // optional — cancel the wait
});
```

### Device initialization (provisioning)

One-time provisioning of a factory-fresh device. `masterkey` / `userkey` are
derived from the passwords automatically — you only supply the metadata.

```js
const result = await hem.initialize('admin-passphrase', 'user-passphrase', {
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

---

## 3. Key management

```js
const token = await hem.authorizePassword('my-password', 'keymgmt:list');

// List — paginated; returns [{ kid, label, type, description }]
const keys = await hem.listKeys(token, 0, 50);

// Search by description (regex against the description field)
const found = await hem.searchKeys(token, 'CCTEST:');
```

```js
// Create a key pair (scope: keymgmt:gen). descr must be base64.
const genToken = await hem.authorizePassword('my-password', 'keymgmt:gen');
const { kid } = await hem.createKeyPair(genToken, 'My signing key', 'ED25519',
  btoa('purpose: document signing'));

// Derive a key from an existing ECDH key + a peer public key
const derived = await hem.deriveKey(genToken, 'Derived key', 'ED25519',
  btoa('derived'), ecdhKid, peerPubKeyBase64);
```

```js
// Import an external public key (scope: keymgmt:imp)
const impToken = await hem.authorizePassword('my-password', 'keymgmt:imp');
const imported = await hem.importPublicKey(impToken, 'Peer key', 'ED25519',
  rawPubKeyBytes /* Uint8Array */, btoa('peer'));

// Update label/description (scope: keymgmt:upd)
const updToken = await hem.authorizePassword('my-password', 'keymgmt:upd');
await hem.updateKey(updToken, kid, 'Renamed key', btoa('new description'));

// Get public key metadata (scope: keymgmt:use:<KID>)
const useToken = await hem.authorizePassword('my-password', `keymgmt:use:${kid}`);
const pub = await hem.getPubKey(useToken, kid);

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
```

### HMAC

```js
const mac = await hem.hmacHash(token, kid, data, 'SHA2-256');      // Uint8Array
await hem.hmacVerify(token, kid, data, mac, 'SHA2-256');           // true / throws
```

### Symmetric encryption

`alg` is `<type>-<mode>`, e.g. `AES256-CBC`, `AES256-GCM`, `AES256-ECB`.
For ECB the plaintext length must be a multiple of 16 bytes.

```js
const ciphertext = await hem.cipherEncrypt(token, kid, data, 'AES256-CBC');
const plaintext  = await hem.cipherDecrypt(token, kid, ciphertext, 'AES256-CBC');
```

### Key wrapping

```js
const wrapped   = await hem.cipherWrap(token, kid, 'AES256', keyMaterialBytes);
const unwrapped = await hem.cipherUnwrap(token, kid, 'AES256', wrapped);
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
const provisioning = await hem.getProvisioning(token);

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

// --- Upgrade flow ---
await hem.usbMode(token);
await hem.uploadFirmware(token, fwBytes);     // optional filename arg
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

const signerKey = await hem.getLoggerKey(token);   // key used to sign log entries
const page      = await hem.listLog(token, 0);     // entries from offset 0
const entry     = await hem.getLogEntry(token, entryId);
```

---

## Error handling

```js
try {
  await hem.listKeys(token);
} catch (e) {
  if (e instanceof HemError) {
    console.error('HEM error:', e.code, e.status, e.data);
    // codes: network, timeout, http_<status>, checkin_error, broker_error,
    //        auth_failed, auth_password_required, denied, sign_error,
    //        verify_failed, ecdh_error, hmac_error, cipher_error, pqc_error,
    //        ext_register_error
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
