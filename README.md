# hem-sdk-js

Encedo HEM SDK — JavaScript.

A dependency-free client for the Encedo **HEM** hardware security device. Runs in
the browser (Web Crypto + `fetch`) and in Node.js. Key material never leaves the
device — the SDK only sends challenges and receives signatures, public keys or
shared secrets.

## Requirements

- **Browser**: Chrome 113+ / Firefox 130+ (X25519 in the Web Crypto API).
- **Node.js**: 18+ (built-in `fetch` and Web Crypto).
- No runtime dependencies.

## Files

| File | Purpose |
|------|---------|
| `hem-sdk.js` | ES module source — import this in Node or with a bundler. |
| `hem-sdk.browser.js` | Pre-built browser bundle (ES module). |
| `hem-sdk.browser.js.map` | Source map for the browser bundle. |
| `hem-sdk.browser.d.ts` | TypeScript type declarations. |
| `rollup.browser.config.js` | Rollup config for the browser bundle. |
| `test/sdk.test.mjs` | End-to-end test against a mock device and broker (`node --test test/sdk.test.mjs`). |

Rebuild the browser bundle after changing `hem-sdk.js`:

```bash
npx rollup -c rollup.browser.config.js
```

## Quick start

```js
import { HEM, HemError } from './hem-sdk.js';

const hem = new HEM('https://abc.ence.do');

const health = await hem.hemCheckin();                      // once, first; { status, newfws?, newuis? }
const token  = await hem.authorizePassword('my-password', 'keymgmt:list');
const { list, total } = await hem.listKeys(token);            // one page, and how many keys there are
```

## Device and broker

Two classes, one boundary. **`HEM`** is the device: everything it does works
with the device alone, so a module behind an air gap authorises with a
password, manages keys, unlocks storage and reads its audit log without a
network. **`Broker`** is the Encedo backend at `api.encedo.com`: the clock
check-in, mobile push authorisation, pairing and listing mobile
authenticators, software downloads, `*.ence.do` domains with their TLS
certificates, provisioning, and sharing a key by e-mail. Every call to the
backend lives in `Broker`, one method per endpoint; `HEM` composes them with
device calls and exposes its instance as `hem.broker` for the calls a page
makes on its own (a domain check while the user types).

```js
const hem = new HEM('https://abc.ence.do', { broker: 'https://api.encedo.com' });
const { prefix } = await hem.broker.domainPredefs();
```

See **[EXAMPLES.md](./EXAMPLES.md)** for commented usage of every operation.

## What it does

The SDK wraps the HEM device REST API. Operations are grouped as:

| Group | Operations |
|-------|------------|
| **Checkin** | `hemCheckin` — connection test + clock sync (call once, first); returns `newfws` / `newuis` when an update is available |
| **Authentication** (a scope is a string or an array of 1..8; a cached token serves each scope it holds) | `authorizePassword`, `authorizeRemote` (mobile push; cancelling withdraws the event), `authorizeMaster` (the 24 words), `initialize` (device initialisation) |
| **Master secret** | `generateMnemonic`, `entropyToMnemonic`, `mnemonicToEntropy`, `validateMnemonic` — BIP39, where the entropy *is* the master key |
| **Mobile authenticators** | `registerExtAuth` (pair; hands the QR payload to the caller), `listExtAuth`, `deleteExtAuth`, `hasExtAuth`, `getExtAuthMac` |
| **Provisioning and domains** | `provision` / `installProvisioning` (device certificate), `registerDomain` (`<prefix>.ence.do` + TLS) |
| **Stripped build** | `rollup.mini.config.js`: only the methods a project lists, with what they call (CLAUDE.md) |
| **Key management** | `listKeys`, `searchKeys` (prefix / suffix / anywhere, type and mode filters), `listKeysAll` / `searchKeysAll` (every page, async generators), `getKeyPublicInfo`, `createKeyPair`, `deriveKey` (ECDH or HMAC parent), `importPublicKey`, `updateKey`, `deleteKey` — every key in one shape, `HemKey` |
| **Cryptography** | `exdsaSign`/`exdsaVerify` (EdDSA/ECDSA, `det`, `ctx`), `ecdh` (peer bytes or KID; raw, digest or HKDF), `ecdhHkdf` (several keys from one agreement), `hmacHash`/`hmacVerify`, `cipherEncrypt`/`cipherDecrypt` (AES-CBC/GCM, ChaCha20-Poly1305), `cipherWrap`/`cipherUnwrap`, `mlkemEncaps`/`mlkemDecaps`, `mldsaSign`/`mldsaVerify` (post-quantum; HashML-DSA and external μ), `xwingEncaps`/`xwingDecaps`, `hpkeSeal`/`hpkeOpen` (RFC 9180), `kdf` (HKDF, SP 800-108), `otp`/`otpVerify` (TOTP, HOTP), `random`. The `*Verify` calls resolve to the device's verdict, `true` or `false` |
| **System** | `getVersion`, `getStatus`, `getConfig`, `setConfig`, `setUserPassword`, `getAttestation`, `reboot`, `shutdown`, `selftest`, `defragCheck`/`defragStart` (key storage reclaim), `bootstrap` (before personalisation: HTTPS, EPA attestation key) |
| **Upgrade** | `rebootToUsbMode`, `uploadFirmware`/`checkFirmware`/`waitFirmwareCheck`/`installFirmware`, `uploadUi`/`checkUi`/`waitUiCheck`/`installUi` (uploads take `onProgress`; the checks answer null while the device is still verifying, the waits poll) |
| **Storage** | `lockStorage`, `unlockStorage` |
| **Audit log** | `getLoggerKey` (with a nonce of ours), `listLogFiles`, `getLogFile`, `verifyLogFile` |
| **Cache** | `clearCache`, `clearKeys` |
| **Broker** (`hem.broker`) | `checkin`, `session`, `eventNew`/`eventCheck`/`eventDelete`/`waitEvent`, `registerInit`/`registerCheck`/`registerFinalise`/`waitRegistration`, `subscribersList`/`subscribersDelete`, `download`, `domainPredefs`/`domainTaken`/`domainRegister`/`domainStatus`/`waitDomain`, `provisioning`, `shareEmailPubkey` |
| **Attestation** (`Attest`, `hem.attest`) | `Attest.prepare` (challenge), `hem.attest` (the device signs), `Attest.verify` (token + PoP, no network), `attest.verifyDevice` (certificate chain to the pinned Encedo root), `attest.validate` / `skidKnown` / `pki` (attest.encedo.com) |
| **Helpers** (exported functions) | `verifyLog` (audit log, format v2, pure Web Crypto), `verifyLoggerKey` (the device signed the nonce it sent with the key), `jwtParse` |

### The master secret

A HEM's master identity is 256 bits of entropy from the CSPRNG. Those 32 bytes
**are** the master X25519 private key, and the same 32 bytes are what the 24
words encode — so the words on a Proof of Personalization are the key itself:
any BIP39 implementation decodes them, and the checksum catches a mistyped
word before anything reaches the device.

```js
const mnemonic = await generateMnemonic();          // show it, print it, never store it
await hem.initialize({ mnemonic }, userPassword, { user: 'Ann', hostname: 'my.ence.do' });
const token = await hem.authorizeMaster(mnemonic, 'system:config');
```

Full signatures are in [`hem-sdk.browser.d.ts`](./hem-sdk.browser.d.ts).

## Scopes

Every JWT is issued for a scope that authorizes a class of operations:

| Scope | Authorizes |
|-------|------------|
| `keymgmt:list` | `listKeys` |
| `keymgmt:search` | `searchKeys` (or `keymgmt:list`, or `auth:ext:pair`; no token at all for a prefix of ≥ 6 bytes when the device has `allow_keysearch`) |
| `keymgmt:gen` | `createKeyPair`, `deriveKey` (also `getKeyPublicInfo`) |
| `keymgmt:derive` | `deriveKey` |
| `keymgmt:imp` | `importPublicKey` |
| `keymgmt:upd` | `updateKey` |
| `keymgmt:del` | `deleteKey` |
| `keymgmt:get` | `getKeyPublicInfo` |
| `keymgmt:use:<KID>` | all `/crypto/*` operations on that key, and `getKeyPublicInfo` of it (X-Wing and HPKE with two keys: both, in one token) |
| any valid token | `random`, `hpkeSeal` to `{ pubkey, kem }`, `getAttestation` |
| `system:config` | `getConfig`, `setConfig`, `setUserPassword`, `registerExtAuth`, `listExtAuth`, `deleteExtAuth`, `registerDomain`, `selftest`, `defragCheck`, `defragStart`, `reboot`, `shutdown`, `rebootToUsbMode` and the upgrade checks / installs |
| `system:upgrade` | all upgrade operations, `reboot` |
| `system:shutdown` | `reboot`, `shutdown` |
| `storage:disk<N>:rw` | `lockStorage`, `unlockStorage` for that disk |
| `logger:get` | `getLoggerKey`, `listLogFiles`, `getLogFile`, `verifyLogFile`, `getConfig` |

## Error handling

Every failure throws a `HemError` with `code` (machine-readable), `status` (HTTP
status or `0`) and `data` (response body when available). A cancelled request
or wait is `aborted`, a deadline is `timeout`, a refusal on the phone is
`denied`. See [EXAMPLES.md](./EXAMPLES.md#error-handling).

## Tests

```bash
node --test test/sdk.test.mjs
```

`test/sdk.test.mjs` runs the SDK against an in-process mock of the device and
the broker; the mock verifies the eJWT the SDK signs. No hardware needed.

```bash
node test/device.mjs [https://my.ence.do] [user password]
```

`test/device.mjs` runs every group against a real, personalised HEM (PPA,
firmware 1.3): key types and modes, paging, all crypto calls checked against
Node's own crypto, attestation with each PoP checked here and the device
certificate chained to pki.encedo.com, the audit log. It makes its own keys
(`SDK-TEST-*`) and deletes them; no reboot, wipe, upgrade or disk unlock.

## Security notes

- Passwords are zeroed in memory immediately after key derivation.
- Derived X25519 private keys are non-extractable `CryptoKey` objects.
- Call `clearKeys()` on logout to discard cached keys and tokens.

## License

See [LICENSE](./LICENSE).
