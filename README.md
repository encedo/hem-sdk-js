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

Rebuild the browser bundle after changing `hem-sdk.js`:

```bash
npx rollup -c rollup.browser.config.js
```

## Quick start

```js
import { HEM, HemError } from './hem-sdk.js';

const hem = new HEM('https://abc.ence.do');

await hem.hemCheckin();                                     // required once, first
const token = await hem.authorizePassword('my-password', 'keymgmt:list');
const keys  = await hem.listKeys(token);
```

See **[EXAMPLES.md](./EXAMPLES.md)** for commented usage of every operation.

## What it does

The SDK wraps the HEM device REST API. Operations are grouped as:

| Group | Operations |
|-------|------------|
| **Checkin** | `hemCheckin` — connection test + clock sync (call once, first) |
| **Authentication** | `authorizePassword`, `authorizeRemote` (mobile push), `initialize` (device provisioning), `registerExtAuth` (pair a mobile authenticator), `getExtAuthMac` (list paired authenticators) |
| **Key management** | `listKeys`, `searchKeys`, `getPubKey`, `createKeyPair`, `deriveKey`, `importPublicKey`, `updateKey`, `deleteKey` |
| **Cryptography** | `exdsaSign(Bytes)`/`exdsaVerify` (EdDSA/ECDSA), `ecdh`, `hmacHash`/`hmacVerify`, `cipherEncrypt`/`cipherDecrypt`, `cipherWrap`/`cipherUnwrap`, `mlkemEncaps`/`mlkemDecaps`, `mldsaSign`/`mldsaVerify` (post-quantum) |
| **System** | `getVersion`, `getStatus`, `getConfig`, `setConfig`, `getAttestation`, `reboot`, `shutdown`, `selftest` |
| **Upgrade** | `usbMode`, `uploadFirmware`/`checkFirmware`/`installFirmware`, `uploadUi`/`checkUi`/`installUi` |
| **Storage** | `lockStorage`, `unlockStorage` |
| **Audit log** | `getLoggerKey`, `listLog`, `getLogEntry` |
| **Cache** | `clearCache`, `clearKeys` |

Full signatures are in [`hem-sdk.browser.d.ts`](./hem-sdk.browser.d.ts).

## Scopes

Every JWT is issued for a scope that authorizes a class of operations:

| Scope | Authorizes |
|-------|------------|
| `keymgmt:list` | `listKeys`, `searchKeys` |
| `keymgmt:gen` | `createKeyPair`, `deriveKey` |
| `keymgmt:imp` | `importPublicKey` |
| `keymgmt:upd` | `updateKey` |
| `keymgmt:del` | `deleteKey` |
| `keymgmt:use:<KID>` | `getPubKey` and all `/crypto/*` operations on that key |
| `system:config` | `getConfig`, `setConfig`, `registerExtAuth` |
| `system:upgrade` | all upgrade operations |
| `storage:disk<N>:rw` | `lockStorage`, `unlockStorage` for that disk |
| `logger:get` | `getLoggerKey`, `listLog`, `getLogEntry` |

## Error handling

Every failure throws a `HemError` with `code` (machine-readable), `status` (HTTP
status or `0`) and `data` (response body when available). See
[EXAMPLES.md](./EXAMPLES.md#error-handling).

## Security notes

- Passwords are zeroed in memory immediately after key derivation.
- Derived X25519 private keys are non-extractable `CryptoKey` objects.
- Call `clearKeys()` on logout to discard cached keys and tokens.

## License

See [LICENSE](./LICENSE).
