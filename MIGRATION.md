# Upgrading to the merged SDK

Everything the Manager needed was on `manager-v2` for a week; it is on `main`
now and there are no branches. The public surface went from 52 methods to 83,
**nothing was removed**, and four things changed in a way that can break a
caller. This is the list, and what to do about each.

The SDK is shared: fix the project, not the SDK.

## 1. `listKeys()` returns `{ list, total }`, not an array

The device has always answered `{ list, total, listed }`; the SDK threw two
thirds of it away, so a caller could not say how many keys there are or page
without guessing.

```js
const keys = await hem.listKeys(token);              // before: an array
const { list, total } = await hem.listKeys(token);   // now
```

Entries also carry `created` and `updated` now, as `searchKeys()` entries
always did.

**Who this touches:** `listKeys` had no caller outside the Manager when this
was checked on 2026-09-04 — every project reads the keychain with
`searchKeys()`, which is unchanged. Grep for `listKeys` to be sure; if it
comes back empty, this one costs nothing.

## 2. `createKeyPair()` and `deriveKey()` take `mode` last, and send it only where it belongs

`mode` says what a key may be used for, and only a key that could do two jobs
needs one. The old code sent `MODE[type] ?? type`, which meant a key of type
`AES256` was created with `mode: 'AES256'` and one of `MLKEM768` with
`mode: 'MLKEM768'` — neither is anything the device asked for — and there was
no way to say `ECDH,ExDSA` for a NIST curve at all.

```js
await hem.createKeyPair(token, label, type, descr);                    // unchanged for 25519 keys
await hem.createKeyPair(token, label, 'SECP384R1', descr, 'ECDH,ExDSA'); // now possible
await hem.deriveKey(token, label, type, descr, kid, peer, mode);        // mode is last, optional
```

`ED25519` still sends `ExDSA` and `CURVE25519` still sends `ECDH`, so **for
those two the request on the wire is byte for byte what it was**. Every other
type now sends no `mode` unless you pass one.

**Who this touches:** a project that creates `ED25519` or `CURVE25519` keys —
which is all of them, as far as the compatibility table goes — sends exactly
what it sent before and needs no change. A project creating AES, ML-KEM or
SECP* keys should check what the device expects and pass `mode` if it wants
one. `encedo-oidc-boundle`'s own copy already had this signature, against real
devices, which is the best evidence that the shaping is right.

## 3. `checkFirmware()` and `checkUi()` answer `null` while the device is still checking

The device verifies an uploaded image in the background and answers 201 or 202
while it is at it. The SDK threw the status away, so a caller could not tell
"still checking" from "checked, and here is the result".

```js
const result = await hem.checkFirmware(token);   // now: null while it is still checking
const result = await hem.waitFirmwareCheck(token, { onPending });  // or let the SDK poll
```

`waitUiCheck()` is the same for a UI bundle. Both take `pollInterval`,
`pollTimeout`, `onPending` and `signal`.

**Who this touches:** only something that uploads firmware or a UI bundle. If
a caller treated any resolved value as success, it now has to wait for a
non-null one — or call the `wait…` form, which is what the Manager does.

## 4. `authorizeMaster()` always derives, and `clearKeys()` was already dropping the token cache

`authorizeMaster()` is new, so nothing can break on it, but the bug it had is
worth knowing about if you copied the pattern: it returned a cached token for
the scope, so the 24 words were never actually checked. It derives every time
now. `clearKeys()` drops the derived keys and every cached token, which is
what ends a session properly.

**Who this touches:** nobody yet. Listed so it is not rediscovered.

## What is new and costs nothing

Additive, so a project takes it when it wants it:

- **`Broker`** — every call to api.encedo.com as a class of its own, reachable
  as `hem.broker` or shareable between HEM instances. Check-in, the push
  events behind phone authorisation, pairing, subscribers, downloads,
  `*.ence.do` domains with `domainStatus`/`waitDomain`, provisioning, sharing a
  public key by e-mail.
- **BIP39** — `generateMnemonic`, `mnemonicToEntropy`, `entropyToMnemonic`,
  `validateMnemonic`, and `initialize({ mnemonic }, …)`. The 256-bit entropy
  **is** the master key and the words encode it; `{ legacy: true }` reproduces
  the v1 Manager's `seedHex.substr(1, 64)` for modules already in the field.
  `initialize()` still takes a password string as its first argument, so the
  old call keeps working.
- **`setUserPassword()`** — changes the everyday password without the password
  ever leaving the browser: it derives the new key and proves it with an HMAC
  of the device nonce under the shared secret.
- **`verifyLog()` and `verifyLoggerKey()`** — an audit-log file checked against
  the device's logger key, and the key checked against a nonce the device signs
  on the spot.
- **`hem.tokens`** — the scopes this client still holds, as `{ scope, exp }`,
  without handing out the JWTs.
- **External authenticators** — `listExtAuth`, `deleteExtAuth`, `hasExtAuth`,
  and `registerExtAuth` with the pairing QR payload fixed.
- **Uploads take `onProgress`**, and every request takes a `signal`.

## Checking a project against it

```bash
cd <project>
git -C <path-to-sdk-copy> pull        # or update the submodule, or re-copy the bundle
grep -rn "listKeys\|createKeyPair\|deriveKey\|checkFirmware\|checkUi" src/
```

Those five names are the whole blast radius. Everything else a project calls
behaves as it did.
