# Upgrading the SDK

## Firmware 1.3

From 2026-11-06 the SDK follows the firmware 1.3 API
(`encedo_firmware/docs/HEM_API_reference_1.3.x.md`) and nothing older:
firmware before 1.3 is retired with it. What changed for a caller, and what
to do about each. The SDK is shared: fix the project, not the SDK.

### Results that were wrong

- **`exdsaVerify`, `hmacVerify`, `mldsaVerify` resolve to `true` or `false`.**
  The device answers 200 for a wrong signature too, with `{"verified":false}`;
  the SDK used to resolve `true` for every 200, so an invalid signature passed.
  Check the value: `if (!(await hem.exdsaVerify(...))) reject()`. A non-200 still throws.
- **`verifyLog` reads format v2** (every line signed with Ed25519, per-file key
  certified by the device log key). The result is
  `{ ok, lines, headers, rotations, lost, gaps, line?, reason? }`;
  `reason` is one of `format`, `cut_front`, `no_header`, `header`, `rotate`,
  `signature` (v1's `hmac`, `sequence`, `no_key` are gone). A deleted line is a
  `gaps` entry and makes `ok` false while every other line still verifies.
- **The HKDF context of the cipher calls was never sent.** The option is now
  `hkdfCtx` (and `hkdfSalt`), 1..128 bytes each; `ctx` is gone. Data
  encrypted or wrapped with a `ctx` before was made without one: decrypt it
  without `hkdfCtx`.
- **`ecdh` / `ecdhKid` without `alg`** return the raw secret at the curve's
  length (P-384 48, P-521 66, X448 56 bytes) instead of throwing.

### Key management

```js
// before                                                    // now
listKeys(token, offset, limit)                               listKeys(token, { offset, limit, returnPubkey })
searchKeys(token, descr, offset, limit)        -> array      searchKeys(token, pattern, { match, offset, limit, type, mode, returnPubkey }) -> page
getPubKey(token, kid)                                        getKeyPublicInfo(token, kid)
createKeyPair(token, label, type, descrB64, mode)            createKeyPair(token, label, type, { descr, mode, returnPubkey })
importPublicKey(token, label, type, pub, descrB64, mode)     importPublicKey(token, label, type, pub, { descr, mode })
deriveKey(token, label, type, descrB64, kid, peerB64, mode)  deriveKey(token, label, type, kid, { pubkey, extKid, hkdfSalt, descr, mode, returnPubkey })
updateKey(token, kid, label, descrB64)                       updateKey(token, kid, label, descr)
```

- **A description is bytes**, not base64: pass a `Uint8Array`, or a string,
  which is taken as UTF-8 text. `null` / absent means none.
- **Every key comes back in one shape** (`HemKey`): `type` is the key type
  alone ('ED25519') and the device's flags are in `flags` (['ATT', 'PKEY',
  'ExDSA']); `description`, `pubkey`, `der` are bytes or null. `createKeyPair`
  and `deriveKey` return it too (with `kid`).
- **`searchKeys` returns a page** like `listKeys`: `{ list, offset, total,
  listed, deleted, invalid }`. Take `.list` where an array was used. Page on
  from `offset + listed` (a page with public keys ends after 3 PQC keys), until
  a page comes back empty. `match: 'suffix'` and `'contains'` are new.
- **`listKeys` pages on `listed`**, not on `list.length`: a record that fails
  its check takes a slot without being listed. The device gives at most 15 a page.
- **`mode` is checked against the key type** (`bad_mode`): `ED25519` + `ECDH`
  and `HPKE` (P-256/384/521, X25519, X448, ML-KEM) are allowed now; a mode on a
  type that takes none (ED448, ML-DSA, AES, HMAC) throws instead of being sent.

### System, upgrade, audit log

| before | now |
|---|---|
| `usbMode(token)` | `rebootToUsbMode(token)` — it restarts the device |
| `uploadFirmware(token, bytes, filename, opts)` | `uploadFirmware(token, bytes, { format, onProgress, signal })` — sent as `firmware.bin` / `firmware.hex` (Intel HEX detected) |
| `uploadUi(token, bytes, filename, opts)` | `uploadUi(token, bytes, { onProgress, signal })` — sent as `webroot.tar` |
| `getLoggerKey(token)` | `getLoggerKey(token, { nonce })` — pass a fresh nonce and check it with `verifyLoggerKey(answer, nonce)` |
| `listLog(token, offset)` | `listLogFiles(token, { offset, limit })` — the open file is not listed, it is `current` |
| `getLogEntry(token, id)` | `getLogFile(token, id)` — the open file is HTTP 409 (was 406) |
| `verifyLogEntry(token, id)` | `verifyLogFile(token, id)` — proves the key with a nonce first; `keyProven` |
| `authorizeRemote(scope, { expSeconds })` | `authorizeRemote(scope, { ctx, note })` — `ext/request` takes no `exp`; the phone's answer sets the token lifetime |
| `getVersion()` → `{ hwv, blv, fwv, fws, conf }` | `{ hwv, fwv, fwk, fws, fwc?, blv?, blk?, bls?, blc?, uis? }`; `{ token }` adds `sd_csd` / `sd_cid` |

`registerDomain(..., { newCertificate: false })` takes the attestation from
`GET /api/system/config/attestation` (the auth challenge carries none, so it
always failed). In Node, requests have no default timeout any more (it was
15 s, shorter than an ML-DSA signature may take); pass `timeoutMs` where one
is wanted.

### Cryptography

```js
// before                                                // now
exdsaSign(token, kid, msgString, alg, ctxB64)            exdsaSign(token, kid, data, alg, { ctx, det })   // data: bytes or text
exdsaSignBytes(token, kid, bytes, alg, ctxB64)           exdsaSign(token, kid, bytes, alg, { ctx })
exdsaVerify(token, kid, data, sig, alg)                  exdsaVerify(token, kid, data, sig, alg, { ctx })
ecdh(token, kid, peerPubKeyBase64, { alg })              ecdh(token, kid, peerBytes, { alg, hkdfSalt, hkdfCtx, hkdfLen })
ecdhKid(token, kid, extKid, { alg })                     ecdh(token, kid, extKid, { alg })                // a 32-hex KID
cipherWrap(token, kid, alg, data, opts)                  cipherWrap(token, kid, data, { alg, ... })      // alg optional, AES256
cipherUnwrap(token, kid, alg, wrapped, opts)             cipherUnwrap(token, kid, wrapped, { alg, ... })
mldsaSign(token, kid, data)                              mldsaSign(token, kid, data, { ctx, mode })
mldsaVerify(token, kid, data, sig)                       mldsaVerify(token, kid, data, sig, { ctx, mode })
```

- **A peer public key is bytes** everywhere (`pubkey` of the peer modes,
  `ecdh`): a base64 string throws `invalid_arg`. Decode it first.
- **A context is bytes or text**, encoded by the SDK (`exdsaSign` took the
  caller's base64 before).
- New: `ecdhHkdf` (several HKDF outputs from one ECDH), `det` (RFC 6979
  ECDSA), alg `ECDSA` (prehashed), ML-DSA `mode` ('HashML-DSA-SHA256/384/512',
  'ML-DSA-mu'), `CHACHA20-POLY1305`. `mlkemEncaps` also returns `alg`.
- `cipherEncrypt`'s `iv` is never null.
- New calls, no change for anyone: `xwingEncaps` / `xwingDecaps`, `hpkeSeal` /
  `hpkeOpen`, `kdf`, `otp` / `otpVerify`, `random`, `defragCheck` /
  `defragStart`, `bootstrap`.

### Authentication and system

- **A scope may be an array** of 1..8 values (`authorizePassword`,
  `authorizeMaster`, `authorizeRemote`): one token for several keys or
  operations, and X-Wing / HPKE with two keys need one. A cached token serves
  every scope it holds; `tokens` lists `scope` as the string or the array.
- `ctx` (1..64 characters, copied into the token) on all three.
- `initialize` caches the `system:config` token the device answers with.
- `getAttestation(token, { nonce })` binds `genuine` to the request;
  `unlockStorage(token, { mode: 'ro' | 'rw' })`.

### Who this touches

Fixed with the change: `encedo-manager`. To fix in the second pass:
`encedo-oidc`, `encedo-chat`, `encedo-pgp`, `encedo-meet`, `www` — see the
table in [CLAUDE.md](CLAUDE.md#downstream-compatibility-checked-2026-09-03).

---

# Upgrading to the merged SDK

Everything the Manager needed was on `manager-v2` for a week; it is on `main`
now and there are no branches. The public surface went from 52 methods to 83,
**nothing was removed**, and five things changed in a way that can break a
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

`mode` is for asymmetric keys that can do two jobs, and that means the NIST
curves and nothing else: one SECP key does ECDH and ExDSA, so it is told which.
Every other type the device supports — the 25519 and 448 curves, the symmetric
types, ML-KEM and ML-DSA — has exactly one use and takes no `mode`. The SDK now
sends the field **only when the caller passes it**, which is what the reference
client does: hem-api-tester test_10 creates all 23 supported types and sends
`mode: 'ECDH,ExDSA'` for the four SECP* curves alone.

A mode on a single-use key is allowed, and checked: the device refuses
`mode: 'ECDH'` on an `ED25519` key with a 4xx, because that key signs and
cannot agree anything. The SDK now catches that contradiction before the
request and throws `HemError` with code `bad_mode`, naming both the type and
the mode — an opaque status is no way to learn which argument was wrong. A mode
that matches the one thing the key does is passed through, pointless but
harmless, and a mode on any other type is sent as given.

**Who this touches:** every project creates `ED25519` or `CURVE25519` keys, and
those requests now carry one field fewer — the `mode: 'ExDSA'` / `mode: 'ECDH'`
the SDK used to add, which was right but redundant. No call site changes; only
the bytes on the wire, and the reference client sends the shorter form. Still,
**this has not been tried against a module since the change** — create one key
of each type against a real device before a release depends on it. A project
creating SECP* keys passes `'ECDH,ExDSA'` (or one of the two) as the last
argument.

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

## 4. `authorizeRemote()` sends the `exp` the device requires

`POST /api/auth/ext/request` takes three fields and the published reference
marks all three required: `epk`, `scope` and `exp`, "Requested lifetime of the
token". The SDK sent the first two. A device reading a missing `exp` as zero
is looking at a request that expired in 1970, which is the shape of the
timestamp complaints seen when a phone authorisation is retried.

```js
await hem.authorizeRemote('keymgmt:list');                      // now asks for 300 s
await hem.authorizeRemote('keymgmt:list', { expSeconds: 120 }); // or say
```

`exp` goes out as an absolute epoch second, `now + expSeconds`, which is what
hem-api-tester test_6 sends (`'exp' => time()+120`) and therefore what runs
against hardware.

**Who this touches:** `oidc` and `meet` call `authorizeRemote`. No call site
changes — they get a field they should always have been sending. **Worth
re-testing a phone sign-in on each**, since this is the one change that alters
a request the device was already unhappy about.

## 5. `authorizeMaster()` always derives, and `clearKeys()` was already dropping the token cache

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
- **`authorizePassword(..., { remember: false })`** uses the derived key for
  that one call instead of keeping it, so the next scope needs the password
  typed again. Tokens are cached either way. It is what a "save password for
  this session" tick, left unticked, should do.

## Checking a project against it

```bash
cd <project>
git -C <path-to-sdk-copy> pull        # or update the submodule, or re-copy the bundle
grep -rn "listKeys\|createKeyPair\|deriveKey\|checkFirmware\|checkUi\|authorizeRemote" src/
```

Those five names, plus `authorizeRemote` for a project that offers phone
sign-in, are the whole blast radius. Everything else a project calls behaves as
it did.
