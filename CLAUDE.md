# CLAUDE.md — hem-sdk-js

Context and conventions for AI agents (Claude Code) working on this repo.

## What this is

`hem-sdk-js` is a dependency-free JavaScript client for the Encedo **HEM**
hardware security device. It runs unchanged in the browser (Web Crypto +
`fetch`) and in Node.js. Private key material never leaves the device.

This repo is the **single source of truth** for the SDK. The same files are
copied (manually, whole-folder) into other projects: `encedo-meet`,
`encedo-pgp`. `encedo-oidc-boundle` carries an older divergent copy — it is
updated separately. **Always make SDK changes here**, never in a downstream copy.

## Layout

| File | Role | Edit? |
|------|------|-------|
| `hem-sdk.js` | ES module source — the only hand-written code | ✅ edit here |
| `hem-sdk.browser.js` + `.js.map` | Rollup output | ❌ generated — never edit |
| `hem-sdk.browser.d.ts` | TypeScript declarations | ✅ keep in sync by hand |
| `rollup.browser.config.js` | Browser build config | rarely |
| `README.md` | High-level overview | keep current |
| `EXAMPLES.md` | Commented usage per operation | keep current |

## Architecture

- Two classes, `HEM` (the device) and `Broker` (the backend at
  api.encedo.com), plus `HemError`, plus the exported helpers `verifyLog` and
  `jwtParse`. **Every call to api.encedo.com lives in `Broker`, one method per
  endpoint.** `HEM` holds one (`hem.broker`, built from `opts.broker`, a URL or
  an instance) and composes broker calls with device calls in the multi-step
  flows (`hemCheckin`, `authorizeRemote`, `registerExtAuth`, `listExtAuth`,
  `provision`, `registerDomain`). A device behind an air gap never needs the
  broker: keep it that way — no device-only method may call it.
- Private fields/methods use `#` (true private). Public methods are thin
  wrappers over the transport.
- `httpRequest(method, url, opts)` — the single HTTP entry point, module-level,
  shared by both classes; `HEM.#req` and `Broker.#req` are one-line wrappers
  that add the base URL, the debug flag and a log tag.
  - Default: JSON request (`application/json`, body `JSON.stringify`d).
  - `opts = { binary: true, filename }` → `application/octet-stream` upload of
    a raw `Uint8Array` (used by firmware/UI upgrade).
  - `opts = { timeoutMs, signal }` → the request is **cancelled**, not merely
    stopped being awaited. This matters more than it looks: the alternative a
    caller reaches for is racing the promise against a timer, which leaves the
    HTTP request running — a page polling an absent device that way accumulates
    one open connection per attempt, and they all land at once when the device
    appears. `AbortSignal.timeout` becomes `code: 'timeout'` and an external
    abort `code: 'aborted'`, so a caller can tell "cancelled" from "unreachable".
    Honoured on **both** transports (`fetch` and `#reqNode`), or the same call
    would be cancellable in a browser and not in Node.
  - Only `getVersion` / `getStatus` expose it so far — they are what a login
    screen probes with. Any other method needs one more parameter, no new
    machinery.
  - `opts = { onProgress }` → the request goes through `XMLHttpRequest`
    (browser only), the one transport with upload progress events. Used by
    `uploadFirmware` / `uploadUi`.
  - `opts = { bytes: true }` → the body comes back as a `Uint8Array`
    (`Broker.download`). `opts = { withStatus: true }` → `{ status, headers,
    data }`, so a poll can tell 202 "pending" from 200 "done".
  - Cancellation is uniform: an aborted request, an aborted poll and an aborted
    wait all reject with `HemError` code `aborted` (not a DOMException).
  - In Node.js, requests with a body go through `#reqNode` (`https.request`
    with an explicit `Content-Length`) — embedded devices reject `undici`'s
    chunked encoding with HTTP 411. `#reqNode` accepts a string or `Uint8Array`.
  - Non-2xx responses throw `HemError`.
- Auth crypto helpers (module-level): `x25519*`, `toB64`/`toB64url`/`fromB64`,
  `strToBytes`, `jwtParse`. eJWT building is `#buildEjwt`; password→X25519 key
  derivation is `#deriveX25519` (PBKDF2-SHA256, 600 000 iterations).
- Caches: `#tokenCache` (scoped JWTs, auto-purged on expiry), `#derivedKeys`
  (derived X25519 key pair). `clearCache()` / `clearKeys()` drop them.

## One line, no branches

The SDK is shared, so it has a single line of history: `main`. Work goes there
and goes out to every project that uses it. A change that breaks a consumer is
allowed — see the table below for who calls what — but it is written down in
[MIGRATION.md](MIGRATION.md) with what a project has to do about it, in the
same commit that makes it.

## Downstream compatibility (checked 2026-09-03)

The SDK is copied into live products, so the public surface only grows.
What each consumer relies on today, from reading their code:

| Consumer | Uses | Load-bearing behaviour |
|---|---|---|
| `encedo-oidc-boundle` (older 510-line copy) | `hemCheckin`, `authorizePassword`, `authorizeRemote` (with `signal` in signin.js), `searchKeys`, `exdsaSign`, `getPubKey`, `getAttestation`, `createKeyPair` | `err instanceof HemError && err.code === 'http_401'` |
| `chat/encedo-chat` (1453-line copy) | `hemCheckin`, `authorizePassword`, `searchKeys`, `getPubKey`, `createKeyPair`, `ecdh`, `updateKey`, `deleteKey`, `getVersion({timeoutMs})`, `getStatus({timeoutMs})` | `e.code === 'timeout' \|\| e.code === 'aborted'` |
| `encedo-pgp` (current copy) | `hemCheckin`, `authorizePassword`, `searchKeys`, `createKeyPair`, `getPubKey`, `importPublicKey`, `exdsaSignBytes`, `exdsaVerify`, `ecdh` | binary in / binary out |
| `encedo-meet` (713-line copy under `src/vendor`) | `authorizePassword`, `hemCheckin`, `authorizeRemote` | — |
| `www` kit pages | `hemCheckin`, `authorizePassword`, `createKeyPair` | — |
| `encedo-manager` v2 | everything above plus `Broker`, `listExtAuth`, `deleteExtAuth`, `hasExtAuth`, `provision`, `registerDomain`, `verifyLog`, upload `onProgress` | `hemCheckin()` resolving to the step-3 object |

The table is a map of blast radius, not a freeze. Breaking changes are allowed
(decided 2026-09-03) — the rule is that a change which breaks a row is made
together with the fix in that project, in the same sitting, and the table is
updated. What the SDK must not do is break a consumer silently.

As it stands nobody reads `hemCheckin()`'s value, nobody catches `AbortError`
by name, and everybody constructs `new HEM(url, {debug?})`, so the current
changes reach no consumer: `hemCheckin` returning an object is still truthy,
cancellation as `HemError` (`aborted`) is only ever caught by code, and the
`initialize` signature change touches a method no consumer calls.

`listKeys()` returns `{ list, total }` instead of a bare array (2026-09-04), and
its entries carry `created` / `updated` like `searchKeys()` does. The device has
always answered `{ list, total, listed }`; dropping `total` meant a UI could not
say how many keys there are, or page without guessing. Nothing outside this repo
calls `listKeys` (grep over every sibling consumer: they all use `searchKeys`),
so the break costs nobody a fix.

`createKeyPair()` and `deriveKey()` take `mode` as a last argument and send the
field only when the caller passes one (2026-09-04, corrected 2026-09-11). It
says what an asymmetric key may be used for, and only a key that can do two
jobs needs telling — the NIST curves, where the same key does ECDH and ExDSA.
The old `MODE[type] ?? type` sent `mode: 'AES256'` for an AES key, and the
first pass at this kept sending `ExDSA` / `ECDH` for the 25519 curves out of
habit. Neither is what the device asks for: hem-api-tester test_10 creates all
23 supported types and sends `mode` for SECP256R1, SECP384R1, SECP521R1 and
SECP256K1 only. So a consumer creating ED25519 or CURVE25519 keys now sends one
field fewer than it did. The device has always accepted both, but this has not
been tried against a module since the change — do that before relying on it.

## The master secret (BIP39)

256 bits from `crypto.getRandomValues` ARE the master X25519 private key, and
the same 32 bytes are what the 24 words encode: `generateMnemonic` ->
`initialize({ mnemonic }, userPassword, cfg)` -> `authorizeMaster(mnemonic,
scope)`. Recovery is `mnemonicToEntropy`, which validates the checksum and
names the offending word, so a wrong word never reaches the device. The English
wordlist is embedded (2048 words, SHA-256 of the newline-joined list
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`); tests pin
the official Trezor vectors.

The v1 Manager derived the master key differently: the BIP39 *seed*
(PBKDF2-HMAC-SHA512, 2048 rounds, salt "mnemonic") and then the 32 bytes
starting one hex character in (`seedHex.substr(1, 64)`), so every key byte
straddles two seed bytes. It loses no entropy, but no standard tool reproduces
it and v1 never checked the checksum. `legacyMasterSeed` reproduces it byte for
byte (cross-checked against jsbip39 + sjcl + tweetnacl), reachable only as
`authorizeMaster(..., { legacy: true })`, for devices already in the field.
Never derive a new master key that way.

`usbMode` is not used by the Manager (USB ACM uploads have their own webshell);
the method stays for other callers.

## API spec source

Two sources, and they agree:

- **<https://docs.encedo.com/hem-api>** — the published reference: every
  endpoint, its request body and its fields. Start here for what a field means
  and whether it is required.
- **`hem-api-tester`** (sibling repo, typically at `../../hem-api-tester`) —
  the reference implementation, run against real devices. Read the matching
  `test_*.php` and `libs/lib.php` for what a correct request actually looks
  like, and for the shapes the published reference leaves out.

Where the docs say a field is optional, the PHP shows when it is sent in
practice: `mode`, for instance, is documented as "Key operation mode (for NIST
ECC only)" and test_10 sends it for the four SECP* curves and for none of the
other 19 types.

`/api/diag/*` endpoints (memory dump, fault injection) are **intentionally not
implemented** — they are hardware-destructive Common Criteria test hooks.

## Conventions when adding a method

1. Public method = thin wrapper over `#req`. No business logic beyond shaping
   the request body and unwrapping the response field.
2. Binary in / binary out: data parameters and return values are `Uint8Array`;
   base64 encoding/decoding happens inside the method (`toB64` / `fromB64`).
   Match `exdsaSignBytes` / `ecdh` as the style reference.
3. `*Verify` methods resolve to `true` and rely on `#req` to throw on failure.
4. Document the **required scope** in the JSDoc.
5. Multi-step / polling flows (broker interaction): model them on
   `authorizeRemote` / `registerExtAuth` — support `pollInterval`,
   `pollTimeout`, `onPending`, `signal`. The loop itself is `Broker.#poll`;
   add a `waitX()` on `Broker` and compose it from `HEM`. A flow that leaves
   something pending on the broker when cancelled must withdraw it (see
   `authorizeRemote` deleting its event).
6. A new backend endpoint is a new `Broker` method, never a URL inside `HEM`.
7. Keep it dependency-free and DOM-free. Visualization (e.g. rendering a QR
   code) stays out of the SDK — hand data to the caller via a callback.
8. Cover it in `test/sdk.test.mjs`: extend the mock with the endpoint and add
   a `test()` that drives the public method.

## After any change to `hem-sdk.js`

1. `node --check hem-sdk.js` — syntax gate; then `node --test test/sdk.test.mjs`.
2. Rebuild the browser bundle: `npx rollup -c rollup.browser.config.js`.
3. Update `hem-sdk.browser.d.ts` with the new/changed signatures.
4. Update `README.md` (group table) and `EXAMPLES.md` if the public API changed.
5. Commit `hem-sdk.js`, the rebuilt bundle, `.js.map`, `.d.ts` and the docs
   together — the bundle must never lag the source.

## Gotchas

- Browser X25519 needs Chrome 113+ / Firefox 130+.
- `mode` on a create, derive or import is **only for the NIST curves**, where
  one key does both ECDH and ExDSA and has to be told which. The other 19 types
  the device supports take no `mode` at all, and the SDK sends one only when a
  caller passes it — as hem-api-tester test_10 does. It may be given on a
  single-use key, but it is checked: `ECDH` on an ED25519 key is a 4xx from the
  device, and `checkMode()` throws `bad_mode` for it before the request. `searchKeys` needs the
  pattern base64-encoded with a leading `^`; that mismatch silently breaks
  against a current device.
- Storage lock/unlock has no disk argument: the disk is selected by the token
  scope (`storage:disk<N>:rw`). The Manager v1 called `/unlock/ro` and
  `/unlock/rw`; those sub-paths are legacy (hem-api-tester test_12 uses the
  bare path).
- The QR payload of `registerExtAuth` carries `hash = base64(SHA-256(request))`
  over the device's ext-auth challenge; the phone checks it. Key order in the
  JSON matters.
- `domainTaken` reads the broker's 200 as "taken" and 404 as "free" (the v1
  Manager treated any failure as free); confirm against the backend before
  relying on it in a UI.
