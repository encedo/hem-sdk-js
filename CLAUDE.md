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

- One class, `HEM`, plus a `HemError` error class. Both `export`ed.
- Private fields/methods use `#` (true private). Public methods are thin
  wrappers over the private transport.
- `#req(method, url, body, token, opts)` — the single HTTP entry point.
  - Default: JSON request (`application/json`, body `JSON.stringify`d).
  - `opts = { binary: true, filename }` → `application/octet-stream` upload of
    a raw `Uint8Array` (used by firmware/UI upgrade).
  - In Node.js, requests with a body go through `#reqNode` (`https.request`
    with an explicit `Content-Length`) — embedded devices reject `undici`'s
    chunked encoding with HTTP 411. `#reqNode` accepts a string or `Uint8Array`.
  - Non-2xx responses throw `HemError`.
- Auth crypto helpers (module-level): `x25519*`, `toB64`/`toB64url`/`fromB64`,
  `strToBytes`, `jwtParse`. eJWT building is `#buildEjwt`; password→X25519 key
  derivation is `#deriveX25519` (PBKDF2-SHA256, 600 000 iterations).
- Caches: `#tokenCache` (scoped JWTs, auto-purged on expiry), `#derivedKeys`
  (derived X25519 key pair). `clearCache()` / `clearKeys()` drop them.

## API spec source

The authoritative description of HEM endpoints, request bodies and response
fields is the PHP test suite **`hem-api-tester`** (sibling repo, typically at
`../../hem-api-tester`). When adding or fixing an endpoint, read the matching
`test_*.php` and `libs/lib.php` — the PHP is the reference implementation.

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
   `pollTimeout`, `onPending`, `signal`.
6. Keep it dependency-free and DOM-free. Visualization (e.g. rendering a QR
   code) stays out of the SDK — hand data to the caller via a callback.

## After any change to `hem-sdk.js`

1. `node --check hem-sdk.js` — syntax gate.
2. Rebuild the browser bundle: `npx rollup -c rollup.browser.config.js`.
3. Update `hem-sdk.browser.d.ts` with the new/changed signatures.
4. Update `README.md` (group table) and `EXAMPLES.md` if the public API changed.
5. Commit `hem-sdk.js`, the rebuilt bundle, `.js.map`, `.d.ts` and the docs
   together — the bundle must never lag the source.

## Gotchas

- Browser X25519 needs Chrome 113+ / Firefox 130+.
- The `createKeyPair` / `deriveKey` request body needs a `mode` field
  (`ED25519`→`ExDSA`, `CURVE25519`→`ECDH`); `searchKeys` needs the pattern
  base64-encoded with a leading `^`. These mismatches silently break against a
  current device — see the methods for the exact shaping.
- Storage lock/unlock has no disk argument: the disk is selected by the token
  scope (`storage:disk<N>:rw`).
