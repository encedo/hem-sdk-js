/**
 * hem-sdk.js -- Encedo HEM Browser SDK
 *
 * Implements a subset of the PHP HEM SDK for browser use (signin.html).
 * Covers the operations needed for the OIDC Trusted App flow (Faza 4):
 *   - Password-based auth (eJWT via PBKDF2 + X25519 ECDH)
 *   - Remote auth via broker polling (mobile push)
 *   - Key listing
 *   - Key-operation authorization (PIN or mobile)
 *   - Ed25519 signing
 *
 * Requires: Chrome 113+ / Firefox 130+ (X25519 in Web Crypto API)
 * Dependencies: none (pure Web Crypto + fetch)
 */

// --- Constants ----------------------------------------------------------------

const PBKDF2_ITERATIONS = 600_000;

// PKCS8 DER prefix for a 32-byte X25519 private key (RFC 8410)
// SEQUENCE { version=0, AlgorithmIdentifier OID 1.3.101.110, privateKey OCTET STRING { OCTET STRING { <32 bytes> } } }
const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e,
  0x02, 0x01, 0x00,
  0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
  0x04, 0x22, 0x04, 0x20,
]);

// X25519 base point u=9 (little-endian, 32 bytes).
// X25519(seed, basePoint) = public key corresponding to seed.
const X25519_BASE_POINT = new Uint8Array(32);
X25519_BASE_POINT[0] = 9;

// Import raw 32-byte seed as an X25519 private CryptoKey via PKCS8 wrapper.
// Algorithm: "X25519" (standalone, not ECDH+namedCurve) -- as per Web Crypto reference.
async function x25519PrivKey(seedBytes) {
  const pkcs8 = new Uint8Array(X25519_PKCS8_PREFIX.length + 32);
  pkcs8.set(X25519_PKCS8_PREFIX);
  pkcs8.set(seedBytes, X25519_PKCS8_PREFIX.length);
  return crypto.subtle.importKey('pkcs8', pkcs8, 'X25519', false, ['deriveBits']);
}

// Import raw 32-byte value as an X25519 public CryptoKey.
async function x25519PubKey(rawBytes) {
  return crypto.subtle.importKey('raw', rawBytes, 'X25519', false, []);
}

// Compute X25519(privKey, pubKeyBytes) -> 32-byte Uint8Array.
// Works for both: shared-secret (remote pubkey) and public-key derivation (base point u=9).
async function x25519(privKey, pubKeyBytes) {
  const pub = await x25519PubKey(pubKeyBytes);
  const bits = await crypto.subtle.deriveBits({ name: 'X25519', public: pub }, privKey, 256);
  return new Uint8Array(bits);
}

// --- Base64 helpers -----------------------------------------------------------

function toB64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
function toB64url(bytes) {
  return toB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64(b64) {
  return Uint8Array.from(atob(b64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}

function strToBytes(s) {
  return new TextEncoder().encode(s);
}

// --- JWT helpers --------------------------------------------------------------

function jwtParse(jwt) {
  try {
    const parts = jwt.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
  } catch { return null; }
}

// --- HEM Errors ---------------------------------------------------------------

export class HemError extends Error {
  constructor(message, { code = 'unknown', status = 0, data = null } = {}) {
    super(message);
    this.name = 'HemError';
    this.code = code;
    this.status = status;
    this.data = data;
  }
}

// --- Main class ---------------------------------------------------------------

export class HEM {
  #baseUrl;
  #broker;
  #debug;
  #tokenCache = [];
  #derivedKeys = null;   // { privKey: CryptoKey (non-extractable), pubkeyB64: string }

  /**
   * @param {string} hsmUrl   Base URL of the Encedo HEM device (e.g. 'https://abc.ence.do')
   * @param {object} [opts]
   * @param {string} [opts.broker='https://api.encedo.com']  Notification broker URL
   * @param {boolean} [opts.debug=false]  Log requests to console
   */
  constructor(hsmUrl, { broker = 'https://api.encedo.com', debug = false } = {}) {
    this.#baseUrl = hsmUrl.replace(/\/+$/, '');
    this.#broker = broker.replace(/\/+$/, '');
    this.#debug = debug;
  }

  // -- Key Cache ---------------------------------------------------------------

  /**
   * Discard cached derived keys (e.g. on logout).
   * Expired JWT tokens are also purged.
   * The CryptoKey object will be garbage-collected; there is no explicit destroy
   * in Web Crypto API — non-extractable keys cannot be read back from memory by JS.
   */
  clearKeys() {
    this.#derivedKeys = null;
    this.#tokenCache = [];
  }

  // -- Token Cache -------------------------------------------------------------

  #cacheStore(scope, jwt) {
    const payload = jwtParse(jwt);
    const exp = payload?.exp ?? (Math.floor(Date.now() / 1000) + 300);
    this.#tokenCache.push({ scope, token: jwt, exp });
    this.#cachePurge();
  }

  #cacheFind(scope) {
    this.#cachePurge();
    const now = Math.floor(Date.now() / 1000);
    return this.#tokenCache.find(e => e.scope === scope && e.exp > now)?.token ?? null;
  }

  #cachePurge() {
    const now = Math.floor(Date.now() / 1000);
    this.#tokenCache = this.#tokenCache.filter(e => e.exp > now);
  }

  /** Remove all cached tokens (e.g. on logout). */
  clearCache() {
    this.#tokenCache = [];
  }

  // -- HTTP --------------------------------------------------------------------

  async #req(method, url, body = null, token = null, opts = {}) {
    const { binary = false, filename = null } = opts;

    // Binary uploads (firmware / UI images) go out as application/octet-stream
    // carrying the raw bytes; every other request is JSON.
    let headers, payload;
    if (binary) {
      headers = { 'Content-Type': 'application/octet-stream' };
      if (filename) headers['Content-Disposition'] = `attachment; filename="${filename}"`;
      payload = body;                                    // Uint8Array — sent as-is
    } else {
      headers = { 'Content-Type': 'application/json' };
      payload = body !== null ? JSON.stringify(body) : null;
    }
    if (token) headers['Authorization'] = 'Bearer ' + token;

    if (this.#debug) {
      console.debug('[HEM] ->', method, url);
      console.debug('[HEM] req headers:', JSON.stringify(headers));
      console.debug('[HEM] req body:', binary
        ? `(binary, ${payload?.length ?? 0} bytes)`
        : (payload ?? '(none)'));
    }

    // In Node.js, undici (built-in fetch) uses chunked transfer encoding by
    // default, which some embedded devices reject with HTTP 411.
    // Detect Node.js and use https.request directly to set Content-Length.
    const isNode = typeof process !== 'undefined' && process.versions?.node;

    let status, resHeaders, data;

    if (isNode && payload !== null) {
      ({ status, headers: resHeaders, data } = await this.#reqNode(method, url, headers, payload));
    } else {
      const fetchOpts = { method, headers };
      if (payload !== null) fetchOpts.body = payload;

      let res;
      try {
        res = await fetch(url, fetchOpts);
      } catch (e) {
        throw new HemError(`Network error: ${e.message}`, { code: 'network' });
      }

      status = res.status;
      resHeaders = Object.fromEntries(res.headers.entries());
      const ct = res.headers.get('content-type') ?? '';
      if (ct.includes('json')) {
        try { data = await res.json(); } catch { data = null; }
      } else {
        data = await res.text();
      }
    }

    if (this.#debug) {
      console.debug('[HEM] <- status:', status);
      console.debug('[HEM] res headers:', JSON.stringify(resHeaders));
      console.debug('[HEM] res body:', JSON.stringify(data));
    }

    if (status < 200 || status >= 300) {
      throw new HemError(
        `HEM ${method} ${url} -> HTTP ${status}`,
        { code: `http_${status}`, status, data }
      );
    }
    return data;
  }

  // Node.js-specific HTTP request using https.request (sets Content-Length explicitly)
  async #reqNode(method, url, headers, body) {
    const { default: https } = await import('node:https');
    const { default: http } = await import('node:http');
    const { URL: NodeURL } = await import('node:url');

    const parsed = new NodeURL(url);
    // body is a JSON string or a Uint8Array (binary upload) — normalise to Buffer
    const payloadBuf = typeof body === 'string' ? Buffer.from(body, 'utf8') : Buffer.from(body);
    const reqHeaders = {
      ...headers,
      'Content-Length': payloadBuf.length.toString(),
    };

    if (this.#debug) {
      console.debug('[HEM] reqNode headers sent:', JSON.stringify(reqHeaders));
    }

    return new Promise((resolve, reject) => {
      const lib = parsed.protocol === 'https:' ? https : http;
      const req = lib.request({
        method,
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        headers: reqHeaders,
        agent: false,   // fresh TLS connection per request (HSM doesn't pool)
        timeout: 15000,
      }, (res) => {
        let raw = '';
        res.setEncoding('utf8');
        res.on('data', chunk => {
          if (this.#debug) console.debug('[HEM] res chunk:', chunk);
          raw += chunk;
        });
        res.on('end', () => {
          if (this.#debug) console.debug('[HEM] res status:', res.statusCode, 'raw:', raw);
          const resHeaders = res.headers;
          let data;
          const ct = res.headers['content-type'] ?? '';
          if (ct.includes('json')) {
            try { data = JSON.parse(raw); } catch { data = raw; }
          } else {
            data = raw;
          }
          resolve({ status: res.statusCode, headers: resHeaders, data });
        });
      });
      req.on('timeout', () => {
        req.destroy();
        reject(new HemError('Request timeout', { code: 'timeout' }));
      });
      req.on('error', e => {
        if (this.#debug) console.debug('[HEM] req error:', e.message);
        reject(new HemError(`Network error: ${e.message}`, { code: 'network' }));
      });
      req.write(payloadBuf);
      req.end();
    });
  }

  // -- eJWT generation (PBKDF2 + X25519 ECDH + HMAC-SHA256) -------------------

  /**
   * PBKDF2-SHA256 -> 32-byte seed -> X25519 private CryptoKey + public key (standard base64).
   * Public key = X25519(seed, basePoint) -- same as nacl.box.keyPair.fromSecretKey(seed).publicKey.
   */
  async #deriveX25519(password, salt) {
    // PBKDF2 -> 32-byte seed
    // Convert password to bytes first so we can zero it immediately after importKey
    const passBytes = strToBytes(password);
    const passKey = await crypto.subtle.importKey(
      'raw', passBytes, 'PBKDF2', false, ['deriveBits']
    );
    passBytes.fill(0);   // zero UTF-8 bytes of password; CryptoKey holds no reference to them

    const seedBytes = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: strToBytes(salt), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      passKey, 256
    ));

    // Import seed as X25519 private key (non-extractable), then zero the raw seed
    const privKey = await x25519PrivKey(seedBytes);
    seedBytes.fill(0);   // seed no longer needed; privKey is non-extractable CryptoKey

    // Derive public key: X25519(seed, basePoint=9) -- no JWK export needed
    const pubKeyBytes = await x25519(privKey, X25519_BASE_POINT);
    const pubkeyB64 = toB64(pubKeyBytes);   // standard base64 (matches PHP base64_encode)

    return { privKey, pubkeyB64 };
  }

  /**
   * Build eJWT: base64url(header).base64url(payload).HMAC-SHA256sig
   * Header is { ecdh: 'x25519' } -- matches JS reference implementation.
   * Shared secret = X25519(seed, devicePubkey) -- same as nacl.scalarMult(seed, remotePub).
   */
  async #buildEjwt(privKey, devicePubkeyB64, payload) {
    // Header matches jwt_generate_hs256 reference: adds alg+typ to the caller-supplied fields
    const hdr = toB64url(strToBytes(JSON.stringify({ ecdh: 'x25519', alg: 'HS256', typ: 'JWT' })));
    const bdy = toB64url(strToBytes(JSON.stringify(payload)));
    const input = `${hdr}.${bdy}`;

    // Shared secret: X25519(seed, devicePubkey)
    const sharedSecret = await x25519(privKey, fromB64(devicePubkeyB64));

    // HMAC-SHA256(input, sharedSecret)
    const hmacKey = await crypto.subtle.importKey(
      'raw', sharedSecret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', hmacKey, strToBytes(input));

    return `${input}.${toB64url(new Uint8Array(sig))}`;
  }

  // -- Authorization: Password -------------------------------------------------

  /**
   * Authenticate with a local password and obtain a scoped JWT token.
   *
   * Two-step HEM flow:
   *   1. GET  /api/auth/token  -> challenge { eid, spk, jti }
   *   2. POST /api/auth/token  { auth: eJWT } -> { token: JWT }
   *
   * The resulting JWT is cached automatically.
   *
   * @param {string} password    Local password (plain text)
   * @param {string} scope       e.g. 'keymgmt:list' or 'keymgmt:use:<KID>'
   * @param {number} [expSeconds=300]  Requested token lifetime
   * @returns {Promise<string>}  JWT token
   */
  async authorizePassword(password, scope, expSeconds = 300) {
    const cached = this.#cacheFind(scope);
    if (cached) return cached;

    // Phase 1 -- get challenge (always needed for fresh jti + spk)
    const challenge = await this.#req('GET', `${this.#baseUrl}/api/auth/token`);
    // { eid: string (stable salt), spk: base64 (device X25519 pubkey), jti: string (nonce) }

    // Derive X25519 keys from password and cache them, or reuse cached keys
    if (password) {
      this.#derivedKeys = await this.#deriveX25519(password, challenge.eid);
      // Note: JS strings are immutable — the password primitive cannot be zeroed here.
      // The caller should not hold a long-lived reference to it.
    }
    if (!this.#derivedKeys) {
      throw new HemError('Password required (no cached keys)', { code: 'auth_password_required' });
    }
    const { privKey, pubkeyB64 } = this.#derivedKeys;

    // Build JWT payload
    const iat = Math.floor(Date.now() / 1000) - 5;   // -5s for clock drift
    const payload = {
      jti: challenge.jti,
      aud: challenge.spk,
      exp: iat + expSeconds,
      iat,
      iss: pubkeyB64,   // our X25519 public key as standard base64
      scope,
    };

    // Build eJWT and send
    const ejwt = await this.#buildEjwt(privKey, challenge.spk, payload);
    const resp = await this.#req('POST', `${this.#baseUrl}/api/auth/token`, { auth: ejwt });

    if (!resp.token) throw new HemError('No token in auth response', { code: 'auth_failed' });

    this.#cacheStore(scope, resp.token);
    return resp.token;
  }

  // -- Checkin (clock sync + connection test) ----------------------------------

  /**
   * Perform a 3-step checkin: tests HSM connection, tests broker, and synchronises clocks.
   * Must be called once after construction, before any other operation.
   *
   * Mirrors PHP hem_checkin():
   *   1. GET  /api/system/checkin          -> must have { check }
   *   2. POST {broker}/checkin             -> must have { checked }
   *   3. POST /api/system/checkin          -> must have { status }
   */
  async hemCheckin() {
    const step1 = await this.#req('GET', `${this.#baseUrl}/api/system/checkin`);
    if (!step1.check) throw new HemError('HSM checkin failed (no check field)', { code: 'checkin_error' });

    const step2 = await this.#req('POST', `${this.#broker}/checkin`, step1);
    if (!step2.checked) throw new HemError('Broker checkin failed (no checked field)', { code: 'broker_error' });

    const step3 = await this.#req('POST', `${this.#baseUrl}/api/system/checkin`, step2);
    if (!step3.status) throw new HemError('HSM checkin step 3 failed (no status field)', { code: 'checkin_error' });

    return true;
  }

  // -- System: Attestation -----------------------------------------------------

  /**
   * Fetch device attestation data from the HSM.
   * Any valid token is accepted -- scope has no effect on this endpoint.
   *
   * @param   {string} token  Any currently valid JWT token (e.g. useToken from authorizePassword)
   * @returns {Promise<{genuine: string, [key: string]: any}>}
   *          genuine -- device attestation blob, validated externally via api.encedo.com
   */
  async getAttestation(token) {
    return this.#req('GET', `${this.#baseUrl}/api/system/config/attestation`, null, token);
  }

  // -- Authorization: Remote (mobile push via broker) --------------------------

  /**
   * Authenticate via mobile push notification (ExtAuth / broker polling).
   * No local crypto required -- the mobile app handles the signing.
   * Requires hemCheckin() to have been called first.
   *
   * Flow:
   *   1. GET  {broker}/notify/session         -> { epk } (broker session pubkey)
   *   2. POST /api/auth/ext/request { epk, scope } -> challenge
   *   3. POST {broker}/notify/event/new       -> { eventid }
   *   4. Poll GET {broker}/notify/event/check/{eventid}  (202 = pending, 200 = done)
   *   5. POST /api/auth/ext/token { authreply } -> { token: JWT }
   *
   * @param {string} scope       e.g. 'keymgmt:list'
   * @param {object} [opts]
   * @param {number} [opts.pollInterval=2000]  Poll interval in ms
   * @param {number} [opts.pollTimeout=60000]  Max wait time in ms
   * @param {Function} [opts.onPending]        Called each poll while waiting (no args)
   * @returns {Promise<string>}  JWT token
   */
  async authorizeRemote(scope, {
    pollInterval = 2_000,
    pollTimeout = 60_000,
    onPending = null,
    signal = null,
  } = {}) {
    const cached = this.#cacheFind(scope);
    if (cached) return cached;

    // Step 1: broker session EPK
    const session = await this.#req('GET', `${this.#broker}/notify/session`);

    // Step 2: request auth from device (pass full session data + scope)
    const challenge = await this.#req('POST', `${this.#baseUrl}/api/auth/ext/request`, {
      ...session,
      scope,
    });

    // Step 3: forward challenge to broker -> eventid
    const event = await this.#req('POST', `${this.#broker}/notify/event/new`, challenge);
    const { eventid } = event;
    if (!eventid) throw new HemError('No eventid from broker', { code: 'broker_error' });

    // Step 4: poll
    const deadline = Date.now() + pollTimeout;
    let result = null;

    while (Date.now() < deadline) {
      await new Promise((r, rej) => {
        const t = setTimeout(r, pollInterval);
        if (signal) {
          if (signal.aborted) { clearTimeout(t); rej(new DOMException('Aborted', 'AbortError')); return; }
          signal.addEventListener('abort', () => { clearTimeout(t); rej(new DOMException('Aborted', 'AbortError')); }, { once: true });
        }
      });
      if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
      if (onPending) onPending();

      let res;
      try {
        res = await fetch(`${this.#broker}/notify/event/check/${eventid}`, signal ? { signal } : undefined);
      } catch (e) {
        if (e instanceof DOMException && e.name === 'AbortError') throw e;
        throw new HemError(`Broker poll network error: ${e.message}`, { code: 'network' });
      }

      if (res.status === 202) continue;   // still pending
      if (!res.ok) throw new HemError(`Broker poll HTTP ${res.status}`, { code: `http_${res.status}`, status: res.status });

      result = await res.json();
      break;
    }

    if (!result) throw new HemError('Remote auth timed out', { code: 'timeout' });

    // Step 5a: check denial
    if (result.deny) throw new HemError('Auth denied by user', { code: 'denied' });
    if (!result.authreply) throw new HemError('Missing authreply', { code: 'broker_error' });

    // Step 5b: exchange authreply for JWT
    const resp = await this.#req('POST', `${this.#baseUrl}/api/auth/ext/token`, {
      authreply: result.authreply,
    });

    if (!resp.token) throw new HemError('No token in ext/token response', { code: 'auth_failed' });

    this.#cacheStore(scope, resp.token);
    return resp.token;
  }

  // -- Initialization (TOE provisioning) ---------------------------------------

  /**
   * Initialize (provision) a factory-fresh HEM device.
   *
   * Two-step flow, mirrors PHP T-2:
   *   1. GET  /api/auth/init  -> challenge { eid, spk, jti, exp }
   *   2. POST /api/auth/init  { init: eJWT } -> result
   *
   * The eJWT carries a `cfg` block and is signed with the ADMIN key.
   * Both the admin and user X25519 key pairs are derived from their
   * passwords (PBKDF2, salt = challenge.eid); their public keys are written
   * into `cfg` as `masterkey` / `userkey` automatically.
   *
   * @param {string} adminPassword  Master/admin passphrase
   * @param {string} userPassword   Local user passphrase
   * @param {object} [cfg]          Device config: { user, email, hostname,
   *                                trusted_ts, trusted_backend, allow_keysearch,
   *                                gen_csr, origin, ... }. masterkey/userkey are
   *                                filled in automatically and override any value
   *                                passed here.
   * @returns {Promise<object>}     Initialization result from the device
   */
  async initialize(adminPassword, userPassword, cfg = {}) {
    // Phase 1 -- challenge
    const challenge = await this.#req('GET', `${this.#baseUrl}/api/auth/init`);
    // { eid: string (salt), spk: base64 (device X25519 pubkey), jti, exp }

    // Derive both key pairs (PBKDF2 salt = challenge.eid)
    const admin = await this.#deriveX25519(adminPassword, challenge.eid);
    const user  = await this.#deriveX25519(userPassword,  challenge.eid);

    const payload = {
      jti: challenge.jti,
      aud: challenge.spk,
      exp: challenge.exp,
      iat: Math.floor(Date.now() / 1000),
      iss: admin.pubkeyB64,
      cfg: {
        ...cfg,
        masterkey: admin.pubkeyB64,
        userkey: user.pubkeyB64,
      },
    };

    // eJWT signed with the ADMIN key
    const ejwt = await this.#buildEjwt(admin.privKey, challenge.spk, payload);
    return this.#req('POST', `${this.#baseUrl}/api/auth/init`, { init: ejwt });
  }

  // -- External Authenticator: Registration ------------------------------------

  /**
   * Register (pair) a new external authenticator (mobile app) with the device.
   *
   * Full flow, mirrors PHP T-5:
   *   1. GET  /api/system/config              -> { eid, user, email, hostname }
   *   2. POST {broker}/notify/session         -> { epk }
   *   3. POST /api/auth/ext/init { epk }       -> challenge { eid, request }
   *   4. POST {broker}/notify/register/init    -> { rid, link }
   *   5. onQrCode(qrText, qrPayload) — caller renders the QR for the mobile app
   *   6. Poll {broker}/notify/register/check/{rid}  (202 pending, 200 done)
   *   7. POST /api/auth/ext/validate { pid, reply } -> confirmation
   *   8. POST {broker}/notify/register/finalise/{rid} -> done
   *
   * @param {string} token  Bearer JWT with the 'system:config' scope
   * @param {object} [opts]
   * @param {Function} [opts.onQrCode]         Called with (qrText, qrPayload).
   *   qrText is the exact JSON string to encode into the QR code (scanned by the
   *   mobile authenticator); qrPayload is the same data as an object.
   * @param {number}   [opts.pollInterval=5000]  Poll interval in ms
   * @param {number}   [opts.pollTimeout=60000]  Max wait time in ms
   * @param {Function} [opts.onPending]        Called each poll while waiting
   * @param {AbortSignal} [opts.signal]        Cancels the polling loop
   * @returns {Promise<object>}  Finalisation result from the broker
   */
  async registerExtAuth(token, {
    onQrCode = null,
    pollInterval = 5_000,
    pollTimeout = 60_000,
    onPending = null,
    signal = null,
  } = {}) {
    // Step 1 -- device config (need eid + metadata for the QR)
    const config = await this.#req('GET', `${this.#baseUrl}/api/system/config`, null, token);
    if (!config.eid) throw new HemError('No eid in device config', { code: 'ext_register_error' });

    // Step 2 -- broker session EPK
    const session = await this.#req('POST', `${this.#broker}/notify/session`, { eid: config.eid });
    const { epk } = session;
    if (!epk) throw new HemError('No epk from broker', { code: 'broker_error' });

    // Step 3 -- device ext-auth challenge
    const challenge = await this.#req('POST', `${this.#baseUrl}/api/auth/ext/init`, { epk }, token);

    // Step 4 -- broker registration session -> rid + QR link
    const reg = await this.#req('POST', `${this.#broker}/notify/register/init`, {
      epk,
      eid: challenge.eid,
      request: challenge.request,
    });
    const { rid, link } = reg;
    if (!rid) throw new HemError('No rid from broker', { code: 'broker_error' });

    // Step 5 -- build the QR payload and hand it to the caller to render.
    // The payload MUST be byte-identical to the PHP tester: the mobile
    // authenticator app scans this exact JSON. Key order (link, hash, user,
    // email, hostname) matches PHP json_encode() of the source array.
    // The SDK only produces the data; rendering the QR image is out of scope.
    const qrPayload = {
      link,
      hash: 'not_implemented_yet',
      user: config.user,
      email: config.email,
      hostname: config.hostname,
    };
    if (onQrCode) onQrCode(JSON.stringify(qrPayload), qrPayload);

    // Step 6 -- poll until the mobile app scans the QR
    const deadline = Date.now() + pollTimeout;
    let reply = null;

    while (Date.now() < deadline) {
      await new Promise((r, rej) => {
        const t = setTimeout(r, pollInterval);
        if (signal) {
          if (signal.aborted) { clearTimeout(t); rej(new DOMException('Aborted', 'AbortError')); return; }
          signal.addEventListener('abort', () => { clearTimeout(t); rej(new DOMException('Aborted', 'AbortError')); }, { once: true });
        }
      });
      if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
      if (onPending) onPending();

      let res;
      try {
        res = await fetch(`${this.#broker}/notify/register/check/${rid}`, signal ? { signal } : undefined);
      } catch (e) {
        if (e instanceof DOMException && e.name === 'AbortError') throw e;
        throw new HemError(`Broker poll network error: ${e.message}`, { code: 'network' });
      }

      if (res.status === 202) continue;   // still pending
      if (!res.ok) throw new HemError(`Broker poll HTTP ${res.status}`, { code: `http_${res.status}`, status: res.status });

      reply = await res.json();
      break;
    }

    if (!reply) throw new HemError('Ext authenticator registration timed out', { code: 'timeout' });
    if (!reply.pid || !reply.reply) throw new HemError('Missing pid/reply from broker', { code: 'broker_error' });

    // Step 7 -- validate the pairing on the device
    const confirmation = await this.#req('POST', `${this.#baseUrl}/api/auth/ext/validate`,
      { pid: reply.pid, reply: reply.reply }, token);

    // Step 8 -- finalise the pairing on the broker
    return this.#req('POST', `${this.#broker}/notify/register/finalise/${rid}`, confirmation);
  }

  /**
   * Obtain MAC data that authenticates this device to the notification broker.
   * The returned MAC is used to query the broker for the list of external
   * authenticators currently paired with the device.
   *
   * Fetches the device `eid`, opens a broker session for an ephemeral key, then
   * calls POST /api/auth/ext/mac — same broker handshake as registerExtAuth().
   *
   * Required scope: 'system:config' (or 'auth:ext:pair')
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<{nonce: string, mac: string, eid: string}>}
   */
  async getExtAuthMac(token) {
    const config = await this.#req('GET', `${this.#baseUrl}/api/system/config`, null, token);
    if (!config.eid) throw new HemError('No eid in device config', { code: 'ext_register_error' });

    const session = await this.#req('POST', `${this.#broker}/notify/session`, { eid: config.eid });
    if (!session.epk) throw new HemError('No epk from broker', { code: 'broker_error' });

    return this.#req('POST', `${this.#baseUrl}/api/auth/ext/mac`, { epk: session.epk }, token);
  }

  // -- Key Management ----------------------------------------------------------

  /**
   * Generate a new key in the HSM.
   *
   * Required scope: 'keymgmt:gen'
   *
   * @param {string} token   Bearer JWT
   * @param {string} label   Human-readable key label
   * @param {string} type    Key type, e.g. 'ED25519'
   * @param {string} descr   Base64-encoded description (128-byte field)
   * @returns {Promise<{kid: string}>}
   */
  async createKeyPair(token, label, type, descr) { // label max 32 chars, descr base64-encoded (max 64 chars)
    const MODE = { ED25519: 'ExDSA', CURVE25519: 'ECDH' };
    const mode = MODE[type] ?? type;
    return this.#req('POST', `${this.#baseUrl}/api/keymgmt/create`, { mode, type, label, descr }, token);
  }

  /**
   * Import an external public key into the HSM repository.
   *
   * Required scope: 'keymgmt:imp'
   *
   * @param {string}      token       Bearer JWT (must have keymgmt:imp scope)
   * @param {string}      label       Key label (max 32 chars)
   * @param {string}      type        Key type, e.g. 'ED25519', 'CURVE25519', 'SECP384R1'
   * @param {Uint8Array}  pubKeyBytes Public key bytes: raw 32/56/57 B for 25519/448 types,
   *                                  compressed SEC1 point (0x02/0x03||X) for SECP* types
   * @param {string|null} [descr]     Optional base64-encoded description (128-byte field)
   * @param {string|null} [mode]      Optional usage constraint for NIST ECC keys:
   *                                  'ECDH', 'ExDSA' or 'ECDH,ExDSA'
   * @returns {Promise<{kid: string}>}
   */
  async importPublicKey(token, label, type, pubKeyBytes, descr = null, mode = null) {
    const body = { type, label, pubkey: toB64(pubKeyBytes) };
    if (descr !== null) body.descr = descr;
    if (mode !== null) body.mode = mode;
    return this.#req('POST', `${this.#baseUrl}/api/keymgmt/import`, body, token);
  }

  /**
   * Derive a new key in the HSM from an existing ECDH key and a peer public key.
   *
   * Required scope: 'keymgmt:gen'
   *
   * @param {string} token        Bearer JWT
   * @param {string} label        Human-readable key label (max 32 chars)
   * @param {string} type         Key type of the derived key, e.g. 'ED25519'
   * @param {string} descr        Base64-encoded description (128-byte field)
   * @param {string} kid          KID of the existing ECDH key to derive from
   * @param {string} peerPubKeyBase64  Peer's raw public key (standard base64)
   * @returns {Promise<{kid: string}>}
   */
  async deriveKey(token, label, type, descr, kid, peerPubKeyBase64) {
    const MODE = { ED25519: 'ExDSA', CURVE25519: 'ECDH' };
    const mode = MODE[type] ?? type;
    return this.#req('POST', `${this.#baseUrl}/api/keymgmt/derive`,
      { mode, type, label, descr, kid, pubkey: peerPubKeyBase64 }, token);
  }

  /**
   * Update a key's metadata (label and description) in the HSM repository.
   *
   * Required scope: 'keymgmt:upd'
   *
   * @param {string} token  Bearer JWT
   * @param {string} kid    Key ID to update
   * @param {string} label  New label (max 32 chars)
   * @param {string} descr  New base64-encoded description
   * @returns {Promise<object>}
   */
  async updateKey(token, kid, label, descr) {
    return this.#req('POST', `${this.#baseUrl}/api/keymgmt/update`,
      { kid, label, descr }, token);
  }

  /**
   * Get public key metadata (type, pubkey) for a given KID.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string} token   Bearer JWT
   * @param {string} kid     Key ID (hex string)
   * @returns {Promise<{type: string, pubkey: string, updated: number}>}
   */
  async getPubKey(token, kid) {
    return this.#req('GET', `${this.#baseUrl}/api/keymgmt/get/${kid}`, null, token);
  }

  /**
   * List keys in the HSM repository.
   * Returns an array of { kid, label, type, description } where description
   * is a Uint8Array (raw 128-byte field) or null.
   *
   * Required scope: 'keymgmt:list'
   *
   * @param {string} token   Bearer JWT
   * @param {number} [offset=0]
   * @param {number} [limit=50]
   * @returns {Promise<Array<{kid:string, label:string, type:string, description:Uint8Array|null}>>}
   */
  async listKeys(token, offset = 0, limit = 50) {
    const data = await this.#req(
      'GET', `${this.#baseUrl}/api/keymgmt/list/${offset}/${limit}`,
      null, token
    );
    return (data.list ?? []).map(entry => ({
      kid: entry.kid,
      label: entry.label ?? '',
      type: entry.type ?? '',
      description: entry.descr ? fromB64(entry.descr) : null,
    }));
  }

  // -- Cryptography ------------------------------------------------------------

  /**
   * Sign a message with an EdDSA or ECDSA key stored in the HSM.
   * Mirrors PHP api_exdsa_sign().
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string} token           Bearer JWT
   * @param {string} kid             Key ID (32-char hex)
   * @param {string} msg             Message to sign (string -- encoded to UTF-8 bytes then base64)
   * @param {string} [alg='Ed25519'] Signature algorithm (Ed25519, Ed25519ph, Ed25519ctx, Ed448, ...)
   * @param {string|null} [ctx=null] Optional context (base64-encoded) for Ed25519ctx / Ed448
   * @returns {Promise<Uint8Array>}  Raw signature bytes (convert to base64url before use in JWT)
   */
  async exdsaSign(token, kid, msg, alg = 'Ed25519', ctx = null) {
    const body = { kid, alg, msg: toB64(strToBytes(msg)) };
    if (ctx !== null) body.ctx = ctx;
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/exdsa/sign`, body, token);
    if (!ret.sign) throw new HemError('No sign in exdsa/sign response', { code: 'sign_error' });
    // Convert standard base64 response to base64url for JWT use
    return fromB64(ret.sign);
  }

  /**
   * Sign arbitrary binary data with an EdDSA key stored in the HSM.
   * Like exdsaSign but accepts Uint8Array directly (no UTF-8 conversion).
   * Use this for cryptographic protocols (OpenPGP, TLS, etc.) that sign raw bytes.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token  Bearer JWT
   * @param {string}     kid    Key ID (32-char hex)
   * @param {Uint8Array} data   Raw bytes to sign
   * @param {string}     [alg='Ed25519']
   * @param {string|null} [ctx=null]
   * @returns {Promise<Uint8Array>}  Raw 64-byte Ed25519 signature (R || S)
   */
  async exdsaSignBytes(token, kid, data, alg = 'Ed25519', ctx = null) {
    const body = { kid, alg, msg: toB64(data) };
    if (ctx !== null) body.ctx = ctx;
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/exdsa/sign`, body, token);
    if (!ret.sign) throw new HemError('No sign in exdsa/sign response', { code: 'sign_error' });
    return fromB64(ret.sign);
  }

  /**
   * Verify an EdDSA/ECDSA signature on the HSM using an imported public key.
   * Returns true if valid; throws HemError (code 'verify_failed') if signature is invalid (HTTP 406).
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token  Bearer JWT
   * @param {string}     kid    Key ID (32-char hex) of the public key in HSM
   * @param {Uint8Array} data   Raw bytes that were signed
   * @param {Uint8Array} sig    Raw signature bytes (64 bytes for Ed25519)
   * @param {string}     [alg='Ed25519']
   * @returns {Promise<true>}   Resolves to true on success, throws on invalid signature
   */
  async exdsaVerify(token, kid, data, sig, alg = 'Ed25519') {
    await this.#req('POST', `${this.#baseUrl}/api/crypto/exdsa/verify`,
      { kid, alg, msg: toB64(data), sign: toB64(sig) }, token);
    return true;
  }

  /**
   * Perform a Curve25519 ECDH operation on the HSM.
   * The private key never leaves the device — only the 32-byte shared secret is returned.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string} token             Bearer JWT
   * @param {string} kid               Key ID (32-char hex) of the X25519 private key in HSM
   * @param {string} peerPubKeyBase64  Peer's raw 32-byte X25519 public key in standard base64
   * @returns {Promise<Uint8Array>}    Raw 32-byte shared secret
   */
  async ecdh(token, kid, peerPubKeyBase64) {
    const ret = await this.#req(
      'POST', `${this.#baseUrl}/api/crypto/ecdh`,
      { kid, pubkey: peerPubKeyBase64 },
      token
    );
    if (!ret.ecdh) throw new HemError('No ecdh in response', { code: 'ecdh_error' });
    const result = fromB64(ret.ecdh);
    if (result.length !== 32) throw new HemError(`ECDH result length invalid: expected 32, got ${result.length}`, { code: 'ecdh_error' });
    return result;
  }

  /**
   * Compute an HMAC over arbitrary data using a symmetric key in the HSM.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token  Bearer JWT
   * @param {string}     kid    Key ID (32-char hex) of the HMAC key
   * @param {Uint8Array} data   Raw bytes to authenticate
   * @param {string|null} [alg=null]  Hash algorithm, e.g. 'SHA2-256' (device default if null)
   * @returns {Promise<Uint8Array>}  Raw MAC bytes
   */
  async hmacHash(token, kid, data, alg = null) {
    const body = { kid, msg: toB64(data) };
    if (alg !== null) body.alg = alg;
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/hmac/hash`, body, token);
    if (!ret.mac) throw new HemError('No mac in hmac/hash response', { code: 'hmac_error' });
    return fromB64(ret.mac);
  }

  /**
   * Verify an HMAC on the HSM. Resolves true on success; throws HemError if the
   * MAC is invalid.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token  Bearer JWT
   * @param {string}     kid    Key ID (32-char hex) of the HMAC key
   * @param {Uint8Array} data   Raw bytes that were authenticated
   * @param {Uint8Array} mac    Raw MAC bytes to verify
   * @param {string|null} [alg=null]  Hash algorithm (must match hmacHash)
   * @returns {Promise<true>}
   */
  async hmacVerify(token, kid, data, mac, alg = null) {
    const body = { kid, msg: toB64(data), mac: toB64(mac) };
    if (alg !== null) body.alg = alg;
    await this.#req('POST', `${this.#baseUrl}/api/crypto/hmac/verify`, body, token);
    return true;
  }

  /**
   * Encrypt data with a symmetric key stored in the HSM.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token  Bearer JWT
   * @param {string}     kid    Key ID (32-char hex) of the symmetric key
   * @param {Uint8Array} data   Plaintext bytes (for ECB the length must be a
   *                            multiple of the 16-byte AES block size)
   * @param {string}     alg    Cipher + mode, e.g. 'AES256-CBC', 'AES256-GCM', 'AES256-ECB'
   * @returns {Promise<Uint8Array>}  Ciphertext bytes
   */
  async cipherEncrypt(token, kid, data, alg) {
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/cipher/encrypt`,
      { kid, msg: toB64(data), alg }, token);
    if (!ret.ciphertext) throw new HemError('No ciphertext in encrypt response', { code: 'cipher_error' });
    return fromB64(ret.ciphertext);
  }

  /**
   * Decrypt data with a symmetric key stored in the HSM.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token       Bearer JWT
   * @param {string}     kid         Key ID (32-char hex) of the symmetric key
   * @param {Uint8Array} ciphertext  Ciphertext bytes
   * @param {string}     alg         Cipher + mode (must match cipherEncrypt)
   * @returns {Promise<Uint8Array>}  Plaintext bytes
   */
  async cipherDecrypt(token, kid, ciphertext, alg) {
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/cipher/decrypt`,
      { kid, msg: toB64(ciphertext), alg }, token);
    if (!ret.plaintext) throw new HemError('No plaintext in decrypt response', { code: 'cipher_error' });
    return fromB64(ret.plaintext);
  }

  /**
   * Key-wrap: encrypt a key (KEK) with a wrapping key stored in the HSM.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token  Bearer JWT
   * @param {string}     kid    Key ID (32-char hex) of the wrapping key
   * @param {string}     alg    Wrapping algorithm (key type, e.g. 'AES256')
   * @param {Uint8Array} data   Key material to wrap
   * @returns {Promise<Uint8Array>}  Wrapped key bytes
   */
  async cipherWrap(token, kid, alg, data) {
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/cipher/wrap`,
      { kid, alg, msg: toB64(data) }, token);
    if (!ret.wrapped) throw new HemError('No wrapped in wrap response', { code: 'cipher_error' });
    return fromB64(ret.wrapped);
  }

  /**
   * Key-unwrap: decrypt a wrapped key with a wrapping key stored in the HSM.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token    Bearer JWT
   * @param {string}     kid      Key ID (32-char hex) of the wrapping key
   * @param {string}     alg      Wrapping algorithm (must match cipherWrap)
   * @param {Uint8Array} wrapped  Wrapped key bytes
   * @returns {Promise<Uint8Array>}  Unwrapped key material
   */
  async cipherUnwrap(token, kid, alg, wrapped) {
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/cipher/unwrap`,
      { kid, alg, msg: toB64(wrapped) }, token);
    if (!ret.unwrapped) throw new HemError('No unwrapped in unwrap response', { code: 'cipher_error' });
    return fromB64(ret.unwrapped);
  }

  /**
   * ML-KEM (post-quantum) encapsulation against an ML-KEM key in the HSM.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string} token  Bearer JWT
   * @param {string} kid    Key ID (32-char hex) of the ML-KEM key
   * @returns {Promise<{ss: Uint8Array, ct: Uint8Array}>}
   *          ss — shared secret, ct — ciphertext to send to the peer
   */
  async mlkemEncaps(token, kid) {
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/pqc/mlkem/encaps`,
      { kid }, token);
    if (!ret.ss || !ret.ct) throw new HemError('Missing ss/ct in mlkem/encaps response', { code: 'pqc_error' });
    return { ss: fromB64(ret.ss), ct: fromB64(ret.ct) };
  }

  /**
   * ML-KEM (post-quantum) decapsulation with an ML-KEM key in the HSM.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token  Bearer JWT
   * @param {string}     kid    Key ID (32-char hex) of the ML-KEM key
   * @param {Uint8Array} ct     Ciphertext from the peer's encapsulation
   * @returns {Promise<Uint8Array>}  Shared secret
   */
  async mlkemDecaps(token, kid, ct) {
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/pqc/mlkem/decaps`,
      { kid, ct: toB64(ct) }, token);
    if (!ret.ss) throw new HemError('No ss in mlkem/decaps response', { code: 'pqc_error' });
    return fromB64(ret.ss);
  }

  /**
   * ML-DSA (post-quantum) signature with an ML-DSA key in the HSM.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token  Bearer JWT
   * @param {string}     kid    Key ID (32-char hex) of the ML-DSA key
   * @param {Uint8Array} data   Raw bytes to sign
   * @returns {Promise<Uint8Array>}  Signature bytes
   */
  async mldsaSign(token, kid, data) {
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/pqc/mldsa/sign`,
      { kid, msg: toB64(data) }, token);
    if (!ret.sign) throw new HemError('No sign in mldsa/sign response', { code: 'pqc_error' });
    return fromB64(ret.sign);
  }

  /**
   * ML-DSA (post-quantum) signature verification on the HSM. Resolves true on
   * success; throws HemError if the signature is invalid.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token  Bearer JWT
   * @param {string}     kid    Key ID (32-char hex) of the ML-DSA key
   * @param {Uint8Array} data   Raw bytes that were signed
   * @param {Uint8Array} sign   Signature bytes
   * @returns {Promise<true>}
   */
  async mldsaVerify(token, kid, data, sign) {
    await this.#req('POST', `${this.#baseUrl}/api/crypto/pqc/mldsa/verify`,
      { kid, msg: toB64(data), sign: toB64(sign) }, token);
    return true;
  }

  /**
   * Search keys in the HSM repository by pattern.
   * Returns the same shape as listKeys.
   *
   * Required scope: 'keymgmt:list'
   *
   * @param {string} token    Bearer JWT
   * @param {string} descr    Search pattern matched against description (regex)
   * @param {number} [offset=0]
   * @param {number} [limit=50]
   * @returns {Promise<Array<{kid:string, label:string, type:string, description:Uint8Array|null}>>}
   */
  async searchKeys(token, descr, _offset = 0, _limit = 50) { // TODO: pass _offset/_limit in path once HSM API is fixed
    const descrB64 = '^' + toB64(new TextEncoder().encode(descr));
    const data = await this.#req(
      // TODO: restore /${offset}/${limit} path params once HSM API is fixed
      'POST', `${this.#baseUrl}/api/keymgmt/search`,
      { descr: descrB64 }, token
    );
    return (data.list ?? []).map(entry => ({
      kid: entry.kid,
      label: entry.label ?? '',
      type: entry.type ?? '',
      description: entry.descr ? fromB64(entry.descr) : null,
    }));
  }

  /**
   * Delete a key from the HSM.
   *
   * Required scope: 'keymgmt:del'
   *
   * @param {string} token  Bearer JWT (must have keymgmt:del scope)
   * @param {string} kid    Key ID to delete (32 hex chars)
   * @returns {Promise<void>}
   */
  async deleteKey(token, kid) {
    await this.#req('DELETE', `${this.#baseUrl}/api/keymgmt/delete/${kid}`, null, token);
  }

  // -- System Management -------------------------------------------------------

  /**
   * Get device version information (hardware, bootloader, firmware).
   * No authentication required.
   *
   * @returns {Promise<{hwv:string, blv:string, fwv:string, fws:string, conf:string}>}
   */
  async getVersion() {
    return this.#req('GET', `${this.#baseUrl}/api/system/version`);
  }

  /**
   * Get current device status (init state, failure-lockdown state, hostname, ...).
   * No authentication required.
   *
   * @returns {Promise<object>}
   */
  async getStatus() {
    return this.#req('GET', `${this.#baseUrl}/api/system/status`);
  }

  /**
   * Read the device configuration.
   *
   * Required scope: 'system:config'
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<object>}  Config object (eid, user, email, hostname, ...)
   */
  async getConfig(token) {
    return this.#req('GET', `${this.#baseUrl}/api/system/config`, null, token);
  }

  /**
   * Update the device configuration. Only known fields are applied; unknown
   * fields are ignored and reported back via `updated: false`.
   *
   * Required scope: 'system:config'
   *
   * @param {string} token  Bearer JWT
   * @param {object} cfg    Partial config, e.g. { user }, { email }, { hostname }
   * @returns {Promise<{updated: boolean}>}
   */
  async setConfig(token, cfg) {
    return this.#req('POST', `${this.#baseUrl}/api/system/config`, cfg, token);
  }

  /**
   * Reboot the device. Any valid token is accepted.
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<object>}
   */
  async reboot(token) {
    return this.#req('GET', `${this.#baseUrl}/api/system/reboot`, null, token);
  }

  /**
   * Shut the device down. Any valid token is accepted.
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<object>}
   */
  async shutdown(token) {
    return this.#req('GET', `${this.#baseUrl}/api/system/shutdown`, null, token);
  }

  /**
   * Run the device self-test suite.
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<object>}
   */
  async selftest(token) {
    return this.#req('GET', `${this.#baseUrl}/api/system/selftest`, null, token);
  }

  // -- Firmware / UI Upgrade ---------------------------------------------------

  /**
   * Query the device USB upgrade mode.
   *
   * Required scope: 'system:upgrade'
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<object>}
   */
  async usbMode(token) {
    return this.#req('GET', `${this.#baseUrl}/api/system/upgrade/usbmode`, null, token);
  }

  /**
   * Upload a firmware image to the device.
   *
   * The SDK takes the raw byte stream — obtaining it is the caller's job.
   * Two common cases:
   *
   *   // a) From a local file (Node.js):
   *   import { readFile } from 'node:fs/promises';
   *   const bytes = new Uint8Array(await readFile('./encedo_fw.hex'));
   *   await hem.uploadFirmware(token, bytes);
   *
   *   // b) From a URL or a file picker (browser):
   *   const bytes = new Uint8Array(await (await fetch(fwUrl)).arrayBuffer());
   *   // or from <input type="file">:
   *   // const bytes = new Uint8Array(await fileInput.files[0].arrayBuffer());
   *   await hem.uploadFirmware(token, bytes);
   *
   * Required scope: 'system:upgrade'
   *
   * @param {string}     token       Bearer JWT
   * @param {Uint8Array} bytes       Raw firmware image bytes
   * @param {string}     [filename='firmware.bin']  Upload filename
   * @returns {Promise<object>}
   */
  async uploadFirmware(token, bytes, filename = 'firmware.bin') {
    return this.#req('POST', `${this.#baseUrl}/api/system/upgrade/upload_fw`,
      bytes, token, { binary: true, filename });
  }

  /**
   * Verify the firmware image previously uploaded with uploadFirmware().
   *
   * Required scope: 'system:upgrade'
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<object>}
   */
  async checkFirmware(token) {
    return this.#req('GET', `${this.#baseUrl}/api/system/upgrade/check_fw`, null, token);
  }

  /**
   * Install the verified firmware image. The device reboots afterwards.
   *
   * Required scope: 'system:upgrade'
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<object>}
   */
  async installFirmware(token) {
    return this.#req('GET', `${this.#baseUrl}/api/system/upgrade/install_fw`, null, token);
  }

  /**
   * Upload a UI bundle image to the device.
   * See uploadFirmware() for how to obtain the byte stream from a local file
   * or a URL — the SDK takes the raw bytes either way.
   *
   * Required scope: 'system:upgrade'
   *
   * @param {string}     token       Bearer JWT
   * @param {Uint8Array} bytes       Raw UI bundle bytes
   * @param {string}     [filename='ui.bin']  Upload filename
   * @returns {Promise<object>}
   */
  async uploadUi(token, bytes, filename = 'ui.bin') {
    return this.#req('POST', `${this.#baseUrl}/api/system/upgrade/upload_ui`,
      bytes, token, { binary: true, filename });
  }

  /**
   * Verify the UI bundle previously uploaded with uploadUi().
   *
   * Required scope: 'system:upgrade'
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<object>}
   */
  async checkUi(token) {
    return this.#req('GET', `${this.#baseUrl}/api/system/upgrade/check_ui`, null, token);
  }

  /**
   * Install the verified UI bundle.
   *
   * Required scope: 'system:upgrade'
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<object>}
   */
  async installUi(token) {
    return this.#req('GET', `${this.#baseUrl}/api/system/upgrade/install_ui`, null, token);
  }

  // -- Storage -----------------------------------------------------------------

  /**
   * Lock an embedded storage disk. The disk (disk0 / disk1) and access mode are
   * selected by the token's scope — e.g. a token scoped to 'storage:disk0:rw'
   * locks disk0.
   *
   * Required scope: 'storage:disk<N>:rw'
   *
   * @param {string} token  Bearer JWT scoped to a specific disk
   * @returns {Promise<object>}
   */
  async lockStorage(token) {
    return this.#req('GET', `${this.#baseUrl}/api/storage/lock`, null, token);
  }

  /**
   * Unlock an embedded storage disk. The disk is selected by the token's scope.
   *
   * Required scope: 'storage:disk<N>:rw'
   *
   * @param {string} token  Bearer JWT scoped to a specific disk
   * @returns {Promise<object>}
   */
  async unlockStorage(token) {
    return this.#req('GET', `${this.#baseUrl}/api/storage/unlock`, null, token);
  }

  // -- Logger / Audit Log ------------------------------------------------------

  /**
   * Get the Ed25519 public key the device uses to sign audit-log entries.
   * Use it to verify log integrity (rotating HMAC chain + entry signatures).
   *
   * Required scope: 'logger:get'
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<object>}
   */
  async getLoggerKey(token) {
    return this.#req('GET', `${this.#baseUrl}/api/logger/key`, null, token);
  }

  /**
   * List audit-log entries starting at an offset.
   *
   * Required scope: 'logger:get'
   *
   * @param {string} token   Bearer JWT
   * @param {number} [offset=0]
   * @returns {Promise<object>}
   */
  async listLog(token, offset = 0) {
    return this.#req('GET', `${this.#baseUrl}/api/logger/list/${offset}`, null, token);
  }

  /**
   * Fetch a single audit-log entry by id.
   *
   * Required scope: 'logger:get'
   *
   * @param {string} token        Bearer JWT
   * @param {string|number} id    Log entry id
   * @returns {Promise<object>}
   */
  async getLogEntry(token, id) {
    return this.#req('GET', `${this.#baseUrl}/api/logger/${id}`, null, token);
  }

}
