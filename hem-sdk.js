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

  async #req(method, url, body = null, token = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = 'Bearer ' + token;

    const opts = { method, headers };
    if (body !== null) opts.body = JSON.stringify(body);

    if (this.#debug) console.debug('[HEM] ->', method, url, body ?? '');

    let res;
    try {
      res = await fetch(url, opts);
    } catch (e) {
      throw new HemError(`Network error: ${e.message}`, { code: 'network' });
    }

    let data;
    const ct = res.headers.get('content-type') ?? '';
    if (ct.includes('json')) {
      try { data = await res.json(); } catch { data = null; }
    } else {
      data = await res.text();
    }

    if (this.#debug) console.debug('[HEM] <-', res.status, data);

    if (!res.ok) {
      throw new HemError(
        `HEM ${method} ${url} -> HTTP ${res.status}`,
        { code: `http_${res.status}`, status: res.status, data }
      );
    }
    return data;
  }

  // -- eJWT generation (PBKDF2 + X25519 ECDH + HMAC-SHA256) -------------------

  /**
   * PBKDF2-SHA256 -> 32-byte seed -> X25519 private CryptoKey + public key (standard base64).
   * Public key = X25519(seed, basePoint) -- same as nacl.box.keyPair.fromSecretKey(seed).publicKey.
   */
  async #deriveX25519(password, salt) {
    // PBKDF2 -> 32-byte seed
    const passKey = await crypto.subtle.importKey(
      'raw', strToBytes(password), 'PBKDF2', false, ['deriveBits']
    );
    const seedBytes = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: strToBytes(salt), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      passKey, 256
    ));

    // Import seed as X25519 private key via PKCS8 wrapper
    const privKey = await x25519PrivKey(seedBytes);

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

    // Phase 1 -- get challenge
    const challenge = await this.#req('GET', `${this.#baseUrl}/api/auth/token`);
    // { eid: string (salt), spk: base64 (device X25519 pubkey), jti: string }

    // Derive X25519 key from password (PBKDF2, salt = challenge.eid)
    const { privKey, pubkeyB64 } = await this.#deriveX25519(password, challenge.eid);

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
    return this.#req('POST', `${this.#baseUrl}/api/keymgmt/create`, { label, type, descr }, token);
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
    const data = await this.#req(
      // TODO: restore /${offset}/${limit} path params once HSM API is fixed
      'POST', `${this.#baseUrl}/api/keymgmt/search`,
      { descr }, token
    );
    return (data.list ?? []).map(entry => ({
      kid: entry.kid,
      label: entry.label ?? '',
      type: entry.type ?? '',
      description: entry.descr ? fromB64(entry.descr) : null,
    }));
  }

}
