/**
 * hem-sdk.js -- Encedo HEM SDK (browser + Node.js)
 *
 * A dependency-free client for the Encedo HEM hardware security device.
 *
 *   HEM     -- the device: authentication (password, mobile push), provisioning,
 *              pairing, key management, /api/crypto/*, system, upgrade, storage,
 *              audit log. Everything a device behind an air gap can do works
 *              without the broker.
 *   Broker  -- the Encedo backend (api.encedo.com): check-in, push events,
 *              pairing sessions, paired-authenticator lists, downloads, *.ence.do
 *              domains and TLS, provisioning, key sharing. One method per
 *              endpoint; HEM composes them with device calls.
 *   verifyLog, jwtParse -- pure helpers.
 *
 * Requires: Chrome 113+ / Firefox 130+ (X25519 in Web Crypto API), Node.js 18+
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

/** Decode a JWT payload without verifying it (scope, exp, sub...). Returns null on malformed input. */
function jwtParse(jwt) {
  try {
    const parts = jwt.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
  } catch { return null; }
}

// --- HEM Errors ---------------------------------------------------------------

class HemError extends Error {
  constructor(message, { code = 'unknown', status = 0, data = null } = {}) {
    super(message);
    this.name = 'HemError';
    this.code = code;
    this.status = status;
    this.data = data;
  }
}

// --- HTTP transport -----------------------------------------------------------
//
// One entry point for every request the SDK makes, to the device and to the
// broker alike. JSON in, JSON out by default. `binary` sends a raw Uint8Array as
// application/octet-stream (firmware / UI upgrade); `bytes` returns the response
// body as a Uint8Array (downloads). `signal` / `timeoutMs` cancel the request
// itself, not merely the wait for it. `onProgress(loaded, total)` reports upload
// progress -- browser only, through XMLHttpRequest, which fetch cannot do.
// `withStatus` returns { status, headers, data } instead of `data`, so a caller
// can tell a 202 "still pending" from a 200 "done" without a second request.
// Non-2xx responses throw HemError.

async function httpRequest(method, url, {
  body = null, token = null, binary = false, filename = null, bytes = false,
  signal = null, timeoutMs = 0, onProgress = null, withStatus = false,
  debug = false, tag = 'HEM',
} = {}) {
  let headers, payload;
  if (binary) {
    headers = { 'Content-Type': 'application/octet-stream' };
    if (filename) headers['Content-Disposition'] = `attachment; filename="${filename}"`;
    payload = body;                                    // Uint8Array -- sent as-is
  } else {
    headers = { 'Content-Type': 'application/json' };
    payload = body !== null ? JSON.stringify(body) : null;
  }
  if (token) headers['Authorization'] = 'Bearer ' + token;

  if (debug) {
    console.debug(`[${tag}] ->`, method, url);
    console.debug(`[${tag}] req headers:`, JSON.stringify(headers));
    console.debug(`[${tag}] req body:`, binary
      ? `(binary, ${payload?.length ?? 0} bytes)`
      : (payload ?? '(none)'));
  }

  // In Node.js, undici (built-in fetch) uses chunked transfer encoding by
  // default, which some embedded devices reject with HTTP 411.
  // Detect Node.js and use https.request directly to set Content-Length.
  const isNode = typeof process !== 'undefined' && process.versions?.node;

  let status, resHeaders, data;

  if (isNode && payload !== null) {
    ({ status, headers: resHeaders, data } = await requestNode(method, url, headers, payload, { signal, timeoutMs, debug, tag }));
  } else if (onProgress && typeof XMLHttpRequest !== 'undefined') {
    ({ status, headers: resHeaders, data } = await requestXhr(method, url, headers, payload, { signal, timeoutMs, onProgress, bytes }));
  } else {
    const fetchOpts = { method, headers };
    if (payload !== null) fetchOpts.body = payload;
    const abort = abortSignalFor(signal, timeoutMs);
    if (abort) fetchOpts.signal = abort;

    let res;
    try {
      res = await fetch(url, fetchOpts);
    } catch (e) {
      // A cancelled request is not an unreachable device, and a caller that
      // cannot tell them apart will report the wrong thing to a user. Without
      // this they all arrive as `network`.
      if (e?.name === 'TimeoutError') throw new HemError(`Request timeout after ${timeoutMs} ms`, { code: 'timeout' });
      if (e?.name === 'AbortError') throw new HemError('Request aborted', { code: 'aborted' });
      throw new HemError(`Network error: ${e.message}`, { code: 'network' });
    }

    status = res.status;
    resHeaders = Object.fromEntries(res.headers.entries());
    const ct = res.headers.get('content-type') ?? '';
    if (bytes && res.ok) {
      data = new Uint8Array(await res.arrayBuffer());
    } else if (ct.includes('json')) {
      try { data = await res.json(); } catch { data = null; }
    } else {
      data = await res.text();
    }
  }

  if (debug) {
    console.debug(`[${tag}] <- status:`, status);
    console.debug(`[${tag}] res headers:`, JSON.stringify(resHeaders));
    console.debug(`[${tag}] res body:`, bytes && data instanceof Uint8Array ? `(binary, ${data.length} bytes)` : JSON.stringify(data));
  }

  if (status < 200 || status >= 300) {
    throw new HemError(
      `${tag} ${method} ${url} -> HTTP ${status}`,
      { code: `http_${status}`, status, data }
    );
  }
  return withStatus ? { status, headers: resHeaders, data } : data;
}

/**
 * The signal a request should run under: the caller's, a deadline, or both.
 *
 * `timeoutMs` exists because the alternative callers reach for is racing the
 * promise against a timer -- which stops WAITING for the request without
 * stopping the request. A page that polls an absent device that way
 * accumulates one open connection per attempt, and they all complete at once
 * when the device appears.
 */
function abortSignalFor(signal, timeoutMs) {
  if (!timeoutMs) return signal ?? null;
  const deadline = AbortSignal.timeout(timeoutMs);
  if (!signal) return deadline;
  return typeof AbortSignal.any === 'function' ? AbortSignal.any([signal, deadline]) : signal;
}

// Browser upload with progress. fetch() has no upload progress events, so a
// firmware image going to the device over a slow link would sit behind a
// spinner for minutes; XMLHttpRequest reports every chunk.
function requestXhr(method, url, headers, payload, { signal = null, timeoutMs = 0, onProgress = null, bytes = false } = {}) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(method, url, true);
    for (const [k, v] of Object.entries(headers)) xhr.setRequestHeader(k, v);
    if (timeoutMs) xhr.timeout = timeoutMs;
    if (bytes) xhr.responseType = 'arraybuffer';
    if (onProgress) xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded, e.total); };
    xhr.onload = () => {
      const resHeaders = {};
      for (const line of xhr.getAllResponseHeaders().trim().split(/[\r\n]+/)) {
        const i = line.indexOf(':');
        if (i > 0) resHeaders[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
      }
      let data;
      if (bytes) {
        data = new Uint8Array(xhr.response);
      } else {
        data = xhr.responseText;
        if ((resHeaders['content-type'] ?? '').includes('json')) {
          try { data = JSON.parse(data); } catch { data = null; }
        }
      }
      resolve({ status: xhr.status, headers: resHeaders, data });
    };
    xhr.onerror = () => reject(new HemError('Network error', { code: 'network' }));
    xhr.ontimeout = () => reject(new HemError(`Request timeout after ${timeoutMs} ms`, { code: 'timeout' }));
    xhr.onabort = () => reject(new HemError('Request aborted', { code: 'aborted' }));
    if (signal) {
      if (signal.aborted) { reject(new HemError('Request aborted', { code: 'aborted' })); return; }
      signal.addEventListener('abort', () => xhr.abort(), { once: true });
    }
    xhr.send(payload);
  });
}

// Node.js-specific HTTP request using https.request (sets Content-Length explicitly)
async function requestNode(method, url, headers, body, { signal = null, timeoutMs = 0, debug = false, tag = 'HEM' } = {}) {
  const { default: https } = await import('node:https');
  const { default: http } = await import('node:http');
  const { URL: NodeURL } = await import('node:url');

  const parsed = new NodeURL(url);
  // body is a JSON string or a Uint8Array (binary upload) -- normalise to Buffer
  const payloadBuf = typeof body === 'string' ? Buffer.from(body, 'utf8') : Buffer.from(body);
  const reqHeaders = {
    ...headers,
    'Content-Length': payloadBuf.length.toString(),
  };

  if (debug) {
    console.debug(`[${tag}] reqNode headers sent:`, JSON.stringify(reqHeaders));
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
      timeout: timeoutMs || 15000,
    }, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', chunk => {
        if (debug) console.debug(`[${tag}] res chunk:`, chunk);
        raw += chunk;
      });
      res.on('end', () => {
        if (debug) console.debug(`[${tag}] res status:`, res.statusCode, 'raw:', raw);
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
      if (debug) console.debug(`[${tag}] req error:`, e.message);
      reject(new HemError(`Network error: ${e.message}`, { code: 'network' }));
    });
    // The caller's signal has to reach the socket here as well, or the same
    // call is cancellable in a browser and not in Node.
    if (signal) {
      const onAbort = () => { req.destroy(); reject(new HemError('Request aborted', { code: 'aborted' })); };
      if (signal.aborted) { onAbort(); return; }
      signal.addEventListener('abort', onAbort, { once: true });
      req.on('close', () => signal.removeEventListener('abort', onAbort));
    }
    req.write(payloadBuf);
    req.end();
  });
}

// Wait, unless the caller cancels first. Cancelling rejects with the same
// `aborted` HemError a cancelled request produces, so one catch handles both.
function sleep(ms, signal = null) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new HemError('Request aborted', { code: 'aborted' })); return; }
    const onAbort = () => { clearTimeout(t); reject(new HemError('Request aborted', { code: 'aborted' })); };
    const t = setTimeout(() => { signal?.removeEventListener('abort', onAbort); resolve(); }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** A 32-byte seed -> X25519 key pair: non-extractable private key + base64 public key. */
async function keysFromSeed(seed) {
  const privKey = await x25519PrivKey(seed);
  return { privKey, pubkeyB64: toB64(await x25519(privKey, X25519_BASE_POINT)) };
}

// --- BIP39: the master secret -------------------------------------------------
//
// The master secret of a HEM is 256 bits of entropy from the system CSPRNG.
// Those 32 bytes ARE the master X25519 private key, and the same 32 bytes are
// what the 24 words encode. So the words on a Proof of Personalization are the
// key: any BIP39 implementation decodes them back to the entropy, the checksum
// catches a mistyped word, and nothing else has to be kept.
//
// (The v1 Manager instead ran the words through the BIP39 seed function and
// took a 32-byte window one hex character into the 512-bit result. It loses no
// entropy, but no standard tool reproduces it, and recovery never checked the
// checksum. `authorizeMaster` can still derive that way for a device
// personalised by v1 -- see its `legacy` option.)

const BIP39_ENGLISH = (
  'abandon ability able about above absent absorb abstract absurd abuse access accident account ' +
  'accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict ' +
  'address adjust admit adult advance advice aerobic affair afford afraid again age agent agree ' +
  'ahead aim air airport aisle alarm album alcohol alert alien all alley allow almost alone alpha ' +
  'already also alter always amateur amazing among amount amused analyst anchor ancient anger angle ' +
  'angry animal ankle announce annual another answer antenna antique anxiety any apart apology ' +
  'appear apple approve april arch arctic area arena argue arm armed armor army around arrange ' +
  'arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume asthma ' +
  'athlete atom attack attend attitude attract auction audit august aunt author auto autumn average ' +
  'avocado avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance ' +
  'balcony ball bamboo banana banner bar barely bargain barrel base basic basket battle beach bean ' +
  'beauty because become beef before begin behave behind believe below belt bench benefit best ' +
  'betray better between beyond bicycle bid bike bind biology bird birth bitter black blade blame ' +
  'blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb ' +
  'bone bonus book boost border boring borrow boss bottom bounce box boy bracket brain brand brass ' +
  'brave bread breeze brick bridge brief bright bring brisk broccoli broken bronze broom brother ' +
  'brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst ' +
  'bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp ' +
  'can canal cancel candy cannon canoe canvas canyon capable capital captain car carbon card cargo ' +
  'carpet carry cart case cash casino castle casual cat catalog catch category cattle caught cause ' +
  'caution cave ceiling celery cement census century cereal certain chair chalk champion change ' +
  'chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child chimney ' +
  'choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap ' +
  'clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth ' +
  'cloud clown club clump cluster clutch coach coast coconut code coffee coil coin collect color ' +
  'column combine come comfort comic common company concert conduct confirm congress connect ' +
  'consider control convince cook cool copper copy coral core corn correct cost cotton couch ' +
  'country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy ' +
  'cream credit creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise ' +
  'crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion ' +
  'custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris ' +
  'decade december decide decline decorate decrease deer defense define defy degree delay deliver ' +
  'demand demise denial dentist deny depart depend deposit depth deputy derive describe desert ' +
  'design desk despair destroy detail detect develop device devote diagram dial diamond diary dice ' +
  'diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease ' +
  'dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll ' +
  'dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream ' +
  'dress drift drill drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf ' +
  'dynamic eager eagle early earn earth easily east easy echo ecology economy edge edit educate ' +
  'effort egg eight either elbow elder electric elegant element elephant elevator elite else embark ' +
  'embody embrace emerge emotion employ empower empty enable enact end endless endorse enemy energy ' +
  'enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry ' +
  'envelope episode equal equip era erase erode erosion error erupt escape essay essence estate ' +
  'eternal ethics evidence evil evoke evolve exact example excess exchange excite exclude excuse ' +
  'execute exercise exhaust exhibit exile exist exit exotic expand expect expire explain expose ' +
  'express extend extra eye eyebrow fabric face faculty fade faint faith fall false fame family ' +
  'famous fan fancy fantasy farm fashion fat fatal father fatigue fault favorite feature february ' +
  'federal fee feed feel female fence festival fetch fever few fiber fiction field figure file film ' +
  'filter final find fine finger finish fire firm first fiscal fish fit fitness fix flag flame ' +
  'flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog foil ' +
  'fold follow food foot force forest forget fork fortune forum forward fossil foster found fox ' +
  'fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel fun funny ' +
  'furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment gas ' +
  'gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle ' +
  'ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue ' +
  'goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape ' +
  'grass gravity great green grid grief grit grocery group grow grunt guard guess guide guilt ' +
  'guitar gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk ' +
  'hazard head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint ' +
  'hip hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse ' +
  'hospital host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt ' +
  'husband hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense ' +
  'immune impact impose improve impulse inch include income increase index indicate indoor industry ' +
  'infant inflict inform inhale inherit initial inject injury inmate inner innocent input inquiry ' +
  'insane insect inside inspire install intact interest into invest invite involve iron island ' +
  'isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey ' +
  'joy judge juice jump jungle junior junk just kangaroo keen keep ketchup key kick kid kidney kind ' +
  'kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab label labor ladder lady lake ' +
  'lamp language laptop large later latin laugh laundry lava law lawn lawsuit layer lazy leader ' +
  'leaf learn leave lecture left leg legal legend leisure lemon lend length lens leopard lesson ' +
  'letter level liar liberty library license life lift light like limb limit link lion liquid list ' +
  'little live lizard load loan lobster local lock logic lonely long loop lottery loud lounge love ' +
  'loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet maid mail main ' +
  'major make mammal man manage mandate mango mansion manual maple marble march margin marine ' +
  'market marriage mask mass master match material math matrix matter maximum maze meadow mean ' +
  'measure meat mechanic medal media melody melt member memory mention menu mercy merge merit merry ' +
  'mesh message metal method middle midnight milk million mimic mind minimum minor minute miracle ' +
  'mirror misery miss mistake mix mixed mixture mobile model modify mom moment monitor monkey ' +
  'monster month moon moral more morning mosquito mother motion motor mountain mouse move movie ' +
  'much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth naive ' +
  'name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve nest ' +
  'net network neutral never news next nice night noble noise nominee noodle normal north nose ' +
  'notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure ' +
  'observe obtain obvious occur ocean october odor off offer office often oil okay old olive ' +
  'olympic omit once one onion online only open opera opinion oppose option orange orbit orchard ' +
  'order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven ' +
  'over own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther ' +
  'paper parade parent park parrot party pass patch path patient patrol pattern pause pave payment ' +
  'peace peanut pear peasant pelican pen penalty pencil people pepper perfect permit person pet ' +
  'phone photo phrase physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe ' +
  'pistol pitch pizza place planet plastic plate play please pledge pluck plug plunge poem poet ' +
  'point polar pole police pond pony pool popular portion position possible post potato pottery ' +
  'poverty powder power practice praise predict prefer prepare present pretty prevent price pride ' +
  'primary print priority prison private prize problem process produce profit program project ' +
  'promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin ' +
  'punch pupil puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter ' +
  'question quick quit quiz quote rabbit raccoon race rack radar radio rail rain raise rally ramp ' +
  'ranch random range rapid rare rate rather raven raw razor ready real reason rebel rebuild recall ' +
  'receive recipe record recycle reduce reflect reform refuse region regret regular reject relax ' +
  'release relief rely remain remember remind remove render renew rent reopen repair repeat replace ' +
  'report require rescue resemble resist resource response result retire retreat return reunion ' +
  'reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid ring riot ripple ' +
  'risk ritual rival river road roast robot robust rocket romance roof rookie room rose rotate ' +
  'rough round route royal rubber rude rug rule run runway rural sad saddle sadness safe sail salad ' +
  'salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say scale scan ' +
  'scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea ' +
  'search season seat second secret section security seed seek segment select sell seminar senior ' +
  'sense sentence series service session settle setup seven shadow shaft shallow share shed shell ' +
  'sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug ' +
  'shuffle shy sibling sick side siege sight sign silent silk silly silver similar simple since ' +
  'sing siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep ' +
  'slender slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack ' +
  'snake snap sniff snow soap soccer social sock soda soft solar soldier solid solution solve ' +
  'someone song soon sorry sort soul sound soup source south space spare spatial spawn speak ' +
  'special speed spell spend sphere spice spider spike spin spirit split spoil sponsor spoon sport ' +
  'spot spray spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp ' +
  'stand start state stay steak steel stem step stereo stick still sting stock stomach stone stool ' +
  'story stove strategy street strike strong struggle student stuff stumble style subject submit ' +
  'subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply ' +
  'supreme sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm ' +
  'swear sweet swift swim swing switch sword symbol symptom syrup system table tackle tag tail ' +
  'talent talk tank tape target task taste tattoo taxi teach team tell ten tenant tennis tent term ' +
  'test text thank that theme then theory there they thing this thought three thrive throw thumb ' +
  'thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast tobacco today ' +
  'toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top topic ' +
  'topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic ' +
  'tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim ' +
  'trip trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel ' +
  'turkey turn turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware ' +
  'uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown unlock until ' +
  'unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful useless ' +
  'usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle ' +
  'velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious ' +
  'victory video view village vintage violin virtual virus visa visit visual vital vivid vocal ' +
  'voice void volcano volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior ' +
  'wash wasp waste water wave way wealth weapon wear weasel weather web wedding weekend weird ' +
  'welcome west wet whale what wheat wheel when where whip whisper wide width wife wild will win ' +
  'window wine wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool ' +
  'word work world worry worth wrap wreck wrestle wrist write wrong yard year yellow you young ' +
  'youth zebra zero zone zoo'
).split(' ');

const BIP39_INDEX = new Map(BIP39_ENGLISH.map((w, i) => [w, i]));

/** Normalise as BIP39 requires: NFKD, lower case, single spaces. */
function normaliseMnemonic(mnemonic) {
  return String(mnemonic).normalize('NFKD').toLowerCase().trim().split(/\s+/).join(' ');
}

/**
 * A fresh master secret: `strengthBits` of entropy from the CSPRNG, as words.
 *
 * @param {number} [strengthBits=256]  128-256, a multiple of 32 (256 -> 24 words)
 * @returns {Promise<string>}  The mnemonic. Show it, print it, pass it to initialize().
 */
async function generateMnemonic(strengthBits = 256) {
  if (strengthBits % 32 || strengthBits < 128 || strengthBits > 256) {
    throw new HemError(`Strength must be 128-256 bits and a multiple of 32, got ${strengthBits}`, { code: 'mnemonic_invalid' });
  }
  return entropyToMnemonic(crypto.getRandomValues(new Uint8Array(strengthBits / 8)));
}

/**
 * Entropy -> words. The last word carries a SHA-256 checksum of the entropy.
 *
 * @param {Uint8Array} entropy  16-32 bytes, length a multiple of 4
 * @returns {Promise<string>}
 */
async function entropyToMnemonic(entropy) {
  if (!(entropy instanceof Uint8Array) || entropy.length % 4 || entropy.length < 16 || entropy.length > 32) {
    throw new HemError('Entropy must be 16-32 bytes and a multiple of 4', { code: 'mnemonic_invalid' });
  }
  const checksum = (await sha256(entropy))[0] >> (8 - entropy.length / 4);
  let bits = '';
  for (const b of entropy) bits += b.toString(2).padStart(8, '0');
  bits += checksum.toString(2).padStart(entropy.length / 4, '0');

  const words = [];
  for (let i = 0; i < bits.length / 11; i++) words.push(BIP39_ENGLISH[parseInt(bits.slice(i * 11, i * 11 + 11), 2)]);
  return words.join(' ');
}

/**
 * Words -> entropy, checking the checksum. The error names the word that is not
 * in the list, or says the checksum failed, so a caller can tell a person what
 * to look at rather than "wrong passphrase".
 *
 * @param {string} mnemonic
 * @returns {Promise<Uint8Array>}  The entropy -- for a master secret, the private key itself
 */
async function mnemonicToEntropy(mnemonic) {
  const words = normaliseMnemonic(mnemonic).split(' ').filter(Boolean);
  if (words.length < 12 || words.length > 24 || words.length % 3) {
    throw new HemError(`A mnemonic is 12 to 24 words, in multiples of three; got ${words.length}`, { code: 'mnemonic_invalid', data: { words: words.length } });
  }
  let bits = '';
  for (const [i, w] of words.entries()) {
    const idx = BIP39_INDEX.get(w);
    if (idx === undefined) {
      throw new HemError(`Word ${i + 1} is not a BIP39 word: "${w}"`, { code: 'mnemonic_invalid', data: { word: i + 1, value: w } });
    }
    bits += idx.toString(2).padStart(11, '0');
  }
  const entropyBits = (words.length * 11 * 32) / 33;
  const entropy = new Uint8Array(entropyBits / 8);
  for (let i = 0; i < entropy.length; i++) entropy[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);

  const expected = (await sha256(entropy))[0] >> (8 - entropy.length / 4);
  if (parseInt(bits.slice(entropyBits), 2) !== expected) {
    throw new HemError('The mnemonic checksum does not match: a word is wrong or out of order', { code: 'mnemonic_checksum' });
  }
  return entropy;
}

/** Whether the words are a well-formed mnemonic with a matching checksum. */
async function validateMnemonic(mnemonic) {
  try { await mnemonicToEntropy(mnemonic); return true; } catch { return false; }
}

/**
 * The v1 Manager's master-key derivation, for a device personalised by it:
 * the BIP39 seed (PBKDF2-HMAC-SHA512, 2048 rounds, salt "mnemonic"), then the
 * 32 bytes starting one hex character in. Kept only so an existing device can
 * still be opened; never derive a NEW master key this way.
 */
async function legacyMasterSeed(mnemonic) {
  const key = await crypto.subtle.importKey('raw', strToBytes(normaliseMnemonic(mnemonic)), 'PBKDF2', false, ['deriveBits']);
  const seed = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: strToBytes('mnemonic'), iterations: 2048, hash: 'SHA-512' }, key, 512));
  // The v1 code took seedHex.substr(1, 64): each byte is the low nibble of one
  // seed byte and the high nibble of the next.
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = ((seed[i] & 0x0f) << 4) | (seed[i + 1] >> 4);
  return out;
}

// --- Broker (api.encedo.com) --------------------------------------------------
//
// Everything that talks to the Encedo backend lives here, and only here. The
// device does not need it: a HEM behind an air gap authorises with a password,
// manages keys, unlocks storage and reads its log without one broker call.
// The broker is needed for: the clock check-in, mobile push authorisation,
// pairing and listing mobile authenticators, software downloads, `*.ence.do`
// domains with their TLS certificates, device provisioning, and sharing a key
// by e-mail.
//
// One method per endpoint, plus the two polling loops. HEM composes them with
// device calls; a page that needs a broker-only call (a domain check while the
// user types) reaches it through `hem.broker`.

class Broker {
  #url;
  #debug;

  /**
   * @param {string} [url='https://api.encedo.com']  Broker base URL
   * @param {object} [opts]
   * @param {boolean} [opts.debug=false]  Log requests to console
   */
  constructor(url = 'https://api.encedo.com', { debug = false } = {}) {
    this.#url = url.replace(/\/+$/, '');
    this.#debug = debug;
  }

  /** Broker base URL, without a trailing slash. */
  get url() { return this.#url; }

  #req(method, path, body = null, opts = {}) {
    return httpRequest(method, `${this.#url}${path}`, { body, debug: this.#debug, tag: 'Broker', ...opts });
  }

  // -- Check-in ----------------------------------------------------------------

  /** Step 2 of the check-in: the broker counter-signs the device's challenge. */
  checkin(check) {
    return this.#req('POST', '/checkin', check);
  }

  // -- Sessions ----------------------------------------------------------------

  /**
   * Open a broker session.
   *
   * With `eid` (the device id from its config or auth challenge) the session
   * belongs to that device and the reply also says whether it has any paired
   * authenticator: { epk, paired }. Without `eid` the session is an ephemeral
   * key for one remote authorisation: { epk, ... } -- pass the whole object on
   * to /api/auth/ext/request.
   *
   * @param {string|null} [eid]
   * @returns {Promise<{epk: string, paired?: boolean}>}
   */
  session(eid = null) {
    return eid
      ? this.#req('POST', '/notify/session', { eid })
      : this.#req('GET', '/notify/session');
  }

  // -- Remote authorisation events ---------------------------------------------

  /** Publish a device challenge as a push event: { eventid }. */
  eventNew(challenge) {
    return this.#req('POST', '/notify/event/new', challenge);
  }

  /** One poll. Resolves null while the phone has not answered yet (HTTP 202). */
  async eventCheck(eventid, { signal = null } = {}) {
    const r = await this.#req('GET', `/notify/event/check/${eventid}`, null, { signal, withStatus: true });
    return r.status === 202 ? null : r.data;
  }

  /** Withdraw a pending event, so the phone stops showing it. */
  eventDelete(eventid) {
    return this.#req('DELETE', `/notify/event/${eventid}`);
  }

  /**
   * Poll an event until the phone answers, the caller cancels, or `pollTimeout`
   * passes. Resolves with the broker's answer ({ authreply } or { deny }).
   * Rejects with HemError `aborted` or `timeout`; the event is left as it is --
   * HEM.authorizeRemote deletes it.
   */
  waitEvent(eventid, opts = {}) {
    return this.#poll(() => this.eventCheck(eventid, opts), 'Remote auth timed out', opts);
  }

  // -- Pairing a mobile authenticator ------------------------------------------

  /** Start a pairing: { rid, link }. `link` goes into the QR code. */
  registerInit({ epk, eid, request }) {
    return this.#req('POST', '/notify/register/init', { epk, eid, request });
  }

  /** One poll. Resolves null until the QR has been scanned (HTTP 202), then { pid, reply }. */
  async registerCheck(rid, { signal = null } = {}) {
    const r = await this.#req('GET', `/notify/register/check/${rid}`, null, { signal, withStatus: true });
    return r.status === 202 ? null : r.data;
  }

  /** Close a pairing with the device's confirmation of the phone's reply. */
  registerFinalise(rid, confirmation) {
    return this.#req('POST', `/notify/register/finalise/${rid}`, confirmation);
  }

  /** Poll a pairing until the phone has scanned the QR code. */
  waitRegistration(rid, opts = {}) {
    return this.#poll(() => this.registerCheck(rid, opts), 'Ext authenticator registration timed out', opts);
  }

  // -- Paired authenticators ---------------------------------------------------
  //
  // Both take the object HEM.getExtAuthMac returns ({ nonce, mac, eid, epk }):
  // the device proves to the broker that whoever asks holds a system:config
  // token, and the broker answers for that device only.

  /** Authenticators paired with the device: [{ pid, ... }]. */
  subscribersList(mac) {
    return this.#req('POST', '/notify/subscribers/list', mac);
  }

  /** Remove one paired authenticator; `mac.pid` names it. */
  subscribersDelete(mac) {
    return this.#req('POST', '/notify/subscribers/delete', mac);
  }

  // -- Software downloads ------------------------------------------------------

  /**
   * Download a firmware or UI image announced by the check-in.
   *
   * @param {'firmware'|'dashboard'} kind
   * @param {string} version   `newfws` / `newuis` from HEM.hemCheckin(), verbatim
   * @returns {Promise<Uint8Array>}  Image bytes, ready for HEM.uploadFirmware / uploadUi
   */
  download(kind, version, { signal = null, timeoutMs = 0 } = {}) {
    const v = version.replace(/\//g, '_').replace(/\+/g, '-').replace(/=+$/, '');
    const path = kind === 'firmware' ? `/download/firmware/${v}/bin` : `/download/dashboard/${v}`;
    return this.#req('GET', path, null, { bytes: true, signal, timeoutMs });
  }

  // -- *.ence.do domains and TLS -----------------------------------------------

  /** Prefixes the broker offers for `<prefix>.ence.do` hostnames: { prefix: [...] }. */
  domainPredefs() {
    return this.#req('GET', '/domain/predefs');
  }

  /**
   * Whether `<prefix>.ence.do` is already registered.
   *
   * The broker answers 200 for a registered name and 404 for a free one; any
   * other failure is thrown, because "unreachable" must not read as "free".
   *
   * @returns {Promise<boolean>}  true when taken
   */
  async domainTaken(prefix) {
    try {
      await this.#req('GET', `/domain/check/${encodeURIComponent(prefix)}`);
      return true;
    } catch (e) {
      if (e instanceof HemError && e.status === 404) return false;
      throw e;
    }
  }

  /**
   * Register (or re-register) `<prefix>.ence.do` for a device and obtain its
   * TLS material: { emp, key, crt }, which goes to the device as
   * setConfig(token, { tls }). `genuine` is the device attestation; `csr` and
   * `ip` are given when a new certificate is requested.
   */
  domainRegister(prefix, { genuine, csr = null, ip = null }) {
    const body = { genuine };
    if (csr) body.csr = csr;
    if (ip) body.ip = ip;
    return this.#req('POST', `/domain/register/${encodeURIComponent(prefix)}`, body);
  }

  // -- Provisioning ------------------------------------------------------------

  /**
   * Turn a device's CSR into its certificate. Takes the { csr, key, genuine }
   * fields of HEM.getAttestation() on an unprovisioned device; the result is
   * installed with HEM.installProvisioning().
   */
  provisioning({ csr, key, genuine }) {
    return this.#req('POST', '/provisioning', { csr, key, genuine });
  }

  // -- Sharing -----------------------------------------------------------------

  /**
   * E-mail a share code (the object HEM's key-share page builds) to someone.
   *
   * @param {string} email
   * @param {object} shareCode   Sent as base64(JSON)
   * @param {string} [auth='']
   */
  shareEmailPubkey(email, shareCode, auth = '') {
    return this.#req('POST', '/share/emailpubkey', {
      email,
      msg: toB64(strToBytes(JSON.stringify(shareCode))),
      auth,
    });
  }

  // -- Polling -----------------------------------------------------------------

  async #poll(step, timeoutMessage, { pollInterval = 2_000, pollTimeout = 60_000, onPending = null, signal = null } = {}) {
    const deadline = Date.now() + pollTimeout;
    while (Date.now() < deadline) {
      await sleep(pollInterval, signal);
      if (onPending) onPending();
      const result = await step();
      if (result !== null) return result;
    }
    throw new HemError(timeoutMessage, { code: 'timeout' });
  }
}

// --- Audit log verification ---------------------------------------------------

/**
 * Verify an audit-log file against the device's logger key.
 *
 * The log is a text file, one entry per line, fields separated by `|`, the
 * first field a hex counter. A line whose third and fourth fields are 0 is a
 * key line: field 5 carries a fresh HMAC key (a nonce) and field 6 the logger
 * key's Ed25519 signature over it. Every line, key lines included, ends with
 * the first 16 bytes of HMAC-SHA256(current nonce, line up to and including
 * the last `|`). Counters must run without gaps (a repeat is allowed).
 * Comment lines start with `#`.
 *
 * Pure Web Crypto, no device call: pass what getLoggerKey() and getLogEntry()
 * returned. Requires Ed25519 in Web Crypto (Chrome 137+ / Firefox 130+ / Node 18+).
 *
 * @param {string} signerKey  `key` from HEM.getLoggerKey(): base64 Ed25519 public key
 * @param {string} logText    The log file
 * @returns {Promise<{ok: boolean, lines: number, line?: number, reason?: 'signature'|'sequence'|'no_key'|'hmac'}>}
 *          `line` and `reason` name the first entry that failed
 */
async function verifyLog(signerKey, logText) {
  const pubKey = await crypto.subtle.importKey('raw', fromB64(signerKey), { name: 'Ed25519' }, false, ['verify']);
  let hmacKey = null;
  let counter = 0;
  let lines = 0;

  for (const line of logText.split('\n')) {
    if (!line || line[0] === '#' || line.length < 3) continue;

    const f = line.split('|');
    const n = parseInt(f[0], 16);

    if (f[2] == 0 && f[3] == 0) {
      // Key line: the nonce becomes the HMAC key for what follows.
      const nonce = fromB64(f[4]);
      const sig = fromB64(f[5]);
      const ok = await crypto.subtle.verify({ name: 'Ed25519' }, pubKey, sig, nonce);
      if (!ok) return { ok: false, lines, line: n, reason: 'signature' };
      hmacKey = await crypto.subtle.importKey('raw', nonce, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      counter = n;
    }

    if (n !== counter + 1 && n !== counter) return { ok: false, lines, line: n, reason: 'sequence' };
    counter = n;

    if (!hmacKey) return { ok: false, lines, line: n, reason: 'no_key' };
    const cut = line.lastIndexOf('|') + 1;
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, strToBytes(line.slice(0, cut)))).subarray(0, 16);
    if (!bytesEqual(mac, fromB64(line.slice(cut)))) return { ok: false, lines, line: n, reason: 'hmac' };
    lines++;
  }
  return { ok: true, lines };
}

// --- /api/crypto/* shared options ---------------------------------------------

// Device limits. Exceeding either surfaces as an opaque HTTP 400, so the SDK
// checks them where the caller can still see which argument was at fault.
const MAX_CRYPTO_MSG = 2048;
const MAX_CRYPTO_CTX = 64;

/**
 * Write the ext_kid / pubkey selector into a request body.
 *
 * Both name a peer public key and turn the operation into an indirect one: the
 * device runs ECDH between `kid` and the peer key and uses the shared secret as
 * the operation's key, so the key actually in use never exists outside the HEM.
 * Naming the key's *own* public key is legal and yields a self-ECDH key — the
 * construction the config-free WireGuard client uses to authenticate its
 * configuration. The peer key must be of the same type as `kid`.
 */
function applyPeerKey(body, opts, op) {
  const { extKid = null, pubkey = null } = opts;
  if (extKid && pubkey) {
    throw new HemError(`${op}: pass extKid or pubkey, not both`, { code: 'invalid_arg' });
  }
  if (extKid) body.ext_kid = extKid;
  else if (pubkey) body.pubkey = pubkey instanceof Uint8Array ? toB64(pubkey) : pubkey;
}

/** Write the optional HKDF context, which domain-separates a derived key. */
function applyCtx(body, opts, op) {
  const { ctx = null } = opts;
  if (ctx === null || ctx === undefined) return;
  const bytes = ctx instanceof Uint8Array ? ctx : strToBytes(ctx);
  if (bytes.length > MAX_CRYPTO_CTX) {
    throw new HemError(`${op}: ctx is ${bytes.length} bytes, max ${MAX_CRYPTO_CTX}`,
      { code: 'invalid_arg' });
  }
  body.ctx = toB64(bytes);
}

function checkMsgSize(op, data) {
  if (data.length > MAX_CRYPTO_MSG) {
    throw new HemError(`${op}: message is ${data.length} bytes, max ${MAX_CRYPTO_MSG}`,
      { code: 'invalid_arg' });
  }
}

// --- Main class ---------------------------------------------------------------

class HEM {
  #baseUrl;
  #broker;
  #debug;
  #tokenCache = [];
  #derivedKeys = null;   // { privKey: CryptoKey (non-extractable), pubkeyB64: string }

  /**
   * @param {string} hsmUrl   Base URL of the Encedo HEM device (e.g. 'https://abc.ence.do')
   * @param {object} [opts]
   * @param {string|Broker} [opts.broker='https://api.encedo.com']  Broker URL, or a Broker instance to share
   * @param {boolean} [opts.debug=false]  Log requests to console
   */
  constructor(hsmUrl, { broker = 'https://api.encedo.com', debug = false } = {}) {
    this.#baseUrl = hsmUrl.replace(/\/+$/, '');
    this.#broker = broker instanceof Broker ? broker : new Broker(broker, { debug });
    this.#debug = debug;
  }

  /** The Broker this instance uses for every api.encedo.com call. */
  get broker() { return this.#broker; }

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
    return httpRequest(method, url, { body, token, debug: this.#debug, tag: 'HEM', ...opts });
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
    return this.#authorizeWithKeys(this.#derivedKeys, challenge, scope, expSeconds);
  }

  // -- Authorization: Master secret (the 24 words) ------------------------------

  /**
   * Authenticate with the master secret from the Proof of Personalization.
   *
   * The words decode to the 32 bytes that ARE the master private key, so this
   * is the same two-step flow as authorizePassword with a different key source.
   * A wrong word is caught before any request: mnemonicToEntropy throws
   * `mnemonic_invalid` (naming the word) or `mnemonic_checksum`.
   *
   * The master key is the device's admin identity: it authorises anything,
   * including a new user password. Do not cache the mnemonic anywhere.
   *
   * @param {string} mnemonic   12-24 BIP39 words
   * @param {string} scope
   * @param {number} [expSeconds=300]
   * @param {object} [opts]
   * @param {boolean} [opts.legacy=false]  Device personalised by the v1 Manager,
   *   whose master key came from the BIP39 seed at a one-nibble offset.
   * @returns {Promise<string>}  JWT token
   */
  async authorizeMaster(mnemonic, scope, expSeconds = 300, { legacy = false } = {}) {
    const cached = this.#cacheFind(scope);
    if (cached) return cached;

    const seed = legacy ? await legacyMasterSeed(mnemonic) : await mnemonicToEntropy(mnemonic);
    if (seed.length !== 32) {
      throw new HemError('The master secret must be 24 words (256 bits)', { code: 'mnemonic_invalid', data: { bytes: seed.length } });
    }
    const keys = await keysFromSeed(seed);
    seed.fill(0);

    const challenge = await this.#req('GET', `${this.#baseUrl}/api/auth/token`);
    return this.#authorizeWithKeys(keys, challenge, scope, expSeconds);
  }

  /** Sign the device's challenge with `keys` and exchange it for a scoped token. */
  async #authorizeWithKeys({ privKey, pubkeyB64 }, challenge, scope, expSeconds) {
    const iat = Math.floor(Date.now() / 1000) - 5;   // -5s for clock drift
    const payload = {
      jti: challenge.jti,
      aud: challenge.spk,
      exp: iat + expSeconds,
      iat,
      iss: pubkeyB64,   // our X25519 public key as standard base64
      scope,
    };

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
   *
   * Resolves with the device's step-3 answer. Besides `status` it may carry
   * `newfws` / `newuis`: a newer firmware / UI image is available, and the
   * value is what Broker.download() takes.
   *
   * Without a reachable broker this throws `broker_error` (or `network`);
   * a device behind an air gap still authorises with a password afterwards.
   *
   * @returns {Promise<{status: string, newfws?: string, newuis?: string, [key: string]: any}>}
   */
  async hemCheckin() {
    const step1 = await this.#req('GET', `${this.#baseUrl}/api/system/checkin`);
    if (!step1.check) throw new HemError('HSM checkin failed (no check field)', { code: 'checkin_error' });

    const step2 = await this.#broker.checkin(step1);
    if (!step2.checked) throw new HemError('Broker checkin failed (no checked field)', { code: 'broker_error' });

    const step3 = await this.#req('POST', `${this.#baseUrl}/api/system/checkin`, step2);
    if (!step3.status) throw new HemError('HSM checkin step 3 failed (no status field)', { code: 'checkin_error' });

    return step3;
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
   * Cancelling (`signal`) or running out of time withdraws the event from the
   * broker, so the phone stops showing a request nobody is waiting for. Both
   * reject with HemError: code `aborted` or `timeout`; a refusal on the phone
   * is `denied`.
   *
   * @param {string} scope       e.g. 'keymgmt:list'
   * @param {object} [opts]
   * @param {number} [opts.pollInterval=2000]  Poll interval in ms
   * @param {number} [opts.pollTimeout=60000]  Max wait time in ms
   * @param {Function} [opts.onPending]        Called each poll while waiting (no args)
   * @param {Function} [opts.onEvent]          Called once with the broker event id
   * @param {AbortSignal} [opts.signal]        Cancels the wait
   * @returns {Promise<string>}  JWT token
   */
  async authorizeRemote(scope, {
    pollInterval = 2_000,
    pollTimeout = 60_000,
    onPending = null,
    onEvent = null,
    signal = null,
  } = {}) {
    const cached = this.#cacheFind(scope);
    if (cached) return cached;

    // Step 1: broker session EPK
    const session = await this.#broker.session();

    // Step 2: request auth from device (pass full session data + scope)
    const challenge = await this.#req('POST', `${this.#baseUrl}/api/auth/ext/request`, {
      ...session,
      scope,
    });

    // Step 3: forward challenge to broker -> eventid
    const { eventid } = await this.#broker.eventNew(challenge);
    if (!eventid) throw new HemError('No eventid from broker', { code: 'broker_error' });
    if (onEvent) onEvent(eventid);

    // Step 4: poll; on cancel or timeout withdraw the event
    let result;
    try {
      result = await this.#broker.waitEvent(eventid, { pollInterval, pollTimeout, onPending, signal });
    } catch (e) {
      await this.#broker.eventDelete(eventid).catch(() => {});
      throw e;
    }

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
   * The eJWT carries a `cfg` block and is signed with the ADMIN key. The public
   * keys are written into `cfg` as `masterkey` / `userkey` automatically.
   *
   * The admin (master) identity should be a BIP39 master secret: call
   * generateMnemonic(), show the words, print them, and pass them here. Those
   * 24 words decode to the 32 bytes that ARE the master private key, so any
   * BIP39 tool can recover it and a mistyped word is caught by the checksum.
   * A password string is still accepted (PBKDF2, salt = challenge.eid) for
   * callers that want one.
   *
   * @param {string|{mnemonic: string}|{entropy: Uint8Array}} admin  Master secret
   * @param {string} userPassword   Local user passphrase
   * @param {object} [cfg]          Device config: { user, email, hostname,
   *                                trusted_ts, trusted_backend, allow_keysearch,
   *                                gen_csr, origin, ... }. masterkey/userkey are
   *                                filled in automatically and override any value
   *                                passed here.
   * @returns {Promise<object>}     Initialization result from the device
   */
  async initialize(admin, userPassword, cfg = {}) {
    // Phase 1 -- challenge
    const challenge = await this.#req('GET', `${this.#baseUrl}/api/auth/init`);
    // { eid: string (salt), spk: base64 (device X25519 pubkey), jti, exp }

    // The admin (master) identity: the 24 words, raw entropy, or a password.
    let adminKeys;
    if (typeof admin === 'string') {
      adminKeys = await this.#deriveX25519(admin, challenge.eid);
    } else if (admin?.mnemonic) {
      const entropy = await mnemonicToEntropy(admin.mnemonic);
      if (entropy.length !== 32) throw new HemError('The master secret must be 24 words (256 bits)', { code: 'mnemonic_invalid' });
      adminKeys = await keysFromSeed(entropy);
      entropy.fill(0);
    } else if (admin?.entropy instanceof Uint8Array) {
      if (admin.entropy.length !== 32) throw new HemError('The master secret must be 32 bytes', { code: 'mnemonic_invalid' });
      adminKeys = await keysFromSeed(admin.entropy);
    } else {
      throw new HemError('initialize needs a master secret: { mnemonic }, { entropy } or a password string', { code: 'mnemonic_invalid' });
    }

    // The user identity is always a password (PBKDF2 salt = challenge.eid)
    const user = await this.#deriveX25519(userPassword, challenge.eid);

    const payload = {
      jti: challenge.jti,
      aud: challenge.spk,
      exp: challenge.exp,
      iat: Math.floor(Date.now() / 1000),
      iss: adminKeys.pubkeyB64,
      cfg: {
        ...cfg,
        masterkey: adminKeys.pubkeyB64,
        userkey: user.pubkeyB64,
      },
    };

    // eJWT signed with the ADMIN key
    const ejwt = await this.#buildEjwt(adminKeys.privKey, challenge.spk, payload);
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
    const session = await this.#broker.session(config.eid);
    const { epk } = session;
    if (!epk) throw new HemError('No epk from broker', { code: 'broker_error' });

    // Step 3 -- device ext-auth challenge
    const challenge = await this.#req('POST', `${this.#baseUrl}/api/auth/ext/init`, { epk }, token);

    // Step 4 -- broker registration session -> rid + QR link
    const reg = await this.#broker.registerInit({ epk, eid: challenge.eid, request: challenge.request });
    const { rid, link } = reg;
    if (!rid) throw new HemError('No rid from broker', { code: 'broker_error' });

    // Step 5 -- build the QR payload and hand it to the caller to render.
    // The payload MUST be byte-identical to the reference implementation: the
    // mobile authenticator app scans this exact JSON. Key order (link, hash,
    // user, email, hostname) matches PHP json_encode() of the source array.
    // `hash` is base64(SHA-256(request)): the phone checks the request it later
    // fetches from the broker against what it scanned.
    // The SDK only produces the data; rendering the QR image is out of scope.
    const qrPayload = {
      link,
      hash: toB64(await sha256(strToBytes(challenge.request))),
      user: config.user,
      email: config.email,
      hostname: config.hostname,
    };
    if (onQrCode) onQrCode(JSON.stringify(qrPayload), qrPayload);

    // Step 6 -- poll until the mobile app scans the QR
    const reply = await this.#broker.waitRegistration(rid, { pollInterval, pollTimeout, onPending, signal });
    if (!reply.pid || !reply.reply) throw new HemError('Missing pid/reply from broker', { code: 'broker_error' });

    // Step 7 -- validate the pairing on the device
    const confirmation = await this.#req('POST', `${this.#baseUrl}/api/auth/ext/validate`,
      { pid: reply.pid, reply: reply.reply }, token);

    // Step 8 -- finalise the pairing on the broker
    return this.#broker.registerFinalise(rid, confirmation);
  }

  /**
   * Obtain MAC data that authenticates this device to the notification broker.
   * The returned object is what Broker.subscribersList / subscribersDelete take;
   * listExtAuth() and deleteExtAuth() below do the whole round trip.
   *
   * Fetches the device `eid`, opens a broker session for an ephemeral key, then
   * calls POST /api/auth/ext/mac -- same broker handshake as registerExtAuth().
   *
   * Required scope: 'system:config' (or 'auth:ext:pair')
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<{nonce: string, mac: string, eid: string, epk: string}>}
   */
  async getExtAuthMac(token) {
    const config = await this.#req('GET', `${this.#baseUrl}/api/system/config`, null, token);
    if (!config.eid) throw new HemError('No eid in device config', { code: 'ext_register_error' });

    const session = await this.#broker.session(config.eid);
    if (!session.epk) throw new HemError('No epk from broker', { code: 'broker_error' });

    const mac = await this.#req('POST', `${this.#baseUrl}/api/auth/ext/mac`, { epk: session.epk }, token);
    return { ...mac, epk: session.epk };
  }

  /**
   * Mobile authenticators paired with this device, as the broker knows them:
   * [{ pid, ... }]. A paired phone also exists in the device's keychain as a
   * key whose description is base64('EXTAID') + pid ('RVhUQUlE' + pid), which
   * is how a UI matches the two lists.
   *
   * Required scope: 'system:config' (or 'auth:ext:pair')
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<Array<{pid: string, [key: string]: any}>>}
   */
  async listExtAuth(token) {
    const mac = await this.getExtAuthMac(token);
    return this.#broker.subscribersList(mac);
  }

  /**
   * Unpair one mobile authenticator on the broker side. The matching keychain
   * entry (description 'RVhUQUlE' + pid) is deleted separately with deleteKey().
   *
   * Required scope: 'system:config' (or 'auth:ext:pair')
   *
   * @param {string} token  Bearer JWT
   * @param {string} pid    Authenticator id from listExtAuth()
   * @returns {Promise<object>}
   */
  async deleteExtAuth(token, pid) {
    const mac = await this.getExtAuthMac(token);
    return this.#broker.subscribersDelete({ ...mac, pid });
  }

  /**
   * Whether any mobile authenticator is paired with this device. No token
   * needed: the auth challenge carries the device id and the broker answers
   * with a `paired` flag. A login screen uses it to offer the phone first.
   *
   * @returns {Promise<boolean>}
   */
  async hasExtAuth() {
    const challenge = await this.#req('GET', `${this.#baseUrl}/api/auth/token`);
    if (!challenge.eid) throw new HemError('No eid in auth challenge', { code: 'auth_failed' });
    const session = await this.#broker.session(challenge.eid);
    return Boolean(session.paired);
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
   * The private key never leaves the device — only the shared secret is returned.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string} token             Bearer JWT
   * @param {string} kid               Key ID (32-char hex) of the X25519 private key in HSM
   * @param {string} peerPubKeyBase64  Peer's raw 32-byte X25519 public key in standard base64
   * @param {object} [opts]
   * @param {string|null} [opts.alg=null]  Hash applied to the shared secret
   *                       ('SHA2-256'…'SHA3-512'). Omit for the raw secret —
   *                       that is what a Noise handshake needs.
   * @returns {Promise<Uint8Array>}    Shared secret: raw 32 bytes, or the digest when alg is set
   */
  async ecdh(token, kid, peerPubKeyBase64, { alg = null } = {}) {
    const body = { kid, pubkey: peerPubKeyBase64 };
    if (alg) body.alg = alg;
    return this.#ecdhCall(body, token, alg);
  }

  /**
   * Curve25519 ECDH between two keys that already live in the HSM: my private
   * key (`kid`) and a peer public key imported into the HSM (`extKid`). Both
   * operands stay in-device — only the shared secret is returned.
   * The two-KID counterpart of {@link ecdh} (which takes a raw peer pubkey).
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string} token   Bearer JWT
   * @param {string} kid     Key ID (32-char hex) of my X25519 private key in HSM
   * @param {string} extKid  Key ID of the peer's X25519 public key in HSM
   * @param {object} [opts]
   * @param {string|null} [opts.alg=null]  Hash applied to the shared secret; omit for raw
   * @returns {Promise<Uint8Array>}  Shared secret: raw 32 bytes, or the digest when alg is set
   */
  async ecdhKid(token, kid, extKid, { alg = null } = {}) {
    const body = { kid, ext_kid: extKid };
    if (alg) body.alg = alg;
    return this.#ecdhCall(body, token, alg);
  }

  async #ecdhCall(body, token, alg) {
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/ecdh`, body, token);
    if (!ret.ecdh) throw new HemError('No ecdh in response', { code: 'ecdh_error' });
    const result = fromB64(ret.ecdh);
    // Only the raw secret has a known length; a hashed result is as long as the digest.
    if (!alg && result.length !== 32) {
      throw new HemError(`ECDH result length invalid: expected 32, got ${result.length}`,
        { code: 'ecdh_error' });
    }
    return result;
  }

  /**
   * Compute an HMAC over arbitrary data using a key in the HSM (max 2048 bytes).
   *
   * With `extKid` or `pubkey` the MAC key is not the key at `kid` but the ECDH
   * shared secret between the two, so pointing at `kid`'s own public key gives a
   * MAC key that never exists outside the device.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token  Bearer JWT
   * @param {string}     kid    Key ID (32-char hex) of the HMAC key
   * @param {Uint8Array} data   Raw bytes to authenticate
   * @param {string|null} [alg=null]  Hash algorithm, e.g. 'SHA2-256' (device default if null)
   * @param {object} [opts]
   * @param {string|null} [opts.extKid=null]  Peer public key already in the HSM
   * @param {Uint8Array|string|null} [opts.pubkey=null]  Raw peer public key; not with extKid
   * @returns {Promise<Uint8Array>}  Raw MAC bytes
   */
  async hmacHash(token, kid, data, alg = null, opts = {}) {
    checkMsgSize('hmacHash', data);
    const body = { kid, msg: toB64(data) };
    if (alg !== null) body.alg = alg;
    applyPeerKey(body, opts, 'hmacHash');
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/hmac/hash`, body, token);
    if (!ret.mac) throw new HemError('No mac in hmac/hash response', { code: 'hmac_error' });
    return fromB64(ret.mac);
  }

  /**
   * Verify an HMAC on the HSM. Resolves true on success; throws HemError if the
   * MAC is invalid — the comparison happens inside the device, so the caller
   * never has to write a constant-time compare.
   *
   * `alg` and `opts` must match the hmacHash call that produced the MAC.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token  Bearer JWT
   * @param {string}     kid    Key ID (32-char hex) of the HMAC key
   * @param {Uint8Array} data   Raw bytes that were authenticated
   * @param {Uint8Array} mac    Raw MAC bytes to verify
   * @param {string|null} [alg=null]  Hash algorithm (must match hmacHash)
   * @param {object} [opts]
   * @param {string|null} [opts.extKid=null]  Peer public key already in the HSM
   * @param {Uint8Array|string|null} [opts.pubkey=null]  Raw peer public key; not with extKid
   * @returns {Promise<true>}
   */
  async hmacVerify(token, kid, data, mac, alg = null, opts = {}) {
    checkMsgSize('hmacVerify', data);
    const body = { kid, msg: toB64(data), mac: toB64(mac) };
    if (alg !== null) body.alg = alg;
    applyPeerKey(body, opts, 'hmacVerify');
    await this.#req('POST', `${this.#baseUrl}/api/crypto/hmac/verify`, body, token);
    return true;
  }

  /**
   * Encrypt data with a symmetric key stored in the HSM (max 2048 bytes).
   * The IV is generated by the device and returned alongside the ciphertext;
   * GCM modes also return the authentication tag. All three are needed to
   * decrypt, so the result is an object rather than a bare byte array.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token  Bearer JWT
   * @param {string}     kid    Key ID (32-char hex) of the symmetric key
   * @param {Uint8Array} data   Plaintext bytes (for ECB the length must be a
   *                            multiple of the 16-byte AES block size)
   * @param {string}     alg    Cipher + mode, e.g. 'AES256-CBC', 'AES256-GCM', 'AES256-ECB'
   * @param {object} [opts]
   * @param {string|null} [opts.extKid=null]  Peer public key already in the HSM
   * @param {Uint8Array|string|null} [opts.pubkey=null]  Raw peer public key; not with extKid
   * @param {Uint8Array|null} [opts.aad=null]  Additional authenticated data (GCM only)
   * @param {Uint8Array|string|null} [opts.ctx=null]  HKDF context, max 64 bytes
   * @returns {Promise<{ciphertext: Uint8Array, iv: Uint8Array, tag: Uint8Array|null}>}
   */
  async cipherEncrypt(token, kid, data, alg, opts = {}) {
    checkMsgSize('cipherEncrypt', data);
    const body = { kid, msg: toB64(data), alg };
    applyPeerKey(body, opts, 'cipherEncrypt');
    applyCtx(body, opts, 'cipherEncrypt');
    if (opts.aad) body.aad = toB64(opts.aad);
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/cipher/encrypt`, body, token);
    if (!ret.ciphertext) throw new HemError('No ciphertext in encrypt response', { code: 'cipher_error' });
    return {
      ciphertext: fromB64(ret.ciphertext),
      iv: ret.iv ? fromB64(ret.iv) : null,
      tag: ret.tag ? fromB64(ret.tag) : null,
    };
  }

  /**
   * Decrypt data with a symmetric key stored in the HSM. `opts.iv` is required
   * for CBC and GCM and `opts.tag` for GCM — pass back what cipherEncrypt
   * returned, along with the same peer key, aad and ctx.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token       Bearer JWT
   * @param {string}     kid         Key ID (32-char hex) of the symmetric key
   * @param {Uint8Array} ciphertext  Ciphertext bytes
   * @param {string}     alg         Cipher + mode (must match cipherEncrypt)
   * @param {object} [opts]  As cipherEncrypt, plus:
   * @param {Uint8Array|null} [opts.iv=null]   IV returned by cipherEncrypt
   * @param {Uint8Array|null} [opts.tag=null]  GCM tag returned by cipherEncrypt
   * @returns {Promise<Uint8Array>}  Plaintext bytes
   */
  async cipherDecrypt(token, kid, ciphertext, alg, opts = {}) {
    checkMsgSize('cipherDecrypt', ciphertext);
    const body = { kid, msg: toB64(ciphertext), alg };
    applyPeerKey(body, opts, 'cipherDecrypt');
    applyCtx(body, opts, 'cipherDecrypt');
    if (opts.iv) body.iv = toB64(opts.iv);
    if (opts.tag) body.tag = toB64(opts.tag);
    if (opts.aad) body.aad = toB64(opts.aad);
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/cipher/decrypt`, body, token);
    if (!ret.plaintext) throw new HemError('No plaintext in decrypt response', { code: 'cipher_error' });
    return fromB64(ret.plaintext);
  }

  /**
   * Key-wrap: encrypt key material with a key-encryption key held in the HSM
   * (NIST AES key wrap — deterministic, 32 bytes in, 40 bytes out).
   *
   * With `extKid` or `pubkey` the KEK is the ECDH shared secret rather than the
   * key at `kid`; `ctx` then domain-separates that KEK from other wrap uses of
   * the same key and must be repeated verbatim on unwrap.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token  Bearer JWT
   * @param {string}     kid    Key ID (32-char hex) of the wrapping key
   * @param {string}     alg    Wrapping algorithm (key type, e.g. 'AES256')
   * @param {Uint8Array} data   Key material to wrap (max 2048 bytes)
   * @param {object} [opts]
   * @param {string|null} [opts.extKid=null]  Peer public key already in the HSM
   * @param {Uint8Array|string|null} [opts.pubkey=null]  Raw peer public key; not with extKid
   * @param {Uint8Array|string|null} [opts.ctx=null]     HKDF context, max 64 bytes
   * @param {Uint8Array|null} [opts.iv=null]             Explicit IV; omit for the default
   * @returns {Promise<Uint8Array>}  Wrapped key bytes
   */
  async cipherWrap(token, kid, alg, data, opts = {}) {
    checkMsgSize('cipherWrap', data);
    const body = { kid, alg, msg: toB64(data) };
    applyPeerKey(body, opts, 'cipherWrap');
    applyCtx(body, opts, 'cipherWrap');
    if (opts.iv) body.iv = toB64(opts.iv);
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/cipher/wrap`, body, token);
    if (!ret.wrapped) throw new HemError('No wrapped in wrap response', { code: 'cipher_error' });
    return fromB64(ret.wrapped);
  }

  /**
   * Key-unwrap: recover key material wrapped by {@link cipherWrap}. Every option
   * must match the wrap call — a differing `ctx` derives a different KEK and the
   * unwrap fails.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token    Bearer JWT
   * @param {string}     kid      Key ID (32-char hex) of the wrapping key
   * @param {string}     alg      Wrapping algorithm (must match cipherWrap)
   * @param {Uint8Array} wrapped  Wrapped key bytes
   * @param {object} [opts]  Same shape as cipherWrap; must match it
   * @returns {Promise<Uint8Array>}  Unwrapped key material
   */
  async cipherUnwrap(token, kid, alg, wrapped, opts = {}) {
    checkMsgSize('cipherUnwrap', wrapped);
    const body = { kid, alg, msg: toB64(wrapped) };
    applyPeerKey(body, opts, 'cipherUnwrap');
    applyCtx(body, opts, 'cipherUnwrap');
    if (opts.iv) body.iv = toB64(opts.iv);
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/cipher/unwrap`, body, token);
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
   * Search the key repository by the description field.
   *
   * The pattern is matched as a prefix. The '^' anchor the device expects goes
   * on the base64 text, not on the bytes, so the SDK adds it after encoding —
   * pass the plain value. A Uint8Array pattern lets a caller search binary
   * descriptions; a string is UTF-8 encoded. Only prefix matching is available:
   * a '$' suffix anchor appears in neither the API reference nor the
   * certification suite, so it is left out until the firmware is checked.
   *
   * The device returns at most `limit` entries (its own default is 15) starting
   * at `offset`. Paginate by adding the page length to `offset` until a page
   * comes back shorter than `limit`.
   *
   * Pass token=null for anonymous access, which the device permits when
   * `allow_keysearch` is configured and the pattern is at least 6 bytes.
   *
   * Required scope: 'keymgmt:search' (or 'keymgmt:list' + 'auth:ext:pair')
   *
   * @param {string|null} token  Bearer JWT, or null for an anonymous search
   * @param {string|Uint8Array} descr  Pattern the description must start with
   * @param {number} [offset=0]  Entries to skip
   * @param {number} [limit=0]   Max entries; <= 0 leaves the device default (15)
   * @returns {Promise<Array<{kid:string, label:string, type:string, created:number|null, updated:number|null, description:Uint8Array|null}>>}
   */
  async searchKeys(token, descr, offset = 0, limit = 0) {
    const bytes = descr instanceof Uint8Array ? descr : strToBytes(descr);
    const body = { descr: '^' + toB64(bytes), offset: Math.max(0, offset) };
    if (limit > 0) body.limit = limit;
    const data = await this.#req(
      'POST', `${this.#baseUrl}/api/keymgmt/search`,
      body, token
    );
    return (data.list ?? []).map(entry => ({
      kid: entry.kid,
      label: entry.label ?? '',
      type: entry.type ?? '',
      created: entry.created ?? null,
      updated: entry.updated ?? null,
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
   * Cheap and unauthenticated, which makes it the natural "is a device there at
   * all" probe — so it is the first method to take a budget. Bound it, or a
   * caller watching for a device that is not plugged in has no way to stop
   * waiting without leaving the request open.
   *
   * @param   {object}      [opts]
   * @param   {number}      [opts.timeoutMs]  Cancel the request after this long
   * @param   {AbortSignal} [opts.signal]     Cancel it from outside
   * @returns {Promise<{hwv:string, blv:string, fwv:string, fws:string, conf:string}>}
   */
  async getVersion(opts = {}) {
    return this.#req('GET', `${this.#baseUrl}/api/system/version`, null, null, opts);
  }

  /**
   * Get current device status (init state, failure-lockdown state, hostname, ...).
   * No authentication required.
   *
   * @param   {object}      [opts]
   * @param   {number}      [opts.timeoutMs]
   * @param   {AbortSignal} [opts.signal]
   * @returns {Promise<object>}
   */
  async getStatus(opts = {}) {
    return this.#req('GET', `${this.#baseUrl}/api/system/status`, null, null, opts);
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
   * @param {object}     [opts]
   * @param {Function}   [opts.onProgress]  (loaded, total) in bytes -- browser only
   * @param {AbortSignal} [opts.signal]     Cancels the upload
   * @returns {Promise<object>}
   */
  async uploadFirmware(token, bytes, filename = 'firmware.bin', { onProgress = null, signal = null } = {}) {
    return this.#req('POST', `${this.#baseUrl}/api/system/upgrade/upload_fw`,
      bytes, token, { binary: true, filename, onProgress, signal });
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
  async uploadUi(token, bytes, filename = 'ui.bin', { onProgress = null, signal = null } = {}) {
    return this.#req('POST', `${this.#baseUrl}/api/system/upgrade/upload_ui`,
      bytes, token, { binary: true, filename, onProgress, signal });
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

  // -- Provisioning (PPA: certificate for the device) ---------------------------

  /**
   * Install the certificate the broker issued for this device.
   * Fails with HTTP 403 on a device that is already provisioned.
   *
   * @param {object} cert   Result of Broker.provisioning()
   * @param {string|null} [token]
   * @returns {Promise<object>}
   */
  async installProvisioning(cert, token = null) {
    return this.#req('POST', `${this.#baseUrl}/api/system/config/provisioning`, cert, token);
  }

  /**
   * Provision the device if it still needs it: read the attestation, and when it
   * carries a CSR, have the broker sign it and install the certificate.
   *
   * Resolves with the installed certificate, or null when the device was
   * already provisioned (no CSR in the attestation).
   *
   * @param {string|null} [token]  Any valid JWT; the attestation endpoint accepts any
   * @returns {Promise<object|null>}
   */
  async provision(token = null) {
    const att = await this.#req('GET', `${this.#baseUrl}/api/system/config/attestation`, null, token);
    if (!att.csr) return null;
    const cert = await this.#broker.provisioning({ csr: att.csr, key: att.key, genuine: att.genuine });
    await this.installProvisioning(cert, token);
    return cert;
  }

  // -- *.ence.do domain and TLS certificate ------------------------------------

  /**
   * Register `<prefix>.ence.do` for this device and install the TLS material.
   *
   * With `newCertificate` (default) the device first generates a CSR
   * (setConfig { gen_csr: true } -> { genuine, csr }); the broker signs it and
   * returns { emp, key, crt }, which is written back as { tls }. Without it the
   * broker re-issues the existing registration from the attestation alone.
   *
   * Required scope: 'system:config'
   *
   * @param {string} token   Bearer JWT
   * @param {string} prefix  Hostname prefix, e.g. 'my' for my.ence.do
   * @param {object} [opts]
   * @param {string} [opts.ip]                 LAN address the name should resolve to
   * @param {boolean} [opts.newCertificate=true]
   * @returns {Promise<object>}  The tls block installed on the device
   */
  async registerDomain(token, prefix, { ip = null, newCertificate = true } = {}) {
    let genuine, csr = null;
    if (newCertificate) {
      const req = await this.#req('POST', `${this.#baseUrl}/api/system/config`, { gen_csr: true }, token);
      genuine = req.genuine;
      csr = req.csr;
    }
    if (!genuine) {
      const challenge = await this.#req('GET', `${this.#baseUrl}/api/auth/token`);
      genuine = challenge.genuine;
    }
    if (!genuine) throw new HemError('No attestation (genuine) available for domain registration', { code: 'domain_error' });

    const tls = await this.#broker.domainRegister(prefix, { genuine, csr, ip });
    await this.#req('POST', `${this.#baseUrl}/api/system/config`, { tls }, token);
    return tls;
  }

  // -- Audit log verification --------------------------------------------------

  /**
   * Fetch one log file and verify it against the device's logger key.
   * See verifyLog() for the format and the result.
   *
   * Required scope: 'logger:get'
   *
   * @param {string} token
   * @param {string|number} id   Log entry id from listLog()
   * @returns {Promise<{ok: boolean, lines: number, line?: number, reason?: string, text: string}>}
   */
  async verifyLogEntry(token, id) {
    const { key } = await this.getLoggerKey(token);
    const text = await this.getLogEntry(token, id);
    const result = await verifyLog(key, typeof text === 'string' ? text : JSON.stringify(text));
    return { ...result, text };
  }

}

export { Broker, HEM, HemError, entropyToMnemonic, generateMnemonic, jwtParse, mnemonicToEntropy, validateMnemonic, verifyLog };
//# sourceMappingURL=hem-sdk.browser.js.map
