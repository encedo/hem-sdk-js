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
      // No default limit, as with fetch: ML-DSA signing waits up to 30 s for
      // the engine and a firmware upload over a slow link takes longer still.
      ...(timeoutMs ? { timeout: timeoutMs } : {}),
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
      reject(new HemError(`Request timeout after ${timeoutMs} ms`, { code: 'timeout' }));
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
/**
 * Call `step` every `pollInterval` ms until it answers something other than
 * null, or `pollTimeout` passes (HemError `timeout`), or `signal` cancels.
 */
async function pollUntil(step, timeoutMessage, { pollInterval = 2_000, pollTimeout = 60_000, onPending = null, signal = null } = {}) {
  const deadline = Date.now() + pollTimeout;
  while (Date.now() < deadline) {
    const result = await step();
    if (result !== null) return result;
    if (onPending) onPending();
    await sleep(pollInterval, signal);
  }
  throw new HemError(timeoutMessage, { code: 'timeout' });
}

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

  /**
   * Where a registration that did not finish at once has got to. A prefix of
   * the owner's choosing is confirmed by e-mail first, so domainRegister()
   * answers 201 with an { id } instead of the tls block; this reads
   * { status: 'pending' | 'email_confirmed' | 'done' | 'failed', ... } for it,
   * and once `status` is 'done' the answer is the tls block itself.
   */
  domainStatus(id) {
    return this.#req('GET', `/domain/register/${encodeURIComponent(id)}`);
  }

  /**
   * Poll a pending registration until it is done. `onPending` gets the status
   * each time, so a page can say "check your inbox" and then "confirmed".
   * Rejects with HemError `domain_failed` when the broker gives up, `timeout`
   * when the caller does (a minute per poll of 4 s by default: four minutes).
   */
  async waitDomain(id, { pollInterval = 4_000, pollTimeout = 240_000, onPending = null, signal = null } = {}) {
    return this.#poll(async () => {
      const answer = await this.domainStatus(id);
      if (answer?.status === 'failed') throw new HemError('The domain registration failed', { code: 'domain_failed' });
      if (answer?.status === 'done' || answer?.crt) return answer;
      if (onPending) onPending(answer?.status ?? 'pending');
      return null;
    }, 'The domain registration was not confirmed in time', { pollInterval, pollTimeout, signal });
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

const LOG_KEY_ROTATE = '32';      // LOGGER_KEY_ROTATE: data = the next per-file public key
const LOG_EVENTS_LOST = '33';     // LOGGER_EVENTS_LOST: data = u32 LE count of dropped events

/**
 * Verify an audit-log file (format v2, firmware 1.3+) against the device log key.
 *
 * One line per event, seven `|`-separated fields:
 * `seq|ts|type|result|subject|data|sig`. `seq` is hex and runs from 0 by one;
 * `data` and `sig` are base64url. Every line is signed (Ed25519, `sig`, over
 * the text up to and including the last `|`) with a per-file key. That key is
 * announced by a header line - type 0, result 0, subject `v2`, data = the
 * per-file public key (32 B) followed by the device log key's signature over
 * it (64 B) - and replaced at a UTC day change by a LOGGER_KEY_ROTATE line
 * naming the next key, followed by the next header. Lines starting with `#`
 * are comments.
 *
 * A gap in `seq` is a deleted line: provable, because nobody else can sign the
 * missing number, so the rest of the file still verifies and the gap is
 * reported. Lines missing at the very end cannot be detected - the device
 * stops by power-off and there is no end marker.
 *
 * Pure Web Crypto, no device call: pass what getLoggerKey() and getLogEntry()
 * returned. Requires Ed25519 in Web Crypto (Chrome 137+ / Firefox 130+ / Node 18+).
 *
 * @param {string|Uint8Array} deviceKey  `key` from HEM.getLoggerKey() (base64), or its 32 bytes
 * @param {string} logText               The log file
 * @returns {Promise<{ok: boolean, lines: number, headers: number, rotations: number, lost: number,
 *           gaps: Array<{after: number, next: number}>, line?: number, reason?: string}>}
 *          `ok` is true when every line verifies and `seq` has no gap. `line`
 *          (1-based line of the file) and `reason` name the first failure:
 *          'format', 'cut_front', 'no_header', 'header', 'rotate', 'signature'.
 */
async function verifyLog(deviceKey, logText) {
  const report = { ok: false, lines: 0, headers: 0, rotations: 0, lost: 0, gaps: [] };
  const fail = (line, reason) => ({ ...report, line, reason });
  const ed25519 = (raw) => crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
  const devKey = await ed25519(deviceKey instanceof Uint8Array ? deviceKey : fromB64(deviceKey));

  let fileKey = null;       // the per-file key of the last header
  let rotated = null;       // the key a LOGGER_KEY_ROTATE line announced
  let prevSeq = null;
  const rows = logText.split('\n');
  for (let i = 0; i < rows.length; i++) {
    const line = rows[i].replace(/\r$/, '');
    if (!line || line[0] === '#') continue;
    const f = line.split('|');
    if (f.length !== 7) return fail(i + 1, 'format');

    const seq = parseInt(f[0], 16);
    if (prevSeq === null && seq !== 0) return fail(i + 1, 'cut_front');
    if (prevSeq !== null && seq !== prevSeq + 1) report.gaps.push({ after: prevSeq, next: seq });
    prevSeq = seq;

    if (f[2] === '0' && f[3] === '0' && f[4] === 'v2') {
      const cert = fromB64(f[5]);
      if (cert.length !== 96) return fail(i + 1, 'header');
      const pub = cert.subarray(0, 32);
      if (!await crypto.subtle.verify({ name: 'Ed25519' }, devKey, cert.subarray(32), pub)) return fail(i + 1, 'header');
      if (report.headers > 0 && !(rotated && bytesEqual(rotated, pub))) return fail(i + 1, 'rotate');
      fileKey = await ed25519(pub);
      rotated = null;
      report.headers++;
    }
    if (!fileKey) return fail(i + 1, 'no_header');

    const sig = fromB64(f[6]);
    const text = strToBytes(line.slice(0, line.lastIndexOf('|') + 1));
    if (sig.length !== 64 || !await crypto.subtle.verify({ name: 'Ed25519' }, fileKey, sig, text)) return fail(i + 1, 'signature');

    if (f[2] === LOG_KEY_ROTATE) { rotated = fromB64(f[5]); report.rotations++; }
    if (f[2] === LOG_EVENTS_LOST) {
      const d = fromB64(f[5]);
      if (d.length >= 4) report.lost += (d[0] | d[1] << 8 | d[2] << 16 | d[3] << 24) >>> 0;
    }
    report.lines++;
  }
  if (!report.lines) return fail(0, 'no_header');
  return { ...report, ok: report.gaps.length === 0 };
}

/**
 * Check that the device still holds the private half of the logger key it just
 * handed over: `/api/logger/key` answers with the public key, a fresh nonce and
 * that nonce's Ed25519 signature. Verifying a log file against a key nobody has
 * proved possession of shows only that the file is self-consistent, so do this
 * first and treat a false as "this device did not sign anything".
 *
 * @param {{key: string, nonce: string, nonce_signed: string}} loggerKey  getLoggerKey()'s answer
 * @param {Uint8Array} [expectedNonce]  The nonce passed to getLoggerKey(); the
 *   device must have signed exactly that, or the answer may be a replay
 * @returns {Promise<boolean>}
 */
async function verifyLoggerKey(loggerKey, expectedNonce = null) {
  const { key, nonce, nonce_signed: signature } = loggerKey ?? {};
  if (!key || !nonce || !signature) return false;
  if (expectedNonce && !bytesEqual(fromB64(nonce), expectedNonce)) return false;
  try {
    const pubKey = await crypto.subtle.importKey('raw', fromB64(key), { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'Ed25519' }, pubKey, fromB64(signature), fromB64(nonce));
  } catch {
    return false;      // a key that will not even import has not signed anything
  }
}

// --- /api/crypto/* shared options ---------------------------------------------

// Device limits. Exceeding either surfaces as an opaque HTTP 400, so the SDK
// checks them where the caller can still see which argument was at fault.
const MAX_CRYPTO_MSG = 2048;
const MAX_HKDF_FIELD = 128;
const HKDF_RESERVED = strToBytes('encedo-');   // prefix of the device's own HKDF labels

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

/**
 * Write the optional HKDF salt and context (`hkdf_salt`, `hkdf_ctx`). With a
 * peer key the device derives the operation key by HKDF over the ECDH secret;
 * the context domain-separates that key and the salt varies it, and both must
 * be repeated verbatim to get the same key back. Each is 1..128 bytes; a
 * context starting with `encedo-` is reserved for the device's own labels.
 * Ignored by the device without a peer key.
 */
function applyHkdf(body, opts, op) {
  for (const [name, field] of [['hkdfSalt', 'hkdf_salt'], ['hkdfCtx', 'hkdf_ctx']]) {
    const v = opts[name];
    if (v === null || v === undefined) continue;
    const bytes = v instanceof Uint8Array ? v : strToBytes(v);
    if (bytes.length < 1 || bytes.length > MAX_HKDF_FIELD) {
      throw new HemError(`${op}: ${name} is ${bytes.length} bytes, must be 1..${MAX_HKDF_FIELD}`, { code: 'invalid_arg' });
    }
    if (field === 'hkdf_ctx' && bytesEqual(bytes.subarray(0, HKDF_RESERVED.length), HKDF_RESERVED)) {
      throw new HemError(`${op}: hkdfCtx may not start with "encedo-" (reserved)`, { code: 'invalid_arg' });
    }
    body[field] = toB64(bytes);
  }
}

/** Bytes as given, or a string as UTF-8. */
function asBytes(v) {
  return v instanceof Uint8Array ? v : strToBytes(String(v));
}

const b64OrNull = (v) => (typeof v === 'string' && v ? fromB64(v) : null);

/**
 * @typedef {object} KeyEntry
 * @property {string} kid            32 hex characters
 * @property {string} label
 * @property {string} type           The key type, e.g. 'SECP256R1', 'AES256', 'GENERIC_DER'
 * @property {string[]} flags        Device flags: 'ATT' (made inside the HEM), 'PKEY'
 *                                   (private half stored), 'ECDH', 'ExDSA', 'CERT', 'PQC', 'HPKE'
 * @property {Uint8Array|null} description
 * @property {number|null} created   Unix seconds
 * @property {number|null} updated
 * @property {Uint8Array|null} pubkey  When the call asked for it (or getKeyPublicInfo)
 * @property {Uint8Array|null} der     Certificate records, getKeyPublicInfo only
 */

/**
 * One key as the SDK hands it out, from a list, search, get, create or derive
 * answer. The device's `type` is the flags and the type joined by commas
 * ('ATT,PKEY,ECDH,ExDSA,SECP256R1'); it is split here so no caller has to.
 */
function keyEntry(e) {
  const parts = String(e.type ?? '').split(',').filter(Boolean);
  return {
    kid: e.kid ?? '',
    label: e.label ?? '',
    type: parts.at(-1) ?? '',
    flags: parts.slice(0, -1),
    description: b64OrNull(e.descr),
    created: e.created ?? null,
    updated: e.updated ?? null,
    pubkey: b64OrNull(e.pubkey),
    der: b64OrNull(e.der),
  };
}

/** A list or search page; `listed` drives the paging (see listKeys). */
function keyPage(data, offset) {
  const list = (data.list ?? []).map(keyEntry);
  return {
    list,
    offset: data.offset ?? offset,
    total: data.total ?? list.length,
    listed: data.listed ?? list.length,
    deleted: data.deleted ?? 0,
    invalid: data.invalid ?? 0,
  };
}

function checkMsgSize(op, data) {
  if (data.length > MAX_CRYPTO_MSG) {
    throw new HemError(`${op}: message is ${data.length} bytes, max ${MAX_CRYPTO_MSG}`,
      { code: 'invalid_arg' });
  }
}

// --- Main class ---------------------------------------------------------------

/**
 * `mode` on a create, derive or import request says what an asymmetric key may
 * be used for (API 1.3, keymgmt/create, key types). The SDK sends it when, and
 * only when, the caller passes one, and checks it against this table first:
 * the device answers a mode that does not fit the type with a bare 400.
 *
 * - NIST curves: 'ECDH', 'ExDSA' or both; P-256/384/521 also 'HPKE' alone
 *   (an HPKE-only key pair, DEV-503). No mode: neither flag.
 * - ED25519 signs; 'ECDH' adds key agreement (the key is used as X25519).
 * - CURVE25519 / CURVE448 agree keys; 'HPKE' makes them HPKE-only instead.
 * - ML-KEM: 'HPKE' makes an HPKE-only key.
 * - Everything else (ED448, ML-DSA, HMAC, OTP, AES) takes no mode.
 *
 * Import takes no 'HPKE': a public key needs no flag to be sealed to.
 */
const NIST_MODES = ['ECDH', 'ExDSA', 'ECDH,ExDSA'];
const KEY_MODES = {
  SECP256R1: [...NIST_MODES, 'HPKE'], SECP384R1: [...NIST_MODES, 'HPKE'], SECP521R1: [...NIST_MODES, 'HPKE'],
  SECP256K1: NIST_MODES,
  ED25519: ['ExDSA', 'ECDH', 'ECDH,ExDSA'],
  CURVE25519: ['ECDH', 'HPKE'], CURVE448: ['ECDH', 'HPKE'],
  MLKEM512: ['HPKE'], MLKEM768: ['HPKE'], MLKEM1024: ['HPKE'],
};

/** Throw `bad_mode` before the request when a mode does not fit the key type. */
function checkMode(type, mode, { importing = false } = {}) {
  if (!mode) return;
  const allowed = (KEY_MODES[type] ?? []).filter(m => !(importing && m === 'HPKE'));
  if (allowed.includes(mode)) return;
  throw new HemError(
    allowed.length
      ? `A key of type ${type} takes mode ${allowed.map(m => `'${m}'`).join(', ')}, not '${mode}'`
      : `A key of type ${type} takes no mode, got '${mode}'`,
    { code: 'bad_mode' });
}

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

  /**
   * What this session can still do without asking the user again: one entry per
   * cached scope, with the second it stops working. The JWTs themselves stay in
   * here — a page has no use for them, and something that can be shown on screen
   * or written to a log should not be a bearer token.
   *
   * @returns {Array<{scope: string, exp: number}>}
   */
  get tokens() {
    this.#cachePurge();
    return this.#tokenCache.map(({ scope, exp }) => ({ scope, exp }));
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
   * @param {object} [opts]
   * @param {boolean} [opts.remember=true]  Keep the derived key for the scopes
   *   that follow. With `false` it is used for this call alone and the next
   *   scope needs the password typed again — v1's "save password for this
   *   session", unticked. Tokens are cached either way.
   * @returns {Promise<string>}  JWT token
   */
  async authorizePassword(password, scope, expSeconds = 300, { remember = true } = {}) {
    const cached = this.#cacheFind(scope);
    if (cached) return cached;

    // Phase 1 -- get challenge (always needed for fresh jti + spk)
    const challenge = await this.#req('GET', `${this.#baseUrl}/api/auth/token`);
    // { eid: string (stable salt), spk: base64 (device X25519 pubkey), jti: string (nonce) }

    // Derive X25519 keys from the password, or reuse what a previous call kept.
    // Whether to keep them is the caller's to decide: a UI that offers "remember
    // the password for this session" keeps them and never asks again, one that
    // does not asks for every scope, and with `remember: false` the key lives no
    // longer than this call. Tokens are cached either way, so the same scope is
    // not asked about twice.
    let keys = this.#derivedKeys;
    if (password) {
      keys = await this.#deriveX25519(password, challenge.eid);
      if (remember) this.#derivedKeys = keys;
      // Note: JS strings are immutable — the password primitive cannot be zeroed here.
      // The caller should not hold a long-lived reference to it.
    }
    if (!keys) {
      throw new HemError('Password required (no cached keys)', { code: 'auth_password_required' });
    }
    return this.#authorizeWithKeys(keys, challenge, scope, expSeconds);
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
    // No cache read here, deliberately. A cached token for this scope may have
    // come from the password, and a caller asking to authorise with the master
    // secret is asking for that key in particular — handing back a token the
    // words never touched would be a lie about who authorised what. The result
    // is cached, so what follows still reuses it.
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
   *   2. POST /api/auth/ext/request { epk, scope, ctx?, note? } -> challenge
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
   * @param {string} [opts.ctx]        1..64 chars, copied into the token
   * @param {string} [opts.note]       1..128 chars shown with the request on the phone
   * @param {number} [opts.pollInterval=2000]  Poll interval in ms
   * @param {number} [opts.pollTimeout=60000]  Max wait time in ms
   * @param {Function} [opts.onPending]        Called each poll while waiting (no args)
   * @param {Function} [opts.onEvent]          Called once with the broker event id
   * @param {AbortSignal} [opts.signal]        Cancels the wait
   * @returns {Promise<string>}  JWT token
   */
  async authorizeRemote(scope, {
    ctx = null,
    note = null,
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

    // Step 2: the device seals the scope for every paired phone. How long the
    // token lives is the phone's answer (`exp` of its authreply), not ours.
    const request = { ...session, scope };
    if (ctx) request.ctx = ctx;
    if (note) request.note = note;
    const challenge = await this.#req('POST', `${this.#baseUrl}/api/auth/ext/request`, request);

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
  //
  // Field rules (API 1.3): a label is 1..64 printable ASCII characters
  // (0x20..0x7E); a description is a byte field of up to 128 bytes, carried as
  // base64 - the SDK takes and returns it as a Uint8Array (a string is taken as
  // UTF-8 text). The SDK polices neither; the device answers 400 to what will
  // not fit. Every key entry the SDK returns has the same shape, see keyEntry().

  /**
   * Generate a new key inside the HEM from its RNG. The private half, or the
   * secret of a symmetric key, never leaves the device.
   *
   * Required scope: 'keymgmt:gen'
   *
   * @param {string} token
   * @param {string} label  1..64 printable ASCII
   * @param {string} type   'SECP256R1', 'ED25519', 'CURVE25519', 'MLKEM768',
   *                        'MLDSA65', 'SHA2-256', 'SHA1', 'AES256', ... (API key types)
   * @param {object} [opts]
   * @param {Uint8Array|string} [opts.descr]  Description, up to 128 bytes
   * @param {string} [opts.mode]  What the key may do, see KEY_MODES: 'ECDH',
   *   'ExDSA', 'ECDH,ExDSA' or 'HPKE'. Only the types that can do more than one
   *   thing take one; a mode that does not fit the type throws `bad_mode`.
   * @param {boolean} [opts.returnPubkey=false]  Return the public key with the answer
   * @returns {Promise<KeyEntry>}  The key as stored; `pubkey` only when asked for
   */
  async createKeyPair(token, label, type, { descr = null, mode = null, returnPubkey = false } = {}) {
    checkMode(type, mode);
    const body = { type, label };
    if (descr !== null) body.descr = toB64(asBytes(descr));
    if (mode) body.mode = mode;
    if (returnPubkey) body.return_pubkey = true;
    return keyEntry(await this.#req('POST', `${this.#baseUrl}/api/keymgmt/create`, body, token));
  }

  /**
   * Store someone else's public key. It gets no private half and no `ATT`
   * flag; ECDH, verify, ML-KEM encapsulation and HPKE sealing work against it.
   *
   * Required scope: 'keymgmt:imp'
   *
   * @param {string} token
   * @param {string} label
   * @param {string} type    'SECP256R1/384R1/521R1/256K1', 'CURVE25519', 'CURVE448',
   *                         'ED25519', 'ED448', 'MLKEM512/768/1024', 'MLDSA44/65/87'
   * @param {Uint8Array} pubkey  Exactly the size of the type: SECP* compressed
   *   SEC1 point (33 / 49 / 67 / 33 B), X25519 32, X448 56, Ed25519 32, Ed448 57,
   *   ML-KEM 800 / 1184 / 1568, ML-DSA 1312 / 1952 / 2592
   * @param {object} [opts]
   * @param {Uint8Array|string} [opts.descr]
   * @param {string} [opts.mode]  SECP*: 'ECDH', 'ExDSA' or both; ED25519: 'ECDH'
   * @returns {Promise<{kid: string}>}
   */
  async importPublicKey(token, label, type, pubkey, { descr = null, mode = null } = {}) {
    checkMode(type, mode, { importing: true });
    const body = { type, label, pubkey: toB64(pubkey) };
    if (descr !== null) body.descr = toB64(asBytes(descr));
    if (mode) body.mode = mode;
    return this.#req('POST', `${this.#baseUrl}/api/keymgmt/import`, body, token);
  }

  /**
   * Derive a new key inside the HEM and store it (no `ATT` flag). The input is
   * either the ECDH secret of the stored private key `kid` and a peer key
   * (`extKid` stored in the HEM, or raw `pubkey`), or - with no peer - the
   * stored HMAC key `kid` itself (SHA2-256/384/512), which builds a key
   * hierarchy from one secret. HKDF-SHA512, info `encedo-derive:v1:<type>`,
   * salt `hkdfSalt`: the same inputs always give the same key, and a host
   * holding the peer's private key computes it too.
   *
   * Required scope: 'keymgmt:derive' (or 'keymgmt:gen')
   *
   * @param {string} token
   * @param {string} label
   * @param {string} type  Target: SECP*, CURVE25519, CURVE448, ED25519, ED448,
   *                       SHA2-*, SHA3-*, SHA1, AES128/192/256 (not ML-KEM / ML-DSA)
   * @param {string} kid   ECDH private key, or the HMAC parent key
   * @param {object} [opts]
   * @param {string} [opts.extKid]  Peer public key stored in the HEM
   * @param {Uint8Array} [opts.pubkey]  Raw peer public key; not with extKid
   * @param {Uint8Array|string} [opts.hkdfSalt]  1..128 bytes
   * @param {Uint8Array|string} [opts.descr]
   * @param {string} [opts.mode]  As createKeyPair
   * @param {boolean} [opts.returnPubkey=false]
   * @returns {Promise<KeyEntry>}
   */
  async deriveKey(token, label, type, kid, { extKid = null, pubkey = null, hkdfSalt = null, descr = null, mode = null, returnPubkey = false } = {}) {
    checkMode(type, mode);
    const body = { type, label, kid };
    applyPeerKey(body, { extKid, pubkey }, 'deriveKey');
    if (hkdfSalt !== null) {
      const salt = asBytes(hkdfSalt);
      if (salt.length < 1 || salt.length > MAX_HKDF_FIELD) {
        throw new HemError(`deriveKey: hkdfSalt is ${salt.length} bytes, must be 1..${MAX_HKDF_FIELD}`, { code: 'invalid_arg' });
      }
      body.hkdf_salt = toB64(salt);
    }
    if (descr !== null) body.descr = toB64(asBytes(descr));
    if (mode) body.mode = mode;
    if (returnPubkey) body.return_pubkey = true;
    return keyEntry(await this.#req('POST', `${this.#baseUrl}/api/keymgmt/derive`, body, token));
  }

  /**
   * Replace a key's label and description; `updated` becomes now. The record
   * is rewritten, so the key moves to the end of the list. System records
   * (TLS key and certificate, EPA attestation key) are read-only: 409.
   *
   * Required scope: 'keymgmt:upd'
   *
   * @param {string} token
   * @param {string} kid
   * @param {string} label
   * @param {Uint8Array|string|null} [descr=null]  null removes the description
   * @returns {Promise<void>}
   */
  async updateKey(token, kid, label, descr = null) {
    const body = { kid, label };
    const bytes = descr === null ? null : asBytes(descr);
    if (bytes?.length) body.descr = toB64(bytes);
    await this.#req('POST', `${this.#baseUrl}/api/keymgmt/update`, body, token);
  }

  /**
   * One key's metadata and public part (`GET /api/keymgmt/get/<kid>`). No
   * private material ever comes back: an asymmetric key gives its public key,
   * a stored private-key DER (TLS key, EPA attestation key) its public point,
   * a certificate record its DER, a symmetric key metadata only.
   *
   * Required scope: 'keymgmt:get', 'keymgmt:gen' or 'keymgmt:use:<kid>'
   *
   * @param {string} token
   * @param {string} kid
   * @returns {Promise<KeyEntry>}  With `der` (Uint8Array) for a certificate record
   */
  async getKeyPublicInfo(token, kid) {
    const data = await this.#req('GET', `${this.#baseUrl}/api/keymgmt/get/${kid}`, null, token);
    return keyEntry({ ...data, kid });
  }

  /**
   * One page of the key repository, in storage order (a changed key moves to
   * the end). The device gives at most 15 entries a page, and fewer when it
   * includes public keys (a page ends after 3 PQC keys); the next page starts
   * at `offset + listed`, until that reaches `total`. Records that fail their
   * CRC take a slot (`invalid`) but are not in `list`.
   *
   * Required scope: 'keymgmt:list'
   *
   * @param {string} token
   * @param {object} [opts]
   * @param {number} [opts.offset=0]
   * @param {number} [opts.limit=15]  The device caps it at 15
   * @param {boolean} [opts.returnPubkey=false]  Add public keys - only on a device
   *   personalised with the `pubkey_in_list` policy, ignored without it
   * @returns {Promise<{list: KeyEntry[], total: number, listed: number, deleted: number, invalid: number, offset: number}>}
   */
  async listKeys(token, { offset = 0, limit = 15, returnPubkey = false } = {}) {
    const data = await this.#req('GET',
      `${this.#baseUrl}/api/keymgmt/list/${offset}/${limit}${returnPubkey ? '/pubkey' : ''}`, null, token);
    return keyPage(data, offset);
  }

  /**
   * Keys whose description matches a byte pattern, with optional filters. The
   * page rules are those of listKeys(), except that `total` counts every
   * record, not the matches: read on from `offset + listed` until a page comes
   * back empty.
   *
   * Without a token the device answers only a prefix search of at least 6
   * bytes, and only when `allow_keysearch` is on; public keys are then left out.
   *
   * Required scope: one of 'keymgmt:search', 'keymgmt:list', 'auth:ext:pair'
   *
   * @param {string|null} token  null for an anonymous search
   * @param {Uint8Array|string} pattern  1..128 bytes; a string is UTF-8
   * @param {object} [opts]
   * @param {'prefix'|'suffix'|'contains'} [opts.match='prefix']
   * @param {number} [opts.offset=0]  Matches to skip
   * @param {number} [opts.limit=15]
   * @param {string} [opts.type]  Only keys of this type, e.g. 'ED25519'
   * @param {string} [opts.mode]  Only keys with these flags: 'ECDH', 'ExDSA', 'ECDH,ExDSA', 'HPKE'
   * @param {boolean} [opts.returnPubkey=false]  Add public keys (`pubkey_in_search` policy)
   * @returns {Promise<{list: KeyEntry[], total: number, listed: number, deleted: number, invalid: number, offset: number}>}
   */
  async searchKeys(token, pattern, { match = 'prefix', offset = 0, limit = 15, type = null, mode = null, returnPubkey = false } = {}) {
    const b64 = toB64(asBytes(pattern));
    const descr = match === 'prefix' ? '^' + b64 : match === 'suffix' ? b64 + '$' : b64;
    const body = { descr, offset, limit };
    if (type) body.type = type;
    if (mode) body.mode = mode;
    if (returnPubkey) body.return_pubkey = true;
    const data = await this.#req('POST', `${this.#baseUrl}/api/keymgmt/search`, body, token);
    return keyPage(data, offset);
  }

  /**
   * Delete a key - any record, the TLS key and certificate and a paired
   * phone's key (which unpairs it) included.
   *
   * Required scope: 'keymgmt:del'
   *
   * @param {string} token
   * @param {string} kid
   * @returns {Promise<void>}
   */
  async deleteKey(token, kid) {
    await this.#req('DELETE', `${this.#baseUrl}/api/keymgmt/delete/${kid}`, null, token);
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
   * Verify an EdDSA/ECDSA signature with a key in the HEM (a key pair or an
   * imported public key). The device answers 200 for every well-formed
   * request and puts the result in the body: this resolves to that result.
   * Any other status (unknown key, wrong curve for `alg`, bad length) throws.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token  Bearer JWT
   * @param {string}     kid    Key ID (32-char hex) of the public key in HSM
   * @param {Uint8Array} data   Raw bytes that were signed
   * @param {Uint8Array} sig    Raw signature bytes (64 bytes for Ed25519)
   * @param {string}     [alg='Ed25519']
   * @returns {Promise<boolean>}  true: the signature is valid; false: it is not
   */
  async exdsaVerify(token, kid, data, sig, alg = 'Ed25519') {
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/exdsa/verify`,
      { kid, alg, msg: toB64(data), sign: toB64(sig) }, token);
    return ret?.verified === true;
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
    // Raw: as long as the curve (X25519 / P-256 / secp256k1 32 B, P-384 48,
    // P-521 66, X448 56); hashed: as long as the digest.
    return fromB64(ret.ecdh);
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
   * Verify an HMAC on the HEM. Resolves to the device's `verified`: false for
   * a wrong MAC, and also when the key or peer cannot make one - the
   * comparison happens inside the device, so the caller never has to write a
   * constant-time compare. Any status other than 200 throws.
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
   * @returns {Promise<boolean>}  true: the MAC matches
   */
  async hmacVerify(token, kid, data, mac, alg = null, opts = {}) {
    checkMsgSize('hmacVerify', data);
    const body = { kid, msg: toB64(data), mac: toB64(mac) };
    if (alg !== null) body.alg = alg;
    applyPeerKey(body, opts, 'hmacVerify');
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/hmac/verify`, body, token);
    return ret?.verified === true;
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
   * @param {Uint8Array} data   Plaintext bytes, 1..2048
   * @param {string}     alg    'AES128-CBC' ... 'AES256-GCM' or 'CHACHA20-POLY1305' (a 256-bit
   *                            key: an AES256 key in the HEM). No ECB.
   * @param {object} [opts]
   * @param {string|null} [opts.extKid=null]  Peer public key already in the HSM
   * @param {Uint8Array|string|null} [opts.pubkey=null]  Raw peer public key; not with extKid
   * @param {Uint8Array|null} [opts.aad=null]  Additional authenticated data (GCM only)
   * @param {Uint8Array|string|null} [opts.hkdfCtx=null]   HKDF context (info), 1..128 bytes; peer-key modes only
   * @param {Uint8Array|string|null} [opts.hkdfSalt=null]  HKDF salt, 1..128 bytes; peer-key modes only
   * @returns {Promise<{ciphertext: Uint8Array, iv: Uint8Array, tag: Uint8Array|null}>}
   */
  async cipherEncrypt(token, kid, data, alg, opts = {}) {
    checkMsgSize('cipherEncrypt', data);
    const body = { kid, msg: toB64(data), alg };
    applyPeerKey(body, opts, 'cipherEncrypt');
    applyHkdf(body, opts, 'cipherEncrypt');
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
    applyHkdf(body, opts, 'cipherDecrypt');
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
   * @param {Uint8Array|string|null} [opts.hkdfCtx=null]   HKDF context (info), 1..128 bytes; peer-key modes only
   * @param {Uint8Array|string|null} [opts.hkdfSalt=null]  HKDF salt, 1..128 bytes; peer-key modes only
   * @param {Uint8Array|null} [opts.iv=null]             Explicit IV; omit for the default
   * @returns {Promise<Uint8Array>}  Wrapped key bytes
   */
  async cipherWrap(token, kid, alg, data, opts = {}) {
    checkMsgSize('cipherWrap', data);
    const body = { kid, alg, msg: toB64(data) };
    applyPeerKey(body, opts, 'cipherWrap');
    applyHkdf(body, opts, 'cipherWrap');
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
    applyHkdf(body, opts, 'cipherUnwrap');
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
   * ML-DSA (post-quantum) signature verification on the HEM, with a key pair
   * or an imported public key. Resolves to the device's `verified` (false also
   * when the signature has the wrong size, or the engine stayed busy for 30 s);
   * any status other than 200 throws.
   *
   * Required scope: 'keymgmt:use:<KID>'
   *
   * @param {string}     token  Bearer JWT
   * @param {string}     kid    Key ID (32-char hex) of the ML-DSA key
   * @param {Uint8Array} data   Raw bytes that were signed
   * @param {Uint8Array} sign   Signature bytes
   * @returns {Promise<boolean>}  true: the signature is valid
   */
  async mldsaVerify(token, kid, data, sign) {
    const ret = await this.#req('POST', `${this.#baseUrl}/api/crypto/pqc/mldsa/verify`,
      { kid, msg: toB64(data), sign: toB64(sign) }, token);
    return ret?.verified === true;
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
   * @param   {string}      [opts.token]      Any valid token: adds `sd_csd` / `sd_cid` on an initialised PPA
   * @returns {Promise<{hwv: string, fwv: string, fwk: string, fws: string, fwc?: string,
   *          blv?: string, blk?: string, bls?: string, blc?: string, uis?: string,
   *          sd_csd?: string, sd_cid?: string}>}  `fwc` / `blc` (release CIDs) only in
   *          release builds; the bootloader fields only when its publisher is the firmware's
   */
  async getVersion({ token = null, ...opts } = {}) {
    return this.#req('GET', `${this.#baseUrl}/api/system/version`, null, token, opts);
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
   * Change the password this device is unlocked with. The new password never
   * travels: what goes over is the X25519 public key it derives to, and a proof
   * that whoever sent it can also do ECDH with the device — an HMAC of the
   * device's own nonce under the shared secret. A module that took a public key
   * without that proof would take one from anybody who could reach this endpoint.
   *
   * The master passphrase is not touched: this is the everyday password, and the
   * 24 words still open the device if it is forgotten.
   *
   * Required scope: 'system:config'
   *
   * @param {string} token        Bearer JWT
   * @param {string} newPassword
   * @returns {Promise<object>}
   */
  async setUserPassword(token, newPassword) {
    const cfg = await this.getConfig(token);
    const { eid, spk, nonce } = cfg;
    if (!eid || !spk || !nonce) {
      throw new HemError('The device did not send eid, spk and nonce to change a password against', { code: 'config_incomplete' });
    }
    const user = await this.#deriveX25519(newPassword, eid);
    const shared = await x25519(user.privKey, fromB64(spk));
    const hmacKey = await crypto.subtle.importKey('raw', shared, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, fromB64(nonce)));
    return this.setConfig(token, {
      userkey: user.pubkeyB64,
      userkey_nonce: nonce,
      userkey_hmac: toB64(mac),
    });
  }

  /**
   * Read the device configuration, with `spk` and `nonce` for a password change.
   *
   * Required scope: 'system:config', 'logger:get' or 'auth:ext:pair'
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
   * Reboot the device (~2 s after the answer). Refused with 409 while software
   * is being installed. Before personalisation no token is needed.
   *
   * Required scope: 'system:config', 'system:upgrade' or 'system:shutdown'
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<object>}
   */
  async reboot(token) {
    return this.#req('GET', `${this.#baseUrl}/api/system/reboot`, null, token);
  }

  /**
   * Stop the device's services: the USB device and the worker that served the
   * request. A token is always needed.
   *
   * Required scope: 'system:config' or 'system:shutdown'
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<object>}
   */
  async shutdown(token) {
    return this.#req('GET', `${this.#baseUrl}/api/system/shutdown`, null, token);
  }

  /**
   * Run the self-tests (also those disabled by `cc_mode`) and read the key
   * repository statistics. The known-answer tests run in the background: the
   * answer carries `kat_busy` while one is still running. A second call while
   * a run is in progress gets 409.
   *
   * Required scope: 'system:config' (before personalisation: no token)
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<object>}
   */
  async selftest(token) {
    return this.#req('GET', `${this.#baseUrl}/api/system/selftest`, null, token);
  }

  // -- Firmware / UI Upgrade ---------------------------------------------------

  /**
   * Restart the device into the bootloader's low-level USB mode (~2 s after
   * the answer). It leaves the running firmware: the module is gone until the
   * bootloader is done with it.
   *
   * Required scope: 'system:upgrade' or 'system:config'
   *
   * @param {string|null} token  Bearer JWT (none before personalisation)
   * @returns {Promise<void>}
   */
  async rebootToUsbMode(token) {
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
   * The device takes the image under one of two names only, `firmware.bin`
   * (raw) or `firmware.hex` (Intel HEX), and below 3 MiB. The SDK picks the
   * name from the content - Intel HEX text starts with `:` - unless `format`
   * says otherwise.
   *
   * @param {string|null} token      Bearer JWT (none before personalisation)
   * @param {Uint8Array}  bytes      The image
   * @param {object}      [opts]
   * @param {'bin'|'hex'} [opts.format]  Default: from the first byte
   * @param {Function}    [opts.onProgress]  (loaded, total) in bytes -- browser only
   * @param {AbortSignal} [opts.signal]      Cancels the upload
   * @returns {Promise<void>}
   */
  async uploadFirmware(token, bytes, { format = null, onProgress = null, signal = null } = {}) {
    const hex = format ? format === 'hex' : bytes[0] === 0x3a;
    await this.#req('POST', `${this.#baseUrl}/api/system/upgrade/upload_fw`,
      bytes, token, { binary: true, filename: hex ? 'firmware.hex' : 'firmware.bin', onProgress, signal });
  }

  /**
   * Verify the firmware image previously uploaded with uploadFirmware(). The
   * device checks the signature in the background: it answers 201 or 202 while
   * it is still at it, and this resolves null then — 200 with the result once
   * it is done. waitFirmwareCheck() does the polling.
   *
   * Required scope: 'system:upgrade'
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<object|null>}  null while the device is still checking
   */
  async checkFirmware(token, { signal = null } = {}) {
    const r = await this.#req('GET', `${this.#baseUrl}/api/system/upgrade/check_fw`, null, token, { signal, withStatus: true });
    return r.status === 200 ? r.data : null;
  }

  /**
   * Poll checkFirmware() until the device has verified the image. Rejects with
   * HemError `timeout`, `aborted`, or whatever the device answered (a 4xx means
   * the image did not verify).
   *
   * @param {string} token
   * @param {object} [opts]  pollInterval (4 s), pollTimeout (3 min), onPending, signal
   * @returns {Promise<object>}  The device's answer to the check
   */
  waitFirmwareCheck(token, { pollInterval = 4_000, pollTimeout = 180_000, onPending = null, signal = null } = {}) {
    return pollUntil(() => this.checkFirmware(token, { signal }), 'The firmware check did not finish in time', { pollInterval, pollTimeout, onPending, signal });
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
   * Upload a signed Manager archive (PPA). The device stores it as
   * `webroot.tar`, the only name it accepts, for checkUi() / installUi().
   * See uploadFirmware() for how to obtain the bytes.
   *
   * Required scope: 'system:upgrade'
   *
   * @param {string|null} token      Bearer JWT (none before personalisation)
   * @param {Uint8Array}  bytes      The signed tar
   * @param {object}      [opts]     onProgress, signal - as uploadFirmware()
   * @returns {Promise<void>}
   */
  async uploadUi(token, bytes, { onProgress = null, signal = null } = {}) {
    await this.#req('POST', `${this.#baseUrl}/api/system/upgrade/upload_ui`,
      bytes, token, { binary: true, filename: 'webroot.tar', onProgress, signal });
  }

  /**
   * Verify the UI bundle previously uploaded with uploadUi(). As with
   * checkFirmware(): null while the device is still checking, the result once
   * it is done; waitUiCheck() polls.
   *
   * Required scope: 'system:upgrade'
   *
   * @param {string} token  Bearer JWT
   * @returns {Promise<object|null>}
   */
  async checkUi(token, { signal = null } = {}) {
    const r = await this.#req('GET', `${this.#baseUrl}/api/system/upgrade/check_ui`, null, token, { signal, withStatus: true });
    return r.status === 200 ? r.data : null;
  }

  /** Poll checkUi() until the device has verified the bundle; see waitFirmwareCheck(). */
  waitUiCheck(token, { pollInterval = 4_000, pollTimeout = 180_000, onPending = null, signal = null } = {}) {
    return pollUntil(() => this.checkUi(token, { signal }), 'The UI bundle check did not finish in time', { pollInterval, pollTimeout, onPending, signal });
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
   * The device log key (Ed25519) and its signature over a nonce. The log key
   * certifies the per-file keys that sign every log line (verifyLog()).
   * Pass a fresh `nonce` of your own to make the answer a proof that the
   * device holds the key now; without one the device signs a time-based nonce
   * of its own, which can be replayed. verifyLoggerKey() checks the answer.
   *
   * Required scope: 'logger:get'
   *
   * @param {string} token
   * @param {object} [opts]
   * @param {Uint8Array} [opts.nonce]  32..64 random bytes
   * @returns {Promise<{key: string, nonce: string, nonce_signed: string}>}  base64
   */
  async getLoggerKey(token, { nonce = null } = {}) {
    if (nonce && (nonce.length < 32 || nonce.length > 64)) {
      throw new HemError(`getLoggerKey: nonce is ${nonce.length} bytes, must be 32..64`, { code: 'invalid_arg' });
    }
    const path = nonce ? `/api/logger/key/${toB64url(nonce)}` : '/api/logger/key';
    return this.#req('GET', `${this.#baseUrl}${path}`, null, token);
  }

  /**
   * One page of the downloadable log files (PPA): one file per power-up, id =
   * the power-up time as 8 hex digits, so sorting by id sorts by time. The
   * file of the current session is still being written; it is not listed and
   * its id comes back as `current`.
   *
   * Required scope: 'logger:get'
   *
   * @param {string} token
   * @param {object} [opts]
   * @param {number} [opts.offset=0]
   * @param {number} [opts.limit=128]  The device caps it at 128
   * @returns {Promise<{id: string[], offset: number, total: number, listed: number,
   *          oldest?: string, newest?: string, current?: string}>}
   */
  async listLogFiles(token, { offset = 0, limit = 128 } = {}) {
    return this.#req('GET', `${this.#baseUrl}/api/logger/list/${offset}/${limit}`, null, token);
  }

  /**
   * Download one log file as text (PPA). The file the device is writing gives
   * HTTP 409 (`http_409`): it is not listed, but an id can still be asked for.
   *
   * Required scope: 'logger:get'
   *
   * @param {string} token
   * @param {string} id  8 hex digits, from listLogFiles()
   * @returns {Promise<string>}
   */
  async getLogFile(token, id) {
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
   * @param {number} [opts.pollInterval=4000]  While an e-mail confirmation is waited for
   * @param {number} [opts.pollTimeout=240000]
   * @param {Function} [opts.onPending]        Called with the registration status each poll
   * @param {AbortSignal} [opts.signal]
   * @returns {Promise<object>}  The tls block installed on the device
   */
  async registerDomain(token, prefix, { ip = null, newCertificate = true, pollInterval = 4_000, pollTimeout = 240_000, onPending = null, signal = null } = {}) {
    let genuine, csr = null;
    if (newCertificate) {
      const req = await this.#req('POST', `${this.#baseUrl}/api/system/config`, { gen_csr: true }, token);
      genuine = req.genuine;
      csr = req.csr;
    }
    // The device attestation of an initialised module comes from
    // config/attestation (any token); the auth challenge carries none.
    if (!genuine) genuine = (await this.getAttestation(token)).genuine;
    if (!genuine) throw new HemError('No attestation (genuine) available for domain registration', { code: 'domain_error' });

    let tls = await this.#broker.domainRegister(prefix, { genuine, csr, ip });
    // A prefix of the owner's choosing is confirmed by e-mail first: the broker
    // answers with an id, and the tls block follows once the owner has clicked.
    if (!tls?.crt && tls?.id) tls = await this.#broker.waitDomain(tls.id, { pollInterval, pollTimeout, onPending, signal });
    await this.#req('POST', `${this.#baseUrl}/api/system/config`, { tls }, token);
    return tls;
  }

  // -- Audit log verification --------------------------------------------------

  /**
   * Fetch one log file and verify it against the device log key, after the
   * device has proved it holds that key by signing a fresh nonce of ours.
   * See verifyLog() for the format and the result; `keyProven` false means the
   * key did not sign the nonce, so a verified file proves nothing about this device.
   *
   * Required scope: 'logger:get'
   *
   * @param {string} token
   * @param {string} id   From listLogFiles()
   * @returns {Promise<{ok: boolean, keyProven: boolean, text: string, [k: string]: any}>}
   */
  async verifyLogFile(token, id) {
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const loggerKey = await this.getLoggerKey(token, { nonce });
    const keyProven = await verifyLoggerKey(loggerKey, nonce);
    const text = await this.getLogFile(token, id);
    const result = await verifyLog(loggerKey.key, typeof text === 'string' ? text : JSON.stringify(text));
    return { ...result, ok: result.ok && keyProven, keyProven, text };
  }

}

export { Broker, HEM, HemError, entropyToMnemonic, generateMnemonic, jwtParse, mnemonicToEntropy, validateMnemonic, verifyLog, verifyLoggerKey };
//# sourceMappingURL=hem-sdk.browser.js.map
