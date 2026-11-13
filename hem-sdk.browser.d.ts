export declare class HemError extends Error {
  code: string;
  status: number;
  data: unknown;
}

/** Decode a JWT payload without verifying it. Returns null on malformed input. */
export declare function jwtParse(jwt: string): Record<string, any> | null;

/** verifyLog()'s answer for an audit-log file in format v2 (firmware 1.3+). */
export interface LogVerification {
  /** Every line verifies and `seq` has no gap. */
  ok: boolean;
  /** Lines verified (all of them when ok). */
  lines: number;
  /** Header lines: the first one and one per key rotation. */
  headers: number;
  rotations: number;
  /** Events the device dropped, from LOGGER_EVENTS_LOST lines. */
  lost: number;
  /** Deleted lines: `seq` jumps from `after` to `next`. Everything else still verifies. */
  gaps: Array<{ after: number; next: number }>;
  /** 1-based line of the file that failed, with `reason`. */
  line?: number;
  reason?: 'format' | 'cut_front' | 'no_header' | 'header' | 'rotate' | 'signature';
}

/** Verify an audit-log file (format v2) against the device log key (`key` from getLoggerKey(), base64 or bytes). */
export declare function verifyLog(deviceKey: string | Uint8Array, logText: string): Promise<LogVerification>;

/**
 * Verify that the device signed getLoggerKey()'s nonce, so the key is one it holds.
 * Pass the nonce given to getLoggerKey() as `expectedNonce`, or the answer may be a replay.
 */
export declare function verifyLoggerKey(loggerKey: { key: string; nonce: string; nonce_signed: string } | undefined, expectedNonce?: Uint8Array | null): Promise<boolean>;

/**
 * BIP39 master secret. The entropy behind the words IS the master X25519
 * private key, so the 24 words on a Proof of Personalization are the key.
 */
export declare function generateMnemonic(strengthBits?: number): Promise<string>;
export declare function entropyToMnemonic(entropy: Uint8Array): Promise<string>;
/** Throws HemError `mnemonic_invalid` (naming the word) or `mnemonic_checksum`. */
export declare function mnemonicToEntropy(mnemonic: string): Promise<Uint8Array>;
export declare function validateMnemonic(mnemonic: string): Promise<boolean>;

export interface PollOpts {
  pollInterval?: number;
  pollTimeout?: number;
  onPending?: () => void;
  signal?: AbortSignal;
}

/** MAC data from HEM.getExtAuthMac(); what the broker's paired-authenticator calls take. */
export interface ExtAuthMac {
  nonce: string;
  mac: string;
  eid: string;
  epk: string;
}

/**
 * The Encedo backend (api.encedo.com). Every call to it lives here; a device
 * behind an air gap never needs one. HEM composes these with device calls and
 * exposes its instance as `hem.broker`.
 */
export declare class Broker {
  constructor(url?: string, opts?: { debug?: boolean });
  readonly url: string;

  checkin(check: Record<string, unknown>): Promise<{ checked: string; [key: string]: unknown }>;
  /** With eid: the device's session, { epk, paired }. Without: an ephemeral session for one remote authorisation. */
  session(eid?: string | null): Promise<{ epk: string; paired?: boolean; [key: string]: unknown }>;

  eventNew(challenge: Record<string, unknown>): Promise<{ eventid: string }>;
  /** null while pending (HTTP 202). */
  eventCheck(eventid: string, opts?: { signal?: AbortSignal }): Promise<Record<string, unknown> | null>;
  eventDelete(eventid: string): Promise<unknown>;
  waitEvent(eventid: string, opts?: PollOpts): Promise<{ authreply?: string; deny?: boolean; [key: string]: unknown }>;

  registerInit(args: { epk: string; eid: string; request: string }): Promise<{ rid: string; link: string }>;
  registerCheck(rid: string, opts?: { signal?: AbortSignal }): Promise<{ pid: string; reply: string } | null>;
  registerFinalise(rid: string, confirmation: Record<string, unknown>): Promise<unknown>;
  waitRegistration(rid: string, opts?: PollOpts): Promise<{ pid: string; reply: string }>;

  subscribersList(mac: ExtAuthMac): Promise<Array<{ pid: string; [key: string]: unknown }>>;
  subscribersDelete(mac: ExtAuthMac & { pid: string }): Promise<unknown>;

  /** Image announced by hemCheckin() as `newfws` / `newuis`, as bytes. */
  download(kind: 'firmware' | 'dashboard', version: string, opts?: { signal?: AbortSignal; timeoutMs?: number }): Promise<Uint8Array>;

  domainPredefs(): Promise<{ prefix: string[] }>;
  /** true when `<prefix>.ence.do` is already registered (200); false on 404; other failures throw. */
  domainTaken(prefix: string): Promise<boolean>;
  domainRegister(prefix: string, args: { genuine: string; csr?: string | null; ip?: string | null }): Promise<{ emp: string; key: string; crt: string; [key: string]: unknown } | { id: string; status?: string }>;
  /** Status of a registration that answered 201 with an id; the tls block once `status` is 'done'. */
  domainStatus(id: string): Promise<{ status: 'pending' | 'email_confirmed' | 'done' | 'failed'; [key: string]: unknown }>;
  /** Poll domainStatus until done. Rejects with `domain_failed` or `timeout`. */
  waitDomain(id: string, opts?: PollOpts & { onPending?: (status: string) => void }): Promise<{ emp: string; key: string; crt: string; [key: string]: unknown }>;

  provisioning(args: { csr: string; key: string; genuine: string }): Promise<Record<string, unknown>>;
  shareEmailPubkey(email: string, shareCode: Record<string, unknown>, auth?: string): Promise<unknown>;
}

export interface HemKey {
  kid: string;
  label: string;
  /** The key type alone: 'SECP256R1', 'AES256', 'GENERIC_DER', ... */
  type: string;
  /** Device flags: 'ATT' (made inside the HEM), 'PKEY' (private half stored), 'ECDH', 'ExDSA', 'CERT', 'PQC', 'HPKE'. */
  flags: string[];
  /** The description field (up to 128 bytes), or null when it is empty. */
  description: Uint8Array | null;
  /** Unix seconds, when the device reports them. */
  created: number | null;
  updated: number | null;
  /** When the call asked for it (`returnPubkey`), and getKeyPublicInfo(). */
  pubkey: Uint8Array | null;
  /** Certificate records, getKeyPublicInfo() only. */
  der: Uint8Array | null;
}

/**
 * One page of listKeys() / searchKeys(). Read on from `offset + listed`: a page
 * holds at most 15 slots, fewer with public keys (3 PQC keys end a page), and
 * an unreadable record (`invalid`) takes a slot without being in `list`.
 * listKeys(): until that reaches `total`. searchKeys(): until a page is empty
 * (`total` counts every record, not the matches).
 */
export interface HemKeyPage {
  list: HemKey[];
  offset: number;
  total: number;
  listed: number;
  deleted: number;
  invalid: number;
}

/** 'ECDH', 'ExDSA', 'ECDH,ExDSA' or 'HPKE'; checked against the key type before the request (`bad_mode`). */
export type HemKeyMode = 'ECDH' | 'ExDSA' | 'ECDH,ExDSA' | 'HPKE';

/**
 * Peer-key selector shared by the /api/crypto/* endpoints. Setting either one
 * makes the device derive the operation's key by ECDH between `kid` and the
 * peer key instead of using `kid` directly; naming `kid`'s own public key
 * yields a key that never exists outside the device. Pass one, never both.
 */
export interface HemPeerKeyOpts {
  extKid?: string | null;
  /** Raw peer public key bytes (SECP* compressed 33/49/67 B, X25519 32, X448 56). */
  pubkey?: Uint8Array | null;
}

/** A peer that must be given (ecdh, ecdhHkdf): exactly one of the two. */
export type HemPeer =
  | { extKid: string; pubkey?: null }
  | { pubkey: Uint8Array; extKid?: null };

/** One HKDF output of ecdhHkdf(); hkdfLen 16..128, default the hash size. */
export interface HemHkdfItem {
  hkdfSalt?: Uint8Array | string | null;
  hkdfCtx?: Uint8Array | string | null;
  hkdfLen?: number | null;
}

/** A token scope: one value, or 1..8 distinct values (at most one storage:*). */
export type HemScope = string | string[];

export interface HemHkdfOpts extends HemPeerKeyOpts {
  /** HKDF context (info), 1..128 bytes, not starting with 'encedo-'; peer-key modes only. */
  hkdfCtx?: Uint8Array | string | null;
  /** HKDF salt, 1..128 bytes; peer-key modes only. */
  hkdfSalt?: Uint8Array | string | null;
}

export interface HemWrapOpts extends HemHkdfOpts {
  /** KEK size, default AES256. */
  alg?: 'AES128' | 'AES192' | 'AES256';
  /** 8 bytes; default the RFC 3394 IV. */
  iv?: Uint8Array | null;
}

export interface HemCipherOpts extends HemHkdfOpts {
  /** CBC 16 B, GCM 12 B, ChaCha20 12 B - decrypt only. */
  iv?: Uint8Array | null;
  /** Additional authenticated data, 1..256 bytes; GCM and ChaCha20-Poly1305. */
  aad?: Uint8Array | null;
  /** Authentication tag (GCM, ChaCha20-Poly1305) — decrypt only. */
  tag?: Uint8Array | null;
}

export type HemHpkeKem = 'DHKEM-P256' | 'DHKEM-P384' | 'DHKEM-P521' | 'DHKEM-X25519' | 'DHKEM-X448' | 'MLKEM512' | 'MLKEM768' | 'MLKEM1024' | 'X-Wing';

export interface HemHpkeOpts {
  /** Default: the KEM's suite. */
  kdf?: 'HKDF-SHA256' | 'HKDF-SHA384' | 'HKDF-SHA512' | null;
  aead?: 'AES128-GCM' | 'AES256-GCM' | 'CHACHA20-POLY1305' | null;
  /** 1..128 bytes. */
  info?: Uint8Array | string | null;
  /** 1..256 bytes. */
  aad?: Uint8Array | null;
}

export interface HemOtpOpts {
  mode?: 'TOTP' | 'HOTP';
  digits?: 6 | 8 | null;
  /** TOTP, 15..300 s. */
  period?: number | null;
  /** TOTP, unix seconds; default the device clock. */
  time?: number | null;
  /** HOTP, required. */
  counter?: number | null;
}

export interface HemCipherResult {
  ciphertext: Uint8Array;
  /** Generated by the device; required to decrypt. */
  iv: Uint8Array;
  /** GCM and ChaCha20-Poly1305. */
  tag: Uint8Array | null;
}

export declare class HEM {
  constructor(hsmUrl: string, opts?: { broker?: string | Broker; debug?: boolean });

  /** The Broker this instance uses for every api.encedo.com call. */
  readonly broker: Broker;

  /**
   * 3-step check-in (device, broker, device). Resolves with the device's
   * answer; `newfws` / `newuis` announce a newer firmware / UI image.
   * Throws `broker_error` or `network` when the broker is unreachable.
   */
  hemCheckin(): Promise<{ status: string; newfws?: string; newuis?: string; [key: string]: unknown }>;

  /** Pass null or '' to reuse cached derived keys (set on first call with a real password). */
  /** `remember: false` uses the derived key for this call alone; the next scope needs the password again. */
  /** A cached token answers for every scope it holds; `ctx` (1..64 chars) is copied into the token. */
  authorizePassword(password: string | null, scope: HemScope, opts?: { expSeconds?: number; remember?: boolean; ctx?: string | null } | null): Promise<string>;

  /**
   * Mobile push authorisation. Cancelling (`signal`) or timing out withdraws
   * the event from the broker; rejects with code `aborted`, `timeout` or `denied`.
   */
  authorizeRemote(scope: HemScope, opts?: PollOpts & {
    /** 1..64 chars (with `require` added), copied into the token. The token lifetime is the phone's answer. */
    ctx?: string | null;
    /** What the app must ask of its user, sent as `uv=bio` / `uv=pin` in ctx. A request; the token's actx says what it did. */
    require?: { uv?: 'bio' | 'pin' } | null;
    /** 1..128 chars shown with the request on the phone. */
    note?: string | null;
    /** Called once with the broker event id. */
    onEvent?: (eventid: string) => void;
  }): Promise<string>;

  /** An attestation JWT for the device (and a key with its PoP); Attest.prepare() makes `request`. Any valid token; with kid keymgmt:use:<kid>. */
  attest(token: string | null, request: AttestRequest): Promise<string>;
  /** Device certificate and attestation token; with `nonce` (32..64 B) the token is bound to this request. Any valid token. */
  getAttestation(token: string | null, opts?: { nonce?: Uint8Array | null }): Promise<{ genuine: string; crt?: string; csr?: string; key?: string }>;

  /**
   * Provision a factory-fresh device. Pass the master secret as `{ mnemonic }`
   * (from generateMnemonic) or `{ entropy }`; a password string still works.
   * masterkey/userkey are written into cfg automatically.
   */
  initialize(admin: string | { mnemonic: string } | { entropy: Uint8Array }, userPassword: string, cfg?: Record<string, unknown>): Promise<{
    instanceid: string; token: string; csr?: string; genuine?: string; reboot_required?: boolean;
  }>;

  /** Authenticate with the 24-word master secret. `legacy`: device personalised by the v1 Manager. */
  authorizeMaster(mnemonic: string, scope: HemScope, opts?: { expSeconds?: number; legacy?: boolean; ctx?: string | null } | null): Promise<string>;

  /** Broker MAC data for the paired-authenticator calls; listExtAuth / deleteExtAuth do the round trip. */
  getExtAuthMac(token: string): Promise<ExtAuthMac>;
  /** Authenticators paired with the device. Scope: system:config. */
  listExtAuth(token: string): Promise<Array<{ pid: string; [key: string]: unknown }>>;
  /** Unpair one authenticator on the broker; its keychain entry ('RVhUQUlE' + pid) is deleted with deleteKey(). */
  deleteExtAuth(token: string, pid: string): Promise<unknown>;
  /** Whether any authenticator is paired. No token needed. */
  hasExtAuth(): Promise<boolean>;

  /** Pair a mobile external authenticator. token needs the 'system:config' scope. */
  registerExtAuth(token: string, opts?: {
    /**
     * Called with (qrText, qrPayload). qrText is the exact JSON string to encode
     * into the QR code scanned by the mobile authenticator app.
     */
    onQrCode?: (
      qrText: string,
      qrPayload: { link: string; hash: string; user?: string; email?: string; hostname?: string },
    ) => void;
  } & PollOpts): Promise<unknown>;

  /** Scope: keymgmt:list. `returnPubkey` needs the `pubkey_in_list` policy. */
  listKeys(token: string, opts?: { offset?: number; limit?: number; returnPubkey?: boolean }): Promise<HemKeyPage>;
  /**
   * Keys whose description matches `pattern` (bytes, or a string as UTF-8). Scope: keymgmt:search,
   * keymgmt:list or auth:ext:pair; null for an anonymous prefix search of at least 6 bytes.
   */
  searchKeys(token: string | null, pattern: string | Uint8Array, opts?: {
    match?: 'prefix' | 'suffix' | 'contains'; offset?: number; limit?: number;
    type?: string | null; mode?: HemKeyMode | null; returnPubkey?: boolean;
  }): Promise<HemKeyPage>;
  /** Every key of listKeys(), across pages: `for await`, or `Array.fromAsync(...)`. Scope: keymgmt:list. */
  listKeysAll(token: string, opts?: { returnPubkey?: boolean }): AsyncGenerator<HemKey, void, undefined>;
  /** Every match of searchKeys(), across pages (until a page comes back empty). Scope: as searchKeys. */
  searchKeysAll(token: string | null, pattern: string | Uint8Array, opts?: {
    match?: 'prefix' | 'suffix' | 'contains'; type?: string | null; mode?: HemKeyMode | null; returnPubkey?: boolean;
  }): AsyncGenerator<HemKey, void, undefined>;
  /** Metadata and public part of one key; never private material. Scope: keymgmt:get, keymgmt:gen or keymgmt:use:<kid>. */
  getKeyPublicInfo(token: string, kid: string): Promise<HemKey>;
  /** Generate a key inside the HEM. Scope: keymgmt:gen. Label 1..64 ASCII, descr up to 128 bytes. */
  createKeyPair(token: string, label: string, type: string, opts?: { descr?: Uint8Array | string | null; mode?: HemKeyMode | null; returnPubkey?: boolean }): Promise<HemKey>;
  /** Store a public key (exact size for the type). Scope: keymgmt:imp. */
  importPublicKey(token: string, label: string, type: string, pubkey: Uint8Array, opts?: { descr?: Uint8Array | string | null; mode?: HemKeyMode | null }): Promise<{ kid: string }>;
  /** Derive from ECDH with a peer (extKid / pubkey) or, with no peer, from an HMAC parent `kid`. Scope: keymgmt:derive or keymgmt:gen. */
  deriveKey(token: string, label: string, type: string, kid: string, opts?: HemPeerKeyOpts & {
    hkdfSalt?: Uint8Array | string | null; descr?: Uint8Array | string | null; mode?: HemKeyMode | null; returnPubkey?: boolean;
  }): Promise<HemKey>;
  /** Replace label and description; null removes the description. Scope: keymgmt:upd. */
  updateKey(token: string, kid: string, label: string, descr?: Uint8Array | string | null): Promise<void>;
  /**
   * ECDSA (raw r ‖ s) or EdDSA signature. `data` is bytes or UTF-8 text; for alg 'ECDSA' the digest.
   * `ctx` (1..255 B) for Ed25519ctx / Ed25519ph / Ed448; `det` for RFC 6979 ECDSA.
   */
  exdsaSign(token: string, kid: string, data: Uint8Array | string, opts?: { alg?: string; ctx?: Uint8Array | string | null; det?: boolean } | null): Promise<Uint8Array>;
  /** The device's `verified`: false for an invalid signature. Other errors throw. */
  exdsaVerify(token: string, kid: string, data: Uint8Array | string, sig: Uint8Array, opts?: { alg?: string; ctx?: Uint8Array | string | null } | null): Promise<boolean>;
  /**
   * ECDH with a peer - `extKid` (stored) or `pubkey` (raw bytes), exactly one, as deriveKey names it.
   * No alg: the raw secret (needs the `raw_ecdh_enabled` policy); 'SHA2-*' / 'SHA3-*': its digest;
   * 'HKDF-SHA2-*': HKDF with hkdfSalt / hkdfCtx (info, not 'encedo-...') / hkdfLen (16..128).
   */
  ecdh(token: string, kid: string, opts: HemPeer & {
    alg?: string | null; hkdfSalt?: Uint8Array | string | null; hkdfCtx?: Uint8Array | string | null; hkdfLen?: number | null;
  }): Promise<Uint8Array>;
  /** One ECDH, 1..8 HKDF outputs; the shared secret never leaves the device. */
  ecdhHkdf(token: string, kid: string, opts: HemPeer & {
    alg?: 'HKDF-SHA2-256' | 'HKDF-SHA2-384' | 'HKDF-SHA2-512'; items: HemHkdfItem[];
  }): Promise<Uint8Array[]>;

  /** `alg` is required with a peer (extKid / pubkey). */
  hmacHash(token: string, kid: string, data: Uint8Array | string, opts?: HemPeerKeyOpts & { alg?: string | null } | null): Promise<Uint8Array>;
  /** The device's `verified`: false for a wrong MAC. Other errors throw. */
  hmacVerify(token: string, kid: string, data: Uint8Array | string, mac: Uint8Array, opts?: HemPeerKeyOpts & { alg?: string | null } | null): Promise<boolean>;
  /** 'AES128-CBC' ... 'AES256-GCM', 'CHACHA20-POLY1305'. */
  cipherEncrypt(token: string, kid: string, data: Uint8Array | string, alg: string, opts?: HemCipherOpts): Promise<HemCipherResult>;
  cipherDecrypt(token: string, kid: string, ciphertext: Uint8Array, alg: string, opts?: HemCipherOpts): Promise<Uint8Array>;
  /** AES key wrap (RFC 3394); data 16..2048 B, a multiple of 8. */
  cipherWrap(token: string, kid: string, data: Uint8Array, opts?: HemWrapOpts): Promise<Uint8Array>;
  cipherUnwrap(token: string, kid: string, wrapped: Uint8Array, opts?: HemWrapOpts): Promise<Uint8Array>;
  /** To a key made in the HEM or an imported public key. */
  mlkemEncaps(token: string, kid: string): Promise<{ alg: string; ss: Uint8Array; ct: Uint8Array }>;
  mlkemDecaps(token: string, kid: string, ct: Uint8Array): Promise<Uint8Array>;
  /** `mode`: 'ML-DSA' (default), 'HashML-DSA-SHA256/384/512' (data = digest), 'ML-DSA-mu' (data = μ, no ctx). */
  mldsaSign(token: string, kid: string, data: Uint8Array | string, opts?: { ctx?: Uint8Array | string | null; mode?: string | null }): Promise<Uint8Array>;
  /** X-Wing (ML-KEM-768 + X25519) to an MLKEM768 key and a CURVE25519 key; one token with both scopes. */
  xwingEncaps(token: string, kid: string, opts: { extKid: string }): Promise<{ alg: string; ss: Uint8Array; ct: Uint8Array }>;
  xwingDecaps(token: string, kid: string, ct: Uint8Array, opts: { extKid: string }): Promise<Uint8Array>;
  /** HPKE (RFC 9180) Base, single shot, to a key in the HEM or to { pubkey, kem } outside it. */
  hpkeSeal(token: string, recipient: { kid: string; extKid?: string | null } | { pubkey: Uint8Array; kem: HemHpkeKem },
    data: Uint8Array | string, opts?: HemHpkeOpts): Promise<{ enc: Uint8Array; ct: Uint8Array; suite: string; kem: string; kdf: string; aead: string }>;
  /** Open with a key pair that has the HPKE flag; suite, info and aad must be the sealer's. */
  hpkeOpen(token: string, kid: string, enc: Uint8Array, ct: Uint8Array, opts?: HemHpkeOpts & { extKid?: string | null }): Promise<Uint8Array>;
  /** HKDF or SP 800-108 (counter) from a stored HMAC SHA2 key; 16..128 bytes out. */
  kdf(token: string, kid: string, alg: 'HKDF' | 'SP800-108', len: number, opts?: { salt?: Uint8Array | string | null; info?: Uint8Array | string | null }): Promise<Uint8Array>;
  /** TOTP / HOTP code of a stored SHA1 seed; keep `step` to refuse replays. */
  otp(token: string, kid: string, opts?: HemOtpOpts): Promise<{ code: string; step: number }>;
  otpVerify(token: string, kid: string, code: string, opts?: HemOtpOpts & { window?: number | null }): Promise<{ verified: boolean; step?: number }>;
  /** 1..8192 bytes from the device DRBG; any valid token (none before personalisation). */
  random(token: string | null, n?: number): Promise<Uint8Array>;
  /** The device's `verified`: false for an invalid signature. Other errors throw. */
  mldsaVerify(token: string, kid: string, data: Uint8Array | string, sign: Uint8Array, opts?: { ctx?: Uint8Array | string | null; mode?: string | null }): Promise<boolean>;

  deleteKey(token: string, kid: string): Promise<void>;

  /** No token needed; a valid one adds sd_csd / sd_cid on an initialised PPA. */
  getVersion(opts?: { timeoutMs?: number; signal?: AbortSignal; token?: string | null }): Promise<{
    hwv: string; fwv: string; fwk: string; fws: string; fwc?: string;
    blv?: string; blk?: string; bls?: string; blc?: string; uis?: string; sd_csd?: string; sd_cid?: string;
  }>;
  getStatus(opts?: { timeoutMs?: number; signal?: AbortSignal }): Promise<Record<string, unknown>>;
  /** Scope: system:config, logger:get or auth:ext:pair. */
  getConfig(token: string): Promise<Record<string, unknown>>;
  /** Change the everyday password. Sends the key it derives to, plus a proof of ECDH; the 24 words are untouched. */
  setUserPassword(token: string, newPassword: string): Promise<unknown>;
  setConfig(token: string, cfg: Record<string, unknown>): Promise<{ updated: boolean }>;
  /** Key storage reclaim report, a dry run. Scope: system:config. */
  defragCheck(token: string): Promise<{ used: number; keys: number; deleted: number; deleted_size: number; invalid: number;
    duplicates: number; reclaimable: boolean; reclaimable_size: number; reserved: string }>;
  /** Start the reclaim at the next boot; `started`: the device restarts in ~2 s. 409 (report in err.data): unreadable records. */
  defragStart(token: string): Promise<{ started: boolean; report: Record<string, unknown> | null }>;
  /** Before personalisation, no token: start HTTPS (`tls`) and, on an EPA, derive the attestation key (`att`). Once per power-up each. */
  bootstrap(parts: { tls?: Record<string, unknown> | null; att?: { seed: Uint8Array; epoch: number } | null }): Promise<{ csr: Uint8Array | null }>;

  /** Scope: system:config, system:upgrade or system:shutdown (none before personalisation). */
  reboot(token: string | null): Promise<unknown>;
  /** Scope: system:config or system:shutdown. */
  shutdown(token: string): Promise<unknown>;
  /** Scope: system:config (none before personalisation). 409 while a run is in progress. */
  selftest(token: string | null): Promise<unknown>;

  /** Restarts the device into the bootloader's USB mode. Scope: system:upgrade or system:config. */
  rebootToUsbMode(token: string | null): Promise<void>;
  /** Sent as firmware.bin or firmware.hex (Intel HEX told by its first byte, or `format`). */
  uploadFirmware(token: string | null, bytes: Uint8Array, opts?: {
    format?: 'bin' | 'hex';
    /** (loaded, total) in bytes; browser only. */
    onProgress?: (loaded: number, total: number) => void;
    signal?: AbortSignal;
  }): Promise<void>;
  /** null while the device is still checking (it answers 201/202); the result once it is done. */
  checkFirmware(token: string, opts?: { signal?: AbortSignal }): Promise<Record<string, unknown> | null>;
  /** Poll checkFirmware() until done. Rejects with `timeout`, `aborted`, or the device's 4xx. */
  waitFirmwareCheck(token: string, opts?: PollOpts): Promise<Record<string, unknown>>;
  installFirmware(token: string): Promise<unknown>;
  /** Sent as webroot.tar, the only name the device takes. */
  uploadUi(token: string | null, bytes: Uint8Array, opts?: {
    onProgress?: (loaded: number, total: number) => void;
    signal?: AbortSignal;
  }): Promise<void>;
  checkUi(token: string, opts?: { signal?: AbortSignal }): Promise<Record<string, unknown> | null>;
  waitUiCheck(token: string, opts?: PollOpts): Promise<Record<string, unknown>>;
  installUi(token: string): Promise<unknown>;

  /** Scope: storage:disk<N> - the disk is the one in the scope. */
  lockStorage(token: string): Promise<unknown>;
  /** Without mode: writable with a ':rw' scope, else read-only. */
  unlockStorage(token: string, opts?: { mode?: 'ro' | 'rw' | null }): Promise<void>;

  /** The device log key; with `nonce` (32..64 bytes) its signature proves possession now. Scope: logger:get. */
  getLoggerKey(token: string, opts?: { nonce?: Uint8Array | null }): Promise<{ key: string; nonce: string; nonce_signed: string }>;
  /** Downloadable log files (the one being written is `current`, not listed). Scope: logger:get. */
  listLogFiles(token: string, opts?: { offset?: number; limit?: number }): Promise<{
    id: string[]; offset: number; total: number; listed: number; oldest?: string; newest?: string; current?: string;
  }>;
  /** One log file as text; the one being written is HTTP 409. Scope: logger:get. */
  getLogFile(token: string, id: string): Promise<string>;

  /** Install the certificate Broker.provisioning() issued. 403 on a provisioned device. */
  installProvisioning(cert: Record<string, unknown>, token?: string | null): Promise<unknown>;
  /** Provision if the attestation still carries a CSR; resolves null when already provisioned. */
  provision(token?: string | null): Promise<Record<string, unknown> | null>;
  /** Register `<prefix>.ence.do` and install the TLS block. Scope: system:config. */
  registerDomain(token: string, prefix: string, opts?: { ip?: string | null; newCertificate?: boolean; pollInterval?: number; pollTimeout?: number; onPending?: (status: string) => void; signal?: AbortSignal }): Promise<Record<string, unknown>>;
  /** Prove the log key with a fresh nonce, fetch one file and verify it. Scope: logger:get. */
  verifyLogFile(token: string, id: string): Promise<LogVerification & { keyProven: boolean; text: string }>;

  clearCache(): void;

  /** Cached scopes and when each stops working — the tokens themselves stay inside. */
  readonly tokens: Array<{ scope: HemScope; exp: number }>;
  /** Discard cached derived keys and all JWT tokens (call on logout). */
  clearKeys(): void;
}

/** SHA-256 of the DER of the Encedo Root CA, pinned by Attest.verifyDevice(). */
export declare const ENCEDO_ROOT_SHA256: string;

export interface AttestRequest {
  nonce: Uint8Array;
  aud: string;
  kid?: string;
  includeMetadata?: boolean;
  /** {} = signature PoP; verifierEphPub = ECDH-MAC; ciphertext = ML-KEM MAC; enc = HPKE export. */
  popArgs?: { verifierEphPub?: Uint8Array; ciphertext?: Uint8Array; enc?: Uint8Array };
}

/** What Attest.prepare() keeps for Attest.verify(); holds the verifier's ephemeral private key for an ECDH PoP. */
export interface AttestState {
  aud: string;
  nonce: Uint8Array;
  kid: string | null;
  pop: 'sig' | 'ecdh' | null;
  curve?: string;
  ephPriv?: CryptoKey;
  ephPub?: Uint8Array;
}

export interface AttestVerification {
  /** Every check passed - a PoP that could not be checked here ('pop_unsupported') is not ok. */
  ok: boolean;
  /** Names of the failed checks: format, alg, typ, jwk, kid, signature, iss, times, jti, device, aud, nonce, key, pop, pop_unsupported, auth, org, age. */
  failed: string[];
  /** Past exp + leeway; reported, not failed. */
  expired: boolean;
  /** SHA-1 / SHA-256 of the device key, hex: what the manufacturer registry is keyed by. */
  skid: string | null;
  skid256: string | null;
  /** The device key, 04 || x || y, for verifyDevice(). */
  point: Uint8Array | null;
  header: Record<string, any> | null;
  claims: Record<string, any> | null;
  pop: { method: 'signature' | 'mac' | null; result: 'ok' | 'fail' | 'unsupported' | 'none' };
  /** The login context of the token behind the request (FW 1.3, DEV-511); null without one. */
  auth: AttestAuth | null;
}

/** The `auth` block of an attestation, read out: how the token was obtained, signed by the device. */
export interface AttestAuth {
  /** 'pwd' passphrase, 'ext' paired authenticator app. */
  method: 'pwd' | 'ext';
  /** The token's iat. */
  iat: number;
  /** Seconds since the login started, from the device uptime (ext: since the request to the app). */
  age: number;
  /** Attestation iat - age, on the device clock (trusted only when trustedTime). */
  authTime: number;
  /** The Origin of the login request; null when there was none. */
  org: string | null;
  /** What the app declared (ext only): v, lock, uva, aos, app, hw, ... - signed by the app, not interpreted by the device. */
  actx: Record<string, any> | null;
  /** ext only: the authenticator's KID, hex lowercase. */
  akid: string | null;
  /** trusted_ts on and the RTC set: iat / authTime come from a trusted clock. */
  trustedTime: boolean;
}

/** Claims of a device access token (jwtParse()); org / upt / v / actx since FW 1.3 (DEV-511). */
export interface HemTokenClaims {
  scope: string | string[];
  /** 'U' / 'M', or base64 of the app KID for a token from an authenticator. */
  sub: string;
  iat: number;
  exp: number;
  jti: string;
  ctx?: string;
  /** The Origin header of the login request. */
  org?: string;
  /** Device uptime (s) when the login started. */
  upt?: number;
  /** Version of the login context: 1. */
  v?: number;
  /** authorizeRemote only: the context the app declared. */
  actx?: Record<string, any>;
}

/**
 * Attestation, in three levels: verify() (the token and its PoP, no network),
 * verifyDevice() (the device certificate chains to the pinned Encedo root),
 * validate() (attest.encedo.com: registry and revocation).
 */
export declare class Attest {
  constructor(url?: string, opts?: { debug?: boolean });
  readonly url: string;
  /** A challenge: `request` for hem.attest(), `state` for verify(). PoP 'sig' or 'ecdh' (curve: SECP256R1/384R1/521R1, CURVE25519); KEM / HPKE TBD. */
  static prepare(args: { aud: string; kid?: string | null; includeMetadata?: boolean; pop?: 'sig' | 'ecdh' | null;
    curve?: 'SECP256R1' | 'SECP384R1' | 'SECP521R1' | 'CURVE25519' | null }): Promise<{ request: AttestRequest; state: AttestState }>;
  /** Level 1. PoP checked here: signatures of P-256/384/521 and Ed25519, ECDH-MAC of P-256/384/521 and X25519. */
  static verify(jwt: string | { attestation: string }, state?: AttestState | null, opts?: { now?: number; leeway?: number;
    /** Fail 'auth' without a login context. */ requireAuth?: boolean;
    /** Fail 'org' unless the login came from this Origin (exact). */ org?: string | null;
    /** Fail 'age' when the login started longer ago (s). */ maxAge?: number | null }): Promise<AttestVerification>;
  /** Level 1_ext. CA certificates from pki() unless `cas` is given; dates and revocation are not checked here. */
  verifyDevice(point: Uint8Array, crt: string | Uint8Array, opts?: { cas?: Array<string | Uint8Array> | null; rootSha256?: string }): Promise<{
    ok: boolean; chain: string[]; reason?: 'certificate' | 'key' | 'issuer' | 'signature' | 'root';
  }>;
  /** Level 2: attest.encedo.com's verdict. */
  validate(jwt: string | { attestation: string }, opts?: { crt?: string | Uint8Array | null }): Promise<{ status: 'valid' | 'valid_unverified' | 'invalid'; expired?: boolean }>;
  /** Whether Encedo knows the device key (SKID, 40 or 64 hex). */
  skidKnown(skid: string): Promise<boolean>;
  /** The Encedo CA certificates, fetched once. */
  pki(): Promise<Array<{ subject: string; issuer: string; not_after: number; sha256: string; pem: string }>>;
}
