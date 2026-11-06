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
  authorizePassword(password: string | null, scope: HemScope, expSeconds?: number, opts?: { remember?: boolean; ctx?: string | null }): Promise<string>;

  /**
   * Mobile push authorisation. Cancelling (`signal`) or timing out withdraws
   * the event from the broker; rejects with code `aborted`, `timeout` or `denied`.
   */
  authorizeRemote(scope: HemScope, opts?: PollOpts & {
    /** 1..64 chars, copied into the token. The token lifetime is the phone's answer. */
    ctx?: string | null;
    /** 1..128 chars shown with the request on the phone. */
    note?: string | null;
    /** Called once with the broker event id. */
    onEvent?: (eventid: string) => void;
  }): Promise<string>;

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
  authorizeMaster(mnemonic: string, scope: HemScope, expSeconds?: number, opts?: { legacy?: boolean; ctx?: string | null }): Promise<string>;

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
  exdsaSign(token: string, kid: string, data: Uint8Array | string, alg?: string, opts?: { ctx?: Uint8Array | string | null; det?: boolean }): Promise<Uint8Array>;
  /** The device's `verified`: false for an invalid signature. Other errors throw. */
  exdsaVerify(token: string, kid: string, data: Uint8Array | string, sig: Uint8Array, alg?: string, opts?: { ctx?: Uint8Array | string | null }): Promise<boolean>;
  /**
   * ECDH with a peer given as raw key bytes or as the KID of a stored key. No alg: the raw secret
   * (needs the `raw_ecdh_enabled` policy); 'SHA2-*' / 'SHA3-*': its digest; 'HKDF-SHA2-*': HKDF.
   */
  ecdh(token: string, kid: string, peer: Uint8Array | string, opts?: {
    alg?: string | null; hkdfSalt?: Uint8Array | string | null; hkdfCtx?: Uint8Array | string | null; hkdfLen?: number | null;
  }): Promise<Uint8Array>;
  /** One ECDH, 1..8 HKDF outputs; the shared secret never leaves the device. */
  ecdhHkdf(token: string, kid: string, peer: Uint8Array | string, alg: 'HKDF-SHA2-256' | 'HKDF-SHA2-384' | 'HKDF-SHA2-512',
    items: Array<{ hkdfSalt?: Uint8Array | string | null; hkdfCtx?: Uint8Array | string | null; hkdfLen?: number | null }>): Promise<Uint8Array[]>;

  hmacHash(token: string, kid: string, data: Uint8Array | string, alg?: string | null, opts?: HemPeerKeyOpts): Promise<Uint8Array>;
  /** The device's `verified`: false for a wrong MAC. Other errors throw. */
  hmacVerify(token: string, kid: string, data: Uint8Array | string, mac: Uint8Array, alg?: string | null, opts?: HemPeerKeyOpts): Promise<boolean>;
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
