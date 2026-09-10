export declare class HemError extends Error {
  code: string;
  status: number;
  data: unknown;
}

/** Decode a JWT payload without verifying it. Returns null on malformed input. */
export declare function jwtParse(jwt: string): Record<string, any> | null;

export interface LogVerification {
  ok: boolean;
  /** Entries verified so far (all of them when ok). */
  lines: number;
  /** Counter of the first entry that failed. */
  line?: number;
  reason?: 'signature' | 'sequence' | 'no_key' | 'hmac';
}

/** Verify an audit-log file against the device's logger key (`key` from getLoggerKey()). */
export declare function verifyLog(signerKey: string, logText: string): Promise<LogVerification>;

/** Verify that the device signed getLoggerKey()'s nonce, so the key is one it holds. */
export declare function verifyLoggerKey(loggerKey: { key: string; nonce: string; nonce_signed: string }): Promise<boolean>;

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
  type: string;
  /** Unix seconds, when the device reports them. */
  created: number | null;
  updated: number | null;
  /** The raw 128-byte description field, or null when it is empty. */
  description: Uint8Array | null;
}

/** listKeys() and searchKeys() return the same entries. */
export type HemSearchKey = HemKey;

/** One page of the key repository plus the size of the whole repository. */
export interface HemKeyPage {
  list: HemKey[];
  total: number;
}

/**
 * Peer-key selector shared by the /api/crypto/* endpoints. Setting either one
 * makes the device derive the operation's key by ECDH between `kid` and the
 * peer key instead of using `kid` directly; naming `kid`'s own public key
 * yields a key that never exists outside the device. Pass one, never both.
 */
export interface HemPeerKeyOpts {
  extKid?: string | null;
  pubkey?: Uint8Array | string | null;
}

export interface HemWrapOpts extends HemPeerKeyOpts {
  /** HKDF context, max 64 bytes — domain-separates the derived key. */
  ctx?: Uint8Array | string | null;
  iv?: Uint8Array | null;
}

export interface HemCipherOpts extends HemWrapOpts {
  /** Additional authenticated data, GCM modes only. */
  aad?: Uint8Array | null;
  /** GCM authentication tag — decrypt only. */
  tag?: Uint8Array | null;
}

export interface HemCipherResult {
  ciphertext: Uint8Array;
  /** Generated by the device; required to decrypt. */
  iv: Uint8Array | null;
  /** GCM modes only. */
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
  authorizePassword(password: string | null, scope: string, expSeconds?: number): Promise<string>;

  /**
   * Mobile push authorisation. Cancelling (`signal`) or timing out withdraws
   * the event from the broker; rejects with code `aborted`, `timeout` or `denied`.
   */
  authorizeRemote(scope: string, opts?: PollOpts & {
    /** Called once with the broker event id. */
    onEvent?: (eventid: string) => void;
  }): Promise<string>;

  getAttestation(token: string): Promise<{ genuine: string; [key: string]: unknown }>;

  /**
   * Provision a factory-fresh device. Pass the master secret as `{ mnemonic }`
   * (from generateMnemonic) or `{ entropy }`; a password string still works.
   * masterkey/userkey are written into cfg automatically.
   */
  initialize(admin: string | { mnemonic: string } | { entropy: Uint8Array }, userPassword: string, cfg?: Record<string, unknown>): Promise<unknown>;

  /** Authenticate with the 24-word master secret. `legacy`: device personalised by the v1 Manager. */
  authorizeMaster(mnemonic: string, scope: string, expSeconds?: number, opts?: { legacy?: boolean }): Promise<string>;

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

  /** One page; `total` is the whole repository, so a caller can page on. */
  listKeys(token: string, offset?: number, limit?: number): Promise<HemKeyPage>;
  /**
   * Prefix search over the description field. Pass the plain pattern — the SDK
   * base64-encodes it and adds the '^' anchor. limit <= 0 leaves the device
   * default (15). token may be null when the device allows anonymous search.
   */
  searchKeys(token: string | null, descr: string | Uint8Array, offset?: number, limit?: number): Promise<HemKey[]>;
  getPubKey(token: string, kid: string): Promise<{ type: string; pubkey: string; updated?: number }>;
  /**
   * `mode` ('ECDH', 'ExDSA' or 'ECDH,ExDSA') is needed by the SECP* curves, which can do both.
   * `label` is ASCII 0x20-0x7F, up to 32 characters, and `descr` the base64 of a 64-byte
   * field; the firmware in preparation doubles both. The device rejects what does not fit.
   */
  createKeyPair(token: string, label: string, type: string, descr: string, mode?: string | null): Promise<{ kid: string }>;
  importPublicKey(token: string, label: string, type: string, pubKeyBytes: Uint8Array, descr?: string | null, mode?: string | null): Promise<{ kid: string }>;
  deriveKey(token: string, label: string, type: string, descr: string, kid: string, peerPubKeyBase64: string, mode?: string | null): Promise<{ kid: string }>;
  updateKey(token: string, kid: string, label: string, descr: string): Promise<unknown>;
  exdsaSignBytes(token: string, kid: string, data: Uint8Array, alg?: string, ctx?: string | null): Promise<string>;
  exdsaVerify(token: string, kid: string, data: Uint8Array, sig: string, alg?: string): Promise<boolean>;
  /** alg hashes the shared secret; omit it for the raw 32 bytes a Noise handshake needs. */
  ecdh(token: string, kid: string, peerPubKeyBase64: string, opts?: { alg?: string | null }): Promise<Uint8Array>;
  ecdhKid(token: string, kid: string, extKid: string, opts?: { alg?: string | null }): Promise<Uint8Array>;

  hmacHash(token: string, kid: string, data: Uint8Array, alg?: string | null, opts?: HemPeerKeyOpts): Promise<Uint8Array>;
  hmacVerify(token: string, kid: string, data: Uint8Array, mac: Uint8Array, alg?: string | null, opts?: HemPeerKeyOpts): Promise<true>;
  cipherEncrypt(token: string, kid: string, data: Uint8Array, alg: string, opts?: HemCipherOpts): Promise<HemCipherResult>;
  cipherDecrypt(token: string, kid: string, ciphertext: Uint8Array, alg: string, opts?: HemCipherOpts): Promise<Uint8Array>;
  cipherWrap(token: string, kid: string, alg: string, data: Uint8Array, opts?: HemWrapOpts): Promise<Uint8Array>;
  cipherUnwrap(token: string, kid: string, alg: string, wrapped: Uint8Array, opts?: HemWrapOpts): Promise<Uint8Array>;
  mlkemEncaps(token: string, kid: string): Promise<{ ss: Uint8Array; ct: Uint8Array }>;
  mlkemDecaps(token: string, kid: string, ct: Uint8Array): Promise<Uint8Array>;
  mldsaSign(token: string, kid: string, data: Uint8Array): Promise<Uint8Array>;
  mldsaVerify(token: string, kid: string, data: Uint8Array, sign: Uint8Array): Promise<true>;

  deleteKey(token: string, kid: string): Promise<void>;

  getVersion(opts?: { timeoutMs?: number; signal?: AbortSignal }): Promise<{ hwv: string; blv: string; fwv: string; fws: string; conf: string }>;
  getStatus(opts?: { timeoutMs?: number; signal?: AbortSignal }): Promise<Record<string, unknown>>;
  getConfig(token: string): Promise<Record<string, unknown>>;
  /** Change the everyday password. Sends the key it derives to, plus a proof of ECDH; the 24 words are untouched. */
  setUserPassword(token: string, newPassword: string): Promise<unknown>;
  setConfig(token: string, cfg: Record<string, unknown>): Promise<{ updated: boolean }>;
  reboot(token: string): Promise<unknown>;
  shutdown(token: string): Promise<unknown>;
  selftest(token: string): Promise<unknown>;

  usbMode(token: string): Promise<unknown>;
  uploadFirmware(token: string, bytes: Uint8Array, filename?: string, opts?: {
    /** (loaded, total) in bytes; browser only. */
    onProgress?: (loaded: number, total: number) => void;
    signal?: AbortSignal;
  }): Promise<unknown>;
  /** null while the device is still checking (it answers 201/202); the result once it is done. */
  checkFirmware(token: string, opts?: { signal?: AbortSignal }): Promise<Record<string, unknown> | null>;
  /** Poll checkFirmware() until done. Rejects with `timeout`, `aborted`, or the device's 4xx. */
  waitFirmwareCheck(token: string, opts?: PollOpts): Promise<Record<string, unknown>>;
  installFirmware(token: string): Promise<unknown>;
  uploadUi(token: string, bytes: Uint8Array, filename?: string, opts?: {
    onProgress?: (loaded: number, total: number) => void;
    signal?: AbortSignal;
  }): Promise<unknown>;
  checkUi(token: string, opts?: { signal?: AbortSignal }): Promise<Record<string, unknown> | null>;
  waitUiCheck(token: string, opts?: PollOpts): Promise<Record<string, unknown>>;
  installUi(token: string): Promise<unknown>;

  lockStorage(token: string): Promise<unknown>;
  unlockStorage(token: string): Promise<unknown>;

  getLoggerKey(token: string): Promise<Record<string, unknown>>;
  listLog(token: string, offset?: number): Promise<Record<string, unknown>>;
  getLogEntry(token: string, id: string | number): Promise<Record<string, unknown>>;

  /** Install the certificate Broker.provisioning() issued. 403 on a provisioned device. */
  installProvisioning(cert: Record<string, unknown>, token?: string | null): Promise<unknown>;
  /** Provision if the attestation still carries a CSR; resolves null when already provisioned. */
  provision(token?: string | null): Promise<Record<string, unknown> | null>;
  /** Register `<prefix>.ence.do` and install the TLS block. Scope: system:config. */
  registerDomain(token: string, prefix: string, opts?: { ip?: string | null; newCertificate?: boolean; pollInterval?: number; pollTimeout?: number; onPending?: (status: string) => void; signal?: AbortSignal }): Promise<Record<string, unknown>>;
  /** Fetch one log file and verify it with verifyLog(). Scope: logger:get. */
  verifyLogEntry(token: string, id: string | number): Promise<LogVerification & { text: string }>;

  clearCache(): void;

  /** Cached scopes and when each stops working — the tokens themselves stay inside. */
  readonly tokens: Array<{ scope: string; exp: number }>;
  /** Discard cached derived keys and all JWT tokens (call on logout). */
  clearKeys(): void;
}
