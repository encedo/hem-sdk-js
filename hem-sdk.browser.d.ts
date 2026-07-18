export declare class HemError extends Error {
  code: string;
  status: number;
  data: unknown;
}

export interface HemKey {
  kid: string;
  label: string;
  type: string;
  description: Uint8Array | null;
}

export declare class HEM {
  constructor(hsmUrl: string, opts?: { broker?: string; debug?: boolean });

  hemCheckin(): Promise<void>;

  /** Pass null or '' to reuse cached derived keys (set on first call with a real password). */
  authorizePassword(password: string | null, scope: string, expSeconds?: number): Promise<string>;

  authorizeRemote(scope: string, opts?: {
    pollInterval?: number;
    pollTimeout?: number;
    onPending?: () => void;
    signal?: AbortSignal;
  }): Promise<string>;

  getAttestation(token: string): Promise<{ genuine: string; [key: string]: unknown }>;

  /** Provision a factory-fresh device. masterkey/userkey are derived automatically. */
  initialize(adminPassword: string, userPassword: string, cfg?: Record<string, unknown>): Promise<unknown>;

  /** Get broker MAC data to list the device's paired external authenticators. */
  getExtAuthMac(token: string): Promise<{ nonce: string; mac: string; eid: string }>;

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
    pollInterval?: number;
    pollTimeout?: number;
    onPending?: () => void;
    signal?: AbortSignal;
  }): Promise<unknown>;

  listKeys(token: string, offset?: number, limit?: number): Promise<HemKey[]>;
  searchKeys(token: string, descrBase64: string, offset?: number, limit?: number): Promise<HemKey[]>;
  getPubKey(token: string, kid: string): Promise<string>;
  createKeyPair(token: string, label: string, type: string, descr: string): Promise<{ kid: string }>;
  importPublicKey(token: string, label: string, type: string, pubKeyBytes: Uint8Array, descr?: string | null, mode?: string | null): Promise<{ kid: string }>;
  deriveKey(token: string, label: string, type: string, descr: string, kid: string, peerPubKeyBase64: string): Promise<{ kid: string }>;
  updateKey(token: string, kid: string, label: string, descr: string): Promise<unknown>;
  exdsaSignBytes(token: string, kid: string, data: Uint8Array, alg?: string, ctx?: string | null): Promise<string>;
  exdsaVerify(token: string, kid: string, data: Uint8Array, sig: string, alg?: string): Promise<boolean>;
  ecdh(token: string, kid: string, peerPubKeyBase64: string): Promise<string>;

  hmacHash(token: string, kid: string, data: Uint8Array, alg?: string | null): Promise<Uint8Array>;
  hmacVerify(token: string, kid: string, data: Uint8Array, mac: Uint8Array, alg?: string | null): Promise<true>;
  cipherEncrypt(token: string, kid: string, data: Uint8Array, alg: string): Promise<Uint8Array>;
  cipherDecrypt(token: string, kid: string, ciphertext: Uint8Array, alg: string): Promise<Uint8Array>;
  cipherWrap(token: string, kid: string, alg: string, data: Uint8Array): Promise<Uint8Array>;
  cipherUnwrap(token: string, kid: string, alg: string, wrapped: Uint8Array): Promise<Uint8Array>;
  mlkemEncaps(token: string, kid: string): Promise<{ ss: Uint8Array; ct: Uint8Array }>;
  mlkemDecaps(token: string, kid: string, ct: Uint8Array): Promise<Uint8Array>;
  mldsaSign(token: string, kid: string, data: Uint8Array): Promise<Uint8Array>;
  mldsaVerify(token: string, kid: string, data: Uint8Array, sign: Uint8Array): Promise<true>;

  deleteKey(token: string, kid: string): Promise<void>;

  getVersion(): Promise<{ hwv: string; blv: string; fwv: string; fws: string; conf: string }>;
  getStatus(): Promise<Record<string, unknown>>;
  getConfig(token: string): Promise<Record<string, unknown>>;
  setConfig(token: string, cfg: Record<string, unknown>): Promise<{ updated: boolean }>;
  reboot(token: string): Promise<unknown>;
  shutdown(token: string): Promise<unknown>;
  selftest(token: string): Promise<unknown>;

  usbMode(token: string): Promise<unknown>;
  uploadFirmware(token: string, bytes: Uint8Array, filename?: string): Promise<unknown>;
  checkFirmware(token: string): Promise<unknown>;
  installFirmware(token: string): Promise<unknown>;
  uploadUi(token: string, bytes: Uint8Array, filename?: string): Promise<unknown>;
  checkUi(token: string): Promise<unknown>;
  installUi(token: string): Promise<unknown>;

  lockStorage(token: string): Promise<unknown>;
  unlockStorage(token: string): Promise<unknown>;

  getLoggerKey(token: string): Promise<Record<string, unknown>>;
  listLog(token: string, offset?: number): Promise<Record<string, unknown>>;
  getLogEntry(token: string, id: string | number): Promise<Record<string, unknown>>;

  clearCache(): void;

  /** Discard cached derived keys and all JWT tokens (call on logout). */
  clearKeys(): void;
}
