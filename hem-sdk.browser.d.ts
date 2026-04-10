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

  listKeys(token: string, offset?: number, limit?: number): Promise<HemKey[]>;
  searchKeys(token: string, descrBase64: string, offset?: number, limit?: number): Promise<HemKey[]>;
  getPubKey(token: string, kid: string): Promise<string>;
  createKeyPair(token: string, label: string, type: string, descr: string): Promise<{ kid: string }>;
  importPublicKey(token: string, label: string, type: string, pubKeyBytes: Uint8Array, descr?: string | null): Promise<{ kid: string }>;
  exdsaSignBytes(token: string, kid: string, data: Uint8Array, alg?: string, ctx?: string | null): Promise<string>;
  exdsaVerify(token: string, kid: string, data: Uint8Array, sig: string, alg?: string): Promise<boolean>;
  ecdh(token: string, kid: string, peerPubKeyBase64: string): Promise<string>;
  deleteKey(token: string, kid: string): Promise<void>;
  clearCache(): void;

  /** Discard cached derived keys and all JWT tokens (call on logout). */
  clearKeys(): void;
}
