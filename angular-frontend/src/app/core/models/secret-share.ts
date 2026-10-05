export interface SecretShare {
  index: number;
  /** BigInteger serialized as a decimal string by the API. */
  share: string;
  /** RSA signature, Base64-encoded. */
  signature: string;
}

export interface SplitSecretRequest {
  k: number;
  n: number;
  secret: string;
}

export interface ShareVaultSnapshot {
  version: 1;
  threshold: number | null;
  totalShares: number | null;
  shares: SecretShare[];
  selectedIndexes: number[];
  updatedAt: string;
}

export type ApiHealthStatus = 'unknown' | 'online' | 'offline';
