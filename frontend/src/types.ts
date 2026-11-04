export interface SecretEnvelope {
  v: 1;
  alg: "A256GCM";
  iv: string;
  ciphertext: string;
  tag: string;
  createdAt: number;
  expiresAt: number;
  maxViews: 1;
}

export interface PlaintextEnvelope {
  v: 1;
  secret: string;
  createdAt: number;
  expiresAt: number;
  maxViews: 1;
}

export interface EncryptedParts {
  iv: string;
  ciphertext: string;
  tag: string;
}

export interface CreateResponse {
  secretId: string;
  expiresAt: number;
  receiptToken: string;
  receiptExpiresAt: number;
  maxViews: 1;
}

export interface ChallengeResponse {
  secretId: string;
  expiresAt: number;
  maxViews: 1;
  challenge: string;
  challengeExpiresAt: number;
}

export interface OpenResponse {
  envelope: SecretEnvelope;
  viewToken: string;
  burnedAt: number;
}

export type ReceiptEventType =
  | "created"
  | "link_opened"
  | "decrypt_attempted"
  | "decrypted"
  | "burned"
  | "expired"
  | "revoked";

export interface ReceiptEvent {
  type: ReceiptEventType;
  at: number;
}

export type ReceiptState = "available" | "burned" | "expired" | "revoked";

export interface ReceiptView {
  secretId: string;
  state: ReceiptState;
  createdAt: number;
  expiresAt: number;
  receiptExpiresAt: number;
  burnedAt?: number;
  revokedAt?: number;
  opens: number;
  lastOpenedAt?: number;
  decrypted: boolean;
  events: ReceiptEvent[];
}

export interface RevokeResponse {
  state: ReceiptState;
  revokedAt?: number;
}

export interface ApiErrorBody {
  error?: {
    code?: string;
    message?: string;
  };
}
