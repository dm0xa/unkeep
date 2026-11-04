import type {
  EncryptedParts,
  PlaintextEnvelope,
  SecretEnvelope,
} from "./types.ts";

export const KEY_BYTES = 32;
export const IV_BYTES = 12;
export const TAG_BYTES = 16;
export const SALT_BYTES = 16;
export const PBKDF2_ITERATIONS = 600_000;
export const MAX_SECRET_BYTES = 16 * 1024;

// Frozen protocol labels: they authenticate existing links and stored
// ciphertext. Do not rename them with the product.
const AAD = new TextEncoder().encode("not-saved:v1");
const WRAP_AAD = new TextEncoder().encode("not-saved:key-wrap:v1");
const PROOF_PREFIX = new TextEncoder().encode("not-saved:open-proof:v1");
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const B64URL = /^[A-Za-z0-9_-]*$/;
const MAX_PLAINTEXT_BYTES = 32 * 1024;

export function cryptoUsable(): boolean {
  const scoped = globalThis as { isSecureContext?: boolean };
  return (
    typeof globalThis.crypto !== "undefined" &&
    typeof globalThis.crypto.subtle !== "undefined" &&
    typeof globalThis.crypto.getRandomValues === "function" &&
    scoped.isSecureContext !== false &&
    typeof btoa === "function" &&
    typeof atob === "function"
  );
}

export function generateKeyMaterial(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(KEY_BYTES));
}

export function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    binary += String.fromCharCode(
      ...bytes.subarray(offset, Math.min(offset + chunk, bytes.length)),
    );
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlDecode(value: string): Uint8Array | null {
  if (value.length === 0 || !B64URL.test(value)) {
    return null;
  }
  const padding = (4 - (value.length % 4)) % 4;
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padding);
  try {
    const binary = atob(padded);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      out[i] = binary.charCodeAt(i);
    }
    return base64urlEncode(out) === value ? out : null;
  } catch {
    return null;
  }
}

function bufferSource(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

async function importKey(
  keyBytes: Uint8Array,
  usage: "encrypt" | "decrypt",
): Promise<CryptoKey> {
  if (keyBytes.byteLength !== KEY_BYTES) {
    throw new Error("Invalid key length");
  }
  return globalThis.crypto.subtle.importKey(
    "raw",
    bufferSource(keyBytes),
    { name: "AES-GCM" },
    false,
    [usage],
  );
}

export async function encryptSecret(
  secret: string,
  keyBytes: Uint8Array,
  meta: { createdAt: number; expiresAt: number; maxViews: 1 },
): Promise<EncryptedParts> {
  const plaintext: PlaintextEnvelope = {
    v: 1,
    secret,
    createdAt: meta.createdAt,
    expiresAt: meta.expiresAt,
    maxViews: meta.maxViews,
  };
  const plaintextBytes = encoder.encode(JSON.stringify(plaintext));
  if (plaintextBytes.byteLength > MAX_PLAINTEXT_BYTES) {
    wipe(plaintextBytes);
    throw new Error("Secret is too large");
  }
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await importKey(keyBytes, "encrypt");
  try {
    const sealed = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: bufferSource(iv),
          additionalData: bufferSource(AAD),
          tagLength: 128,
        },
        key,
        bufferSource(plaintextBytes),
      ),
    );
    if (sealed.byteLength < TAG_BYTES) {
      throw new Error("Invalid ciphertext");
    }
    const ciphertext = sealed.slice(0, sealed.byteLength - TAG_BYTES);
    const tag = sealed.slice(sealed.byteLength - TAG_BYTES);
    const parts = {
      iv: base64urlEncode(iv),
      ciphertext: base64urlEncode(ciphertext),
      tag: base64urlEncode(tag),
    };
    wipe(sealed);
    wipe(ciphertext);
    wipe(tag);
    return parts;
  } finally {
    wipe(plaintextBytes);
  }
}

export async function decryptSecret(
  envelope: SecretEnvelope,
  keyBytes: Uint8Array,
): Promise<PlaintextEnvelope> {
  if (envelope.v !== 1 || envelope.alg !== "A256GCM" || envelope.maxViews !== 1) {
    throw new Error("Unsupported envelope");
  }
  const iv = base64urlDecode(envelope.iv);
  const ciphertext = base64urlDecode(envelope.ciphertext);
  const tag = base64urlDecode(envelope.tag);
  if (!iv || iv.byteLength !== IV_BYTES) {
    throw new Error("Invalid IV");
  }
  if (!tag || tag.byteLength !== TAG_BYTES) {
    throw new Error("Invalid tag");
  }
  if (!ciphertext) {
    throw new Error("Invalid ciphertext");
  }

  const combined = new Uint8Array(ciphertext.byteLength + tag.byteLength);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.byteLength);
  const key = await importKey(keyBytes, "decrypt");
  try {
    const plaintextBytes = new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: bufferSource(iv),
          additionalData: bufferSource(AAD),
          tagLength: 128,
        },
        key,
        bufferSource(combined),
      ),
    );
    try {
      const parsed: unknown = JSON.parse(decoder.decode(plaintextBytes));
      if (!isPlaintextEnvelope(parsed)) {
        throw new Error("Invalid plaintext envelope");
      }
      return parsed;
    } finally {
      wipe(plaintextBytes);
    }
  } finally {
    wipe(combined);
    wipe(iv);
    wipe(ciphertext);
    wipe(tag);
  }
}

export interface WrappedKey {
  salt: string;
  iv: string;
  ciphertext: string;
  tag: string;
}

/** SHA-256("not-saved:open-proof:v1" || key), sent to the server at open time. */
export async function openProof(keyBytes: Uint8Array): Promise<string> {
  if (keyBytes.byteLength !== KEY_BYTES) {
    throw new Error("Invalid key length");
  }
  const message = new Uint8Array(PROOF_PREFIX.byteLength + keyBytes.byteLength);
  message.set(PROOF_PREFIX);
  message.set(keyBytes, PROOF_PREFIX.byteLength);
  try {
    const digest = await globalThis.crypto.subtle.digest(
      "SHA-256",
      bufferSource(message),
    );
    return base64urlEncode(new Uint8Array(digest));
  } finally {
    wipe(message);
  }
}

async function deriveWrappingKey(
  passphrase: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const material = await globalThis.crypto.subtle.importKey(
    "raw",
    bufferSource(encoder.encode(passphrase)),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await globalThis.crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: bufferSource(salt),
      iterations: PBKDF2_ITERATIONS,
    },
    material,
    256,
  );
  return new Uint8Array(bits);
}

/** Wraps the random data key with a PBKDF2-derived key. The passphrase never
 * leaves the browser; the wrapped key fits in the URL fragment. */
export async function wrapDataKey(
  keyBytes: Uint8Array,
  passphrase: string,
): Promise<WrappedKey> {
  if (keyBytes.byteLength !== KEY_BYTES) {
    throw new Error("Invalid key length");
  }
  if (passphrase.length === 0) {
    throw new Error("A passphrase is required");
  }
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const wrappingKey = await deriveWrappingKey(passphrase, salt);
  try {
    const key = await importKey(wrappingKey, "encrypt");
    const sealed = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: bufferSource(iv),
          additionalData: bufferSource(WRAP_AAD),
          tagLength: 128,
        },
        key,
        bufferSource(keyBytes),
      ),
    );
    const ciphertext = sealed.slice(0, sealed.byteLength - TAG_BYTES);
    const tag = sealed.slice(sealed.byteLength - TAG_BYTES);
    const wrapped = {
      salt: base64urlEncode(salt),
      iv: base64urlEncode(iv),
      ciphertext: base64urlEncode(ciphertext),
      tag: base64urlEncode(tag),
    };
    wipe(sealed);
    wipe(ciphertext);
    wipe(tag);
    return wrapped;
  } finally {
    wipe(wrappingKey);
    wipe(salt);
    wipe(iv);
  }
}

/** Reconstructs the data key, or throws when the passphrase is wrong. */
export async function unwrapDataKey(
  wrapped: WrappedKey,
  passphrase: string,
): Promise<Uint8Array> {
  const salt = base64urlDecode(wrapped.salt);
  const iv = base64urlDecode(wrapped.iv);
  const ciphertext = base64urlDecode(wrapped.ciphertext);
  const tag = base64urlDecode(wrapped.tag);
  if (!salt || salt.byteLength !== SALT_BYTES) {
    throw new Error("Invalid salt");
  }
  if (!iv || iv.byteLength !== IV_BYTES) {
    throw new Error("Invalid IV");
  }
  if (!ciphertext || ciphertext.byteLength !== KEY_BYTES) {
    throw new Error("Invalid wrapped key");
  }
  if (!tag || tag.byteLength !== TAG_BYTES) {
    throw new Error("Invalid tag");
  }
  const combined = new Uint8Array(ciphertext.byteLength + tag.byteLength);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.byteLength);
  const wrappingKey = await deriveWrappingKey(passphrase, salt);
  try {
    const key = await importKey(wrappingKey, "decrypt");
    const opened = new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: bufferSource(iv),
          additionalData: bufferSource(WRAP_AAD),
          tagLength: 128,
        },
        key,
        bufferSource(combined),
      ),
    );
    if (opened.byteLength !== KEY_BYTES) {
      wipe(opened);
      throw new Error("Invalid key length");
    }
    return opened;
  } finally {
    wipe(wrappingKey);
    wipe(combined);
    wipe(salt);
    wipe(iv);
    wipe(ciphertext);
    wipe(tag);
  }
}

function isPlaintextEnvelope(value: unknown): value is PlaintextEnvelope {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    v["v"] === 1 &&
    typeof v["secret"] === "string" &&
    typeof v["createdAt"] === "number" &&
    typeof v["expiresAt"] === "number" &&
    v["maxViews"] === 1
  );
}

export function wipe(bytes: Uint8Array): void {
  bytes.fill(0);
}
