import assert from "node:assert/strict";
import test from "node:test";
import {
  IV_BYTES,
  KEY_BYTES,
  TAG_BYTES,
  base64urlDecode,
  base64urlEncode,
  cryptoUsable,
  decryptSecret,
  encryptSecret,
  generateKeyMaterial,
  wipe,
} from "../src/crypto.ts";
import type { SecretEnvelope } from "../src/types.ts";

const META = {
  createdAt: 1_800_000_000_000,
  expiresAt: 1_800_003_600_000,
  maxViews: 1 as const,
};

function envelopeFrom(parts: {
  iv: string;
  ciphertext: string;
  tag: string;
}): SecretEnvelope {
  return {
    v: 1,
    alg: "A256GCM",
    iv: parts.iv,
    ciphertext: parts.ciphertext,
    tag: parts.tag,
    createdAt: META.createdAt,
    expiresAt: META.expiresAt,
    maxViews: 1,
  };
}

test("AES-256-GCM round trips a versioned JSON envelope", async () => {
  const key = generateKeyMaterial();
  const secret = "correct horse battery staple\nsecond line";
  const parts = await encryptSecret(secret, key, META);
  assert.equal(base64urlDecode(parts.iv)?.byteLength, IV_BYTES);
  assert.equal(base64urlDecode(parts.tag)?.byteLength, TAG_BYTES);

  const plaintext = await decryptSecret(envelopeFrom(parts), key);
  assert.equal(plaintext.secret, secret);
  assert.equal(plaintext.createdAt, META.createdAt);
  assert.equal(plaintext.expiresAt, META.expiresAt);
  assert.equal(plaintext.maxViews, 1);
  wipe(key);
});

test("every encryption uses a fresh 12-byte IV", async () => {
  const key = generateKeyMaterial();
  const seen = new Set<string>();
  for (let i = 0; i < 300; i += 1) {
    const parts = await encryptSecret("same plaintext", key, META);
    const iv = base64urlDecode(parts.iv);
    assert.ok(iv);
    assert.equal(iv.byteLength, IV_BYTES);
    assert.equal(seen.has(parts.iv), false, "IV repeated");
    seen.add(parts.iv);
  }
  assert.equal(seen.size, 300);
  wipe(key);
});

test("keys are 256 random bits", () => {
  const seen = new Set<string>();
  for (let i = 0; i < 64; i += 1) {
    const key = generateKeyMaterial();
    assert.equal(key.byteLength, KEY_BYTES);
    seen.add(base64urlEncode(key));
    wipe(key);
  }
  assert.equal(seen.size, 64);
});

test("tampered ciphertext, tag, IV, or wrong key is rejected", async () => {
  const key = generateKeyMaterial();
  const parts = await encryptSecret("tamper target", key, META);
  const envelope = envelopeFrom(parts);

  const flip = (value: string): string => {
    const bytes = base64urlDecode(value);
    assert.ok(bytes);
    bytes[0] = (bytes[0] ?? 0) ^ 1;
    return base64urlEncode(bytes);
  };

  await assert.rejects(() =>
    decryptSecret({ ...envelope, ciphertext: flip(envelope.ciphertext) }, key),
  );
  await assert.rejects(() =>
    decryptSecret({ ...envelope, tag: flip(envelope.tag) }, key),
  );
  await assert.rejects(() =>
    decryptSecret({ ...envelope, iv: flip(envelope.iv) }, key),
  );

  const wrongKey = generateKeyMaterial();
  await assert.rejects(() => decryptSecret(envelope, wrongKey));
  wipe(key);
  wipe(wrongKey);
});

test("unsupported envelope versions and truncated fields are rejected", async () => {
  const key = generateKeyMaterial();
  const parts = await encryptSecret("version check", key, META);
  const envelope = envelopeFrom(parts);

  await assert.rejects(() =>
    decryptSecret({ ...envelope, v: 2 as unknown as 1 }, key),
  );
  await assert.rejects(() =>
    decryptSecret({ ...envelope, tag: envelope.tag.slice(0, 8) }, key),
  );
  await assert.rejects(() =>
    decryptSecret({ ...envelope, ciphertext: "" }, key),
  );
  wipe(key);
});

test("base64url is strict and canonical", () => {
  const bytes = crypto.getRandomValues(new Uint8Array(48));
  const encoded = base64urlEncode(bytes);
  assert.deepEqual(base64urlDecode(encoded), bytes);
  assert.equal(base64urlDecode("===="), null);
  assert.equal(base64urlDecode("a"), null);
  assert.equal(base64urlDecode("A"), null);
  assert.equal(base64urlDecode("AB"), null);
  assert.deepEqual(base64urlDecode("AA"), new Uint8Array([0]));
});

test("wipe zeroes key material", () => {
  const key = generateKeyMaterial();
  wipe(key);
  assert.deepEqual([...key], new Array(KEY_BYTES).fill(0));
});

test("Web Crypto is available in this runtime", () => {
  assert.equal(cryptoUsable(), true);
});
