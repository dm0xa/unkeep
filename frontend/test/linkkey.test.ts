import assert from "node:assert/strict";
import test from "node:test";
import {
  KEY_BYTES,
  base64urlEncode,
  generateKeyMaterial,
  openProof,
} from "../src/crypto.ts";
import { encodeFragment, readFragment, unlockFragment } from "../src/linkkey.ts";

test("raw fragments round trip a 256-bit key", async () => {
  const key = generateKeyMaterial();
  const fragment = await encodeFragment(key, "");
  assert.equal(fragment, base64urlEncode(key));
  const material = readFragment(fragment);
  assert.ok(material);
  assert.equal(material.version, 1);
  if (material.version === 1) {
    assert.deepEqual(material.key, key);
  }
});

test("passphrase fragments wrap the key and reject a wrong passphrase", async () => {
  const key = generateKeyMaterial();
  const fragment = await encodeFragment(key, "correct horse battery staple");
  assert.match(fragment, /^v2\./);

  const material = readFragment(fragment);
  assert.ok(material);
  assert.equal(material.version, 2);
  if (material.version !== 2) {
    return;
  }
  assert.equal(material.wrapped.ciphertext.length, 43);

  const unlocked = await unlockFragment(material, "correct horse battery staple");
  assert.deepEqual(unlocked, key);

  await assert.rejects(
    unlockFragment(material, "wrong passphrase"),
    /operation failed|decrypt/i,
  );

  const second = await encodeFragment(key, "correct horse battery staple");
  assert.notEqual(second, fragment, "each wrap must use a fresh salt and IV");
});

test("malformed fragments are rejected instead of guessed", () => {
  for (const fragment of [
    "",
    "not base64!",
    "AAAA",
    "v2",
    "v2.a.b.c",
    "v2.a.b.c.d.e",
    `v2.${"A".repeat(21)}.${"A".repeat(16)}.${"A".repeat(43)}.${"A".repeat(22)}`,
    `v2.${"A".repeat(22)}.${"A".repeat(16)}.${"A".repeat(42)}.${"A".repeat(22)}`,
    `v2.${"A".repeat(22)}.${"A".repeat(16)}.${"A".repeat(43)}`,
  ]) {
    assert.equal(readFragment(fragment), null, fragment);
  }
});

test("key proofs are deterministic, key-bound, and not the key", async () => {
  const key = generateKeyMaterial();
  const other = generateKeyMaterial();
  const proof = await openProof(key);
  assert.equal(proof, await openProof(key));
  assert.notEqual(proof, await openProof(other));
  assert.notEqual(proof, base64urlEncode(key));
  assert.equal(proof.length, 43);
  assert.equal(Buffer.from(proof, "base64url").byteLength, KEY_BYTES);
});
