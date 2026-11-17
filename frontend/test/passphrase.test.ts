import assert from "node:assert/strict";
import test from "node:test";
import { generatePassphrase } from "../src/passphrase.ts";

test("passphrase is a grammatical lowercase phrase", () => {
  const phrase = generatePassphrase();
  assert.match(phrase, /^[a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+$/);
  assert.equal(phrase.split(" ").length, 5);
});

test("generated phrases differ", () => {
  const seen = new Set<string>();
  for (let i = 0; i < 100; i += 1) {
    seen.add(generatePassphrase());
  }
  assert.ok(seen.size > 95, `only ${seen.size} unique phrases`);
});
