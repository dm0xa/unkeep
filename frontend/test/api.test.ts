import assert from "node:assert/strict";
import test from "node:test";
import {
  confirmDecrypted,
  createSecret,
  fetchReceipt,
  getChallenge,
  openSecret,
  revokeSecret,
} from "../src/api.ts";
import type { SecretEnvelope } from "../src/types.ts";

const envelope: SecretEnvelope = {
  v: 1,
  alg: "A256GCM",
  iv: "AAAAAAAAAAAAAAAA",
  ciphertext: "AAAA",
  tag: "AAAAAAAAAAAAAAAAAAAAAA",
  createdAt: 1_800_000_000_000,
  expiresAt: 1_800_003_600_000,
  maxViews: 1,
};

test("API client puts no key material in request URLs, bodies, or receipt URLs", async () => {
  const calls: Array<{ url: string; init: RequestInit | undefined }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    if (url === "/api/secrets") {
      return new Response(
        JSON.stringify({
          secretId: "secret-id",
          expiresAt: 1_800_003_600_000,
          receiptToken: "receipt-token",
          receiptExpiresAt: 1_800_012_000_000,
          maxViews: 1,
        }),
        { status: 201, headers: { "content-type": "application/json" } },
      );
    }
    if (url === "/api/secrets/secret-id") {
      return new Response(
        JSON.stringify({
          secretId: "secret-id",
          expiresAt: 1_800_003_600_000,
          maxViews: 1,
          challenge: "challenge",
          challengeExpiresAt: 1_800_000_120_000,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url === "/api/secrets/secret-id/open") {
      return new Response(
        JSON.stringify({ envelope, viewToken: "view-token", burnedAt: 1_800_000_001_000 }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url === "/api/secrets/secret-id/decrypted") {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (url === "/api/secrets/secret-id/receipt") {
      return new Response(
        JSON.stringify({
          secretId: "secret-id",
          state: "available",
          createdAt: 1_800_000_000_000,
          expiresAt: 1_800_003_600_000,
          receiptExpiresAt: 1_800_012_000_000,
          opens: 0,
          decrypted: false,
          events: [{ type: "created", at: 1_800_000_000_000 }],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url === "/api/secrets/secret-id/revoke") {
      return new Response(JSON.stringify({ state: "revoked", revokedAt: 1_800_000_002_000 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response("{}", { status: 200 });
  }) as typeof fetch;

  try {
    await createSecret(envelope, 3600, "proof");
    await getChallenge("secret-id");
    await openSecret("secret-id", "challenge", "proof");
    await confirmDecrypted("secret-id", "view-token");
    await fetchReceipt("secret-id", "receipt-token");
    await revokeSecret("secret-id", "receipt-token");
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(calls.length, 6);
  for (const call of calls) {
    assert.equal(call.url.includes("#"), false, `fragment in ${call.url}`);
    assert.equal(call.url.includes("key"), false, `key in ${call.url}`);
    for (const [name, value] of Object.entries(call.init?.headers ?? {})) {
      assert.equal(String(value).includes("#"), false, `fragment in header ${name}`);
    }
  }

  const createBody = String(calls[0]?.init?.body ?? "");
  assert.equal(createBody.includes("#"), false);
  assert.equal(createBody.includes("key"), false);

  const openBody = String(calls[2]?.init?.body ?? "");
  assert.equal(openBody.includes("#"), false);
  assert.equal(openBody.includes("key"), false);
  assert.match(openBody, /"confirmation":"reveal"/);

  const openHeaders = new Headers(calls[2]?.init?.headers);
  assert.equal(openHeaders.get("X-Secret-Proof"), "proof");
  assert.equal(calls[2]?.url.includes("proof"), false);

  const receiptHeaders = new Headers(calls[4]?.init?.headers);
  assert.equal(receiptHeaders.get("X-Receipt-Token"), "receipt-token");
  assert.equal(calls[4]?.url.includes("receipt-token"), false);

  const revokeHeaders = new Headers(calls[5]?.init?.headers);
  assert.equal(revokeHeaders.get("X-Receipt-Token"), "receipt-token");
  assert.equal(revokeHeaders.get("X-Not-Saved-Confirm"), "revoke");
  assert.equal(calls[5]?.url.includes("receipt-token"), false);
});
