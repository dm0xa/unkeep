# Changelog

All notable changes to unkeep are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.0 - 2026-11-05

First release. Zero-knowledge, one-view secret sharing: the browser encrypts a
short secret with AES-256-GCM, the key lives only in the URL fragment, and the
server releases the ciphertext exactly once.

### Added

- One-view secrets: `POST /api/secrets`, challenge, then an atomic burn on
  `POST /api/secrets/{id}/open`; a second open returns `410`.
- Optional passphrase-wrapped links using PBKDF2-SHA256 (600k rounds) and
  AES-GCM key wrapping; a wrong passphrase burns nothing.
- Client-side passphrase unlock limiter: first two failures free, then 5 s, 15 s,
  60 s, 3 min, and 5 min cooldowns per link in `sessionStorage`.
- Key proof (`SHA-256("not-saved:open-proof:v1" || key)`) stored only as a hash,
  so a link without the key cannot burn a secret.
- Sender revoke with the receipt token via `POST /api/secrets/{id}/revoke`;
  idempotent, requires an unread secret.
- Receipts with a deduped `link_opened` event, open counts, and a per-secret
  event log: `created`, `link_opened`, `decrypt_attempted`, `burned`,
  `decrypted`, `expired`, `revoked`.
- In-process store (default) and an optional volatile Valkey store using Lua for
  atomic fetch/delete, receipt updates, and capacity indexes.
- Two deployment recipes: single process or Valkey plus N replicas sharing one
  `SESSION_SECRET`; both lose unread data on restart by design.
- Prometheus `/metrics` behind `METRICS_TOKEN`, plus `/healthz` and `/readyz`.
- Embedded TypeScript SPA with create, reveal, receipt, and error views; light
  and dark themes; self-hosted Archivo variable font.
- Crawler-safe `/s/{id}` shell: previews see no ciphertext and burn nothing.
- Per-IP token-bucket rate limits keyed by an HMAC of the client IP.
- Static Linux binary in a `FROM scratch` image: UID 65532, read-only root,
  no shell, no volumes, no outbound calls.
- GitHub Actions CI: vet, tests with `-race`, Valkey integration, frontend tests
  and bundle check, container smoke test, `govulncheck`.
- Tag-driven release: static binaries for linux/darwin on amd64/arm64, a
  multi-arch `ghcr.io` image, and a GitHub release with `SHA256SUMS`.

### Changed

- Project, module, binary, and images renamed to `unkeep`. Cryptographic labels,
  the `X-Not-Saved-Confirm` header, the `ns_sid` cookie, and the `ns:` Valkey
  prefix are frozen wire identifiers so old links keep working.
- No first-person copy in the interface.

### Security

- AES-256-GCM with a fresh 12-byte IV per secret; tampered IV, tag, or
  ciphertext is rejected.
- Server never sees the plaintext or the key; it stores ciphertext, IV, tag,
  TTL, view metadata, and the key proof hash.
- Burn happens on release; a failed decrypt still burns.
- In-process mode zeroes secret buffers on burn, revoke, expiry, receipt
  eviction, and shutdown. Valkey mode cannot promise allocator-level zeroing.
- Receipt and view tokens are hashed and compared in constant time.
- HMAC-signed, session-bound challenges that expire in two minutes; the burn is
  the replay defense.
- HSTS, strict CSP, `nosniff`, `no-referrer`, frame denial, COOP/CORP,
  Permissions Policy, `no-store`, and `X-Robots-Tag` on every response.
- Logs carry route pattern, status, duration, and error class only.
- Opt-in Valkey integration tests for atomic burn and key deletion.

### Performance

- Frontend bundles stay within enforced budgets: 44 KiB JS, 30 KiB CSS, 8 KiB
  HTML (`frontend/scripts/check-budget.mjs`).
- Local full-flow load test, 32 workers, in-process store: 8,391 cycles/s and
  41,954 requests/s with zero errors; full-cycle p99 9.4 ms.
- Default cold load on localhost: TTFB 0.55 ms, FCP/LCP 719 ms, CLS 0.

### Known limits

- Restart loses unread secrets and receipts in both storage modes.
- The full link is a bearer key and can leak through history, screenshots, and
  chat backups.
- The unlock limiter is client-side and bypassable; PBKDF2 cost is the only
  defense against offline guessing.
- Revoke needs the receipt token. A lost passphrase cannot be reset.
- Valkey mode assumes a single instance; capacity indexes are not
  Cluster-safe. Multiple replicas need edge or shared rate limiting.
- No malware defense and no CAPTCHA; `/metrics` is opt-in.
