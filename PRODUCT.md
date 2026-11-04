# Product

<!-- impeccable:product-schema 1 -->

## Platform
web

## Users
Primary user: a person (most often a developer, operator, or teammate) who needs to hand a short secret — credential, token, note — to a specific recipient over an untrusted channel, with the guarantee that the secret can be read exactly once and leaves no durable trace. Secondary audience: the recipient who opens the link once. [INFERENCE from README/API/docs; not confirmed by user.]

## Product Purpose
unkeep is a zero-knowledge, one-view secret-sharing tool. The browser encrypts a short secret with AES-256-GCM; the server stores ciphertext only and releases it exactly once. An optional passphrase wraps the key, and the sender can burn an unread link. Success means a secret is delivered once to the intended recipient and then unrecoverable, with no account, no durable storage, and no server-side plaintext.

## Positioning
Client-side encryption with the key carried only in the URL fragment, so the server never sees plaintext or the key and cannot recover it even if compelled; burn-on-release plus sender-controlled revoke; no account, no analytics, no outbound calls, no durable database. [INFERENCE]

## Operating Context
Web browser on desktop or mobile; secrets shared as links via chat/email; deployment as a single Go static binary or scratch container, optionally backed by a volatile Valkey for multi-replica. Secrets are ephemeral (minutes to days TTL). [INFERENCE]

## Capabilities and Constraints
- AES-256-GCM in browser; key only in URL fragment; fresh 12-byte IV per encryption.
- maxViews fixed at 1; burn on release; failed decrypt still burns.
- Optional passphrase wrapping (PBKDF2-SHA256 600k rounds); wrong passphrase burns nothing; client-side throttle.
- Sender revoke of unread links; receipt/event log (created, link_opened, burned, decrypted, expired, revoked).
- In-process storage by default; optional volatile Valkey; nothing durable; restart loses unread data.
- Strict CSP, no-referrer, frame denial, HSTS, no-store, robots disallow.
- Rate limits per process; MAX_SECRETS/MAX_RECEIPTS/MAX_TOTAL_MB caps.
- Bundle budgets: app.js 45,056 B, styles.css 30,720 B, index.html 8,192 B. [INFERENCE]

## Brand Commitments
Name: unkeep (connotation: "neglected"/discarded — the secret is kept only long enough to be read once). Voice: no first person in user-facing copy; errors say "The stored copy…"; destruction is the only use of red. [INFERENCE from memory/DESIGN.md]

## Evidence on Hand
README.md, docs/getting_started.md, DESIGN.md (incumbent visual system), docs/create.png (screenshot). No user testimonials or case studies. [INFERENCE]

## Product Principles
- Zero knowledge: the server must never be able to read a secret.
- One view: a released secret is gone; there is no second chance.
- No accounts, no durable state: nothing to breach later.
- Sender agency: the sender can burn an unread link.
- Restraint in copy and color: red reserved for destruction; everything else quiet. [INFERENCE]

## Accessibility & Inclusion
[UNDECIDED] No product-specific accessibility standard recorded; incumbent targets WCAG AA contrast on light/dark. [INFERENCE]
