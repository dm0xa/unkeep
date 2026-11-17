1.1.0

Quicker everywhere: compressed assets, inlined CSS, lighter responses, and less work per request.
The reveal flow keeps the link when the network hiccups, and warns the sender before leaving the result page.
A one-view receipt settles after the burn instead of polling forever.
The passphrase generator makes a short five-word phrase (~25 bits); type your own for anything valuable.
Proxied deployments get the real client address for rate limits, and Valkey mode now requires SESSION_SECRET.

1.0.0

First release. Zero-knowledge, one-view secret sharing: the browser encrypts a short secret with AES-256-GCM, the key lives only in the URL fragment, and the server releases the ciphertext exactly once.
