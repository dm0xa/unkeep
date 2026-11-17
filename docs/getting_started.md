# Getting started with unkeep

One-view secret sharing. The browser encrypts with AES-256-GCM; the key stays in
the URL fragment; the server releases ciphertext once.

| Mode | Valkey | Replicas | Restart |
| --- | --- | --- | --- |
| In-process (default) | No | No | Unread data lost |
| Valkey | Yes, memory-only | Yes | Unread data lost if Valkey is lost |

Valkey is optional. Without `VALKEY_URL`, the original single-binary mode still
applies.

## 1. Single binary

Requires Go 1.26+. Node 22+ only if rebuilding the frontend.

```bash
make build
./bin/unkeep
```

Or build directly; `frontend/dist` and `vendor/` are committed:

```bash
go build -trimpath -ldflags="-s -w" -o bin/unkeep ./backend
./bin/unkeep
```

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

Open `http://127.0.0.1:8080`. Restart loses every unread secret and receipt.

## 2. Docker, in-process

```bash
docker build -t unkeep .
docker run --rm --name unkeep \
  -p 127.0.0.1:8080:8080 \
  --read-only --cap-drop=ALL \
  --security-opt no-new-privileges:true \
  --memory=512m --memory-swap=512m --ulimit core=0 \
  -e GOMEMLIMIT=400MiB -e GOTRACEBACK=none \
  unkeep
```

Or use the single-instance Compose file:

```bash
docker compose up -d --build
docker compose ps
```

The image is a scratch static binary, UID 65532, no shell, no volumes. Use
`/healthz` and `/readyz` from your orchestrator.

## 3. Valkey + binary

Start memory-only Valkey:

```bash
VALKEY_PASSWORD="$(openssl rand -hex 24)"

docker run -d --name unkeep-valkey \
  --user 999:1000 --read-only --cap-drop=ALL \
  --security-opt no-new-privileges:true \
  --memory=2304m --memory-swap=2304m --ulimit core=0 \
  -p 127.0.0.1:6380:6379 \
  valkey/valkey:9-alpine \
  valkey-server --save "" --appendonly no \
    --maxmemory 2gb --maxmemory-policy noeviction \
    --requirepass "$VALKEY_PASSWORD"
```

Run the app:

```bash
SESSION_SECRET="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"

env VALKEY_URL="redis://:$VALKEY_PASSWORD@127.0.0.1:6380/0" \
  VALKEY_PREFIX="ns:" \
  SESSION_SECRET="$SESSION_SECRET" \
  ./bin/unkeep
```

`SESSION_SECRET` is optional for one process, required for more than one. If
Valkey goes down, `/readyz` and API calls return `503`, not a false `410`.

Verify no persistence:

```bash
docker exec unkeep-valkey valkey-cli -a "$VALKEY_PASSWORD" \
  CONFIG GET save appendonly maxmemory-policy
```

Expected: blank `save`, `appendonly no`, `noeviction`.

## 4. Compose with Valkey

```bash
SESSION_SECRET="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
VALKEY_PASSWORD="$(openssl rand -hex 24)"

env SESSION_SECRET="$SESSION_SECRET" VALKEY_PASSWORD="$VALKEY_PASSWORD" sh -c '
  docker compose -f docker-compose.valkey.yml up -d --build &&
  docker compose -f docker-compose.valkey.yml ps
'
```

Open `http://127.0.0.1:8080`. Only the app port is published; Valkey is internal,
read-only, non-root, and has no volume.

Check Valkey wrote nothing:

```bash
env SESSION_SECRET="$SESSION_SECRET" VALKEY_PASSWORD="$VALKEY_PASSWORD" \
  docker compose -f docker-compose.valkey.yml exec valkey find /data -type f
```

It should print nothing. Stop with the same env:

```bash
env SESSION_SECRET="$SESSION_SECRET" VALKEY_PASSWORD="$VALKEY_PASSWORD" \
  docker compose -f docker-compose.valkey.yml down
```

## 5. Multiple replicas

```bash
env PORT=8091 VALKEY_URL="redis://:$VALKEY_PASSWORD@127.0.0.1:6380/0" \
  VALKEY_PREFIX=ns: SESSION_SECRET="$SESSION_SECRET" ./bin/unkeep

env PORT=8092 VALKEY_URL="redis://:$VALKEY_PASSWORD@127.0.0.1:6380/0" \
  VALKEY_PREFIX=ns: SESSION_SECRET="$SESSION_SECRET" ./bin/unkeep
```

Put nginx/ALB/ingress in front. Any replica serves any ID. The same
`SESSION_SECRET` is mandatory.

Behind a TLS proxy:

```bash
env HOST=0.0.0.0 PORT=8080 TRUST_PROXY=1 \
  ALLOWED_HOSTS=app.example.com \
  VALKEY_URL="rediss://user:password@valkey.internal:6379/0" \
  SESSION_SECRET="$SESSION_SECRET" \
  ./bin/unkeep
```

Only trust proxy headers when the proxy overwrites them. `TRUST_PROXY_HOPS=1`
means one proxy appends to `X-Forwarded-For`; raise it if you run more. With
`VALKEY_URL` set, a missing `SESSION_SECRET` is a startup error, not a silently
per-process key that breaks challenges across replicas.

## Essentials

| Variable | Default | Notes |
| --- | --- | --- |
| `PORT` | `8080` | Bind port. |
| `VALKEY_URL` | empty | Empty = in-process. |
| `VALKEY_PREFIX` | `ns:` | Valkey namespace. |
| `SESSION_SECRET` | generated | Required for multiple replicas. |
| `ALLOWED_HOSTS` | loopback | Public hostnames. |
| `TRUST_PROXY` | `false` | Trust proxy headers. |
| `MAX_SECRETS` | `10000` | Live-secret cap. |
| `MAX_RECEIPTS` | `50000` | Receipt cap. |
| `MAX_TOTAL_MB` | `64` | Ciphertext/memory cap. |
| `MAX_BODY_KB` | `64` | Request body cap. |

Full table: [README.md](../README.md#configuration).

## Deletion

- In-process mode zeroes secret buffers on burn, revoke, expiry, sweep, and
  shutdown. Receipt hashes are wiped when the receipt is removed.
- Valkey mode deletes secret keys via Lua and receipt/event keys via TTL. It
  cannot guarantee allocator-level zeroing; strict wipe requires in-process mode.

## No secret data on disk

- No Valkey volumes, RDB, AOF, managed backups, or snapshots.
- No swap: use `--memory-swap` equal to `--memory`.
- No core dumps: `--ulimit core=0`, `GOTRACEBACK=none`.
- Read-only container roots.
- No command logging that captures ciphertext.
- Container logs must contain only operational metadata.

## Tests

```bash
go test ./...
go test -race ./...
cd frontend && npm test && npm run typecheck
```

Valkey integration:

```bash
docker run -d --rm --name unkeep-valkey-test \
  -p 127.0.0.1:6380:6379 \
  valkey/valkey:9-alpine \
  valkey-server --save "" --appendonly no --maxmemory 256mb \
  --maxmemory-policy noeviction

VALKEY_URL=redis://127.0.0.1:6380/0 \
  go test ./backend -run 'Valkey|APIWithValkey'
```

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Port in use | Use `PORT=8091` or stop the other process. |
| `503 store_unavailable` | Check Valkey, `VALKEY_URL`, TLS, `/readyz`. |
| `410` immediately | Burned, expired, revoked, or Valkey restarted. |
| `503 busy` | Capacity reached; wait or raise the cap. |
| App exits at startup | Check Valkey ping and `SESSION_SECRET`. |
| Compose asks for secrets | Pass `SESSION_SECRET` and `VALKEY_PASSWORD` with `env`. |
| `npm` missing | Use direct `go build` with committed `frontend/dist`. |

## Security reminders

- The full link is a bearer key. Send it only to the recipient.
- Links can leak through history, screenshots, and chat backups.
- Keep the separate receipt link to monitor or revoke.
- A failed decrypt still burns. A lost passphrase or receipt token is
  unrecoverable.
- This is a one-view delivery mechanism, not durable secret storage.
