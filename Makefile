.PHONY: build frontend test typecheck run loadtest clean

# Release builds pass VERSION=v1.0.0; it is reported by /metrics.
VERSION ?= dev

build: frontend
	go build -trimpath -ldflags="-s -w -X main.buildVersion=$(VERSION)" -o bin/unkeep ./backend

frontend:
	cd frontend && npm ci && npm run build

typecheck:
	cd frontend && npm run typecheck

test:
	cd frontend && npm test
	go test ./...

run:
	@test -f $(HOME)/.unkeep-session-secret || (openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' > $(HOME)/.unkeep-session-secret)
	SESSION_SECRET="$$(cat $(HOME)/.unkeep-session-secret)" go run ./backend

loadtest:
	go run ./test/loadtest -url=http://127.0.0.1:8091 -workers=32 -duration=10s -bytes=1024

clean:
	rm -rf bin frontend/node_modules
