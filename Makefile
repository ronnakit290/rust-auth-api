BINARY := rust-auth-api
BASE_URL ?= http://127.0.0.1:8080

.PHONY: help dev build release test fmt clippy smoke sso-smoke verify-token docker docker-run clean

help:
	@echo "make dev      - run with hot reload-ish debug build (needs .env)"
	@echo "make test     - unit + integration tests"
	@echo "make build    - debug build"
	@echo "make release  - optimised binary in target/release"
	@echo "make fmt      - cargo fmt"
	@echo "make clippy   - lints (deny warnings)"
	@echo "make smoke    - end-to-end curl run against BASE_URL"
	@echo "make sso-smoke- SSO walkthrough: app registration, PKCE, introspection"
	@echo "make verify-token - verify an issued JWT with the public JWKS (python)"
	@echo "make docker   - build the container image"
	@echo "make clean    - remove target/ and the local sqlite file"

dev:
	cargo run

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets -- -D warnings

smoke:
	BASE_URL=$(BASE_URL) ./scripts/smoke.sh

sso-smoke:
	BASE_URL=$(BASE_URL) ADMIN_EMAIL=$${ADMIN_EMAIL:-admin@example.com} \
		ADMIN_PASSWORD=$${ADMIN_PASSWORD:?set ADMIN_PASSWORD} ./scripts/sso-smoke.sh

verify-token:
	python3 scripts/verify_jwt.py

docker:
	docker build -t $(BINARY):local .

# Secrets come from the environment; nothing is baked into the image or repo.
docker-run:
	@test -n "$$JWT_SECRET" || { echo "JWT_SECRET is required"; exit 1; }
	@test -n "$$SSO_RSA_PRIVATE_KEY" || { echo "SSO_RSA_PRIVATE_KEY is required"; exit 1; }
	docker run --rm -p 8080:8080 -v auth-data:/data \
		-e JWT_SECRET="$$JWT_SECRET" \
		-e SSO_RSA_PRIVATE_KEY="$$SSO_RSA_PRIVATE_KEY" \
		-e SSO_ISSUER="$${SSO_ISSUER:-http://localhost:8080}" \
		-e BOOTSTRAP_ADMIN_EMAIL="$${BOOTSTRAP_ADMIN_EMAIL:-}" \
		-e BOOTSTRAP_ADMIN_PASSWORD="$${BOOTSTRAP_ADMIN_PASSWORD:-}" \
		$(BINARY):local

clean:
	cargo clean
	rm -rf data
