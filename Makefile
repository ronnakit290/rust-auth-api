BINARY := rust-auth-api
BASE_URL ?= http://127.0.0.1:8080

.PHONY: help dev build release test fmt clippy smoke docker docker-run clean

help:
	@echo "make dev      - run with hot reload-ish debug build (needs .env)"
	@echo "make test     - unit + integration tests"
	@echo "make build    - debug build"
	@echo "make release  - optimised binary in target/release"
	@echo "make fmt      - cargo fmt"
	@echo "make clippy   - lints (deny warnings)"
	@echo "make smoke    - end-to-end curl run against BASE_URL"
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

docker:
	docker build -t $(BINARY):local .

docker-run:
	docker run --rm -p 8080:8080 -v auth-data:/data \
		-e JWT_SECRET=$${JWT_SECRET:-dev-only-secret-dev-only-secret-1234} \
		-e BOOTSTRAP_ADMIN_EMAIL=admin@example.com \
		-e BOOTSTRAP_ADMIN_PASSWORD=Admin12345 \
		$(BINARY):local

clean:
	cargo clean
	rm -rf data
