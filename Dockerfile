# ---- build -----------------------------------------------------------------
FROM rust:1-slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependency compilation separately from application code.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
COPY migrations ./migrations
RUN touch src/main.rs && cargo build --release --locked

# ---- runtime ---------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 appuser

WORKDIR /app
COPY --from=builder /app/target/release/rust-auth-api /usr/local/bin/rust-auth-api
COPY migrations ./migrations

RUN mkdir -p /data && chown -R appuser:appuser /data /app
USER appuser

ENV APP_ENV=production \
    HOST=0.0.0.0 \
    PORT=8080 \
    DATABASE_URL=sqlite:///data/auth.db?mode=rwc

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["rust-auth-api"]
