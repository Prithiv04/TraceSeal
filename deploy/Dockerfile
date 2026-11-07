# TraceSeal production image.
# Single artifact: traceseal-core binary (API + embedded frontend + verifier
# re-exec) + Node.js Hedera sidecar + hedera/node_modules.
#
# Build context MUST be the repository root:
#   docker build -f deploy/Dockerfile -t traceseal:latest .

# ---------- stage 1: Rust build ----------
FROM rust:1.85-bookworm AS rust-build
WORKDIR /src
# core-engine has its own lockfile; copy manifests first for layer caching.
COPY core-engine/Cargo.toml core-engine/Cargo.lock ./core-engine/
COPY core-engine/src ./core-engine/src
COPY core-engine/frontend ./core-engine/frontend
COPY core-engine/tests ./core-engine/tests
WORKDIR /src/core-engine
RUN cargo build --release --locked --offline 2>/dev/null \
 || cargo build --release --locked

# ---------- stage 2: Node sidecar deps ----------
FROM node:22-bookworm-slim AS node-deps
WORKDIR /sidecar
COPY hedera/package.json hedera/package-lock.json ./
RUN npm ci --omit=dev

# ---------- stage 3: runtime ----------
FROM debian:bookworm-slim

# Node.js runtime for the Hedera sidecar (official @hashgraph/sdk).
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Non-root service user.
RUN useradd --system --uid 10001 --create-home traceseal

WORKDIR /app

# Rust binary (API + embedded frontend + verifier self re-exec).
COPY --from=rust-build /src/core-engine/target/release/traceseal-core /usr/local/bin/traceseal-core

# Hedera sidecar: source + production node_modules.
COPY hedera/src /app/hedera/src
COPY --from=node-deps /sidecar/node_modules /app/hedera/node_modules
COPY hedera/package.json /app/hedera/package.json

# Persistent data root (SQLite + evidence artifacts). Mounted at runtime.
RUN mkdir -p /data/evidence-store && chown -R traceseal:traceseal /data /app
VOLUME ["/data"]

USER traceseal
ENV TRACESEAL_STORAGE_DIR=/data/evidence-store \
    HEDERA_SIDECAR=/app/hedera/src/cli.mjs \
    NODE_ENV=production

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3000/health || exit 1

# Loopback bind inside the container; the reverse proxy / port mapping
# exposes it. Override with --bind 0.0.0.0:3000 only behind a proxy/firewall.
ENTRYPOINT ["traceseal-core", "serve", "--bind", "127.0.0.1:3000", "--storage-dir", "/data/evidence-store"]
