# TraceSeal — Deployment Guide

## Architecture

Single-process deployment. `traceseal-core` is one Rust binary that serves:

- the embedded frontend (`/`, `/app`) — no separate frontend build/deploy
- the JSON API (`/api/v1/*`, `/health`)
- the TLSNotary verifier (re-executes itself via `current_exe()`)

The Hedera integration is a Node.js sidecar (`hedera/src/cli.mjs`) invoked as
a subprocess; it needs Node.js >= 20.12 and `hedera/node_modules`
(`npm ci` in `hedera/`).

```
client ──HTTPS──> reverse proxy ──> traceseal-core :3000 (loopback)
                                        │
                                        ├─ SQLite + artifacts  (/data, persistent)
                                        └─ node hedera/src/cli.mjs ──> Hedera testnet
```

## Persistence

- SQLite DB + evidence artifacts live under the storage dir
  (`--storage-dir`, default `evidence-store`; `/data/evidence-store` in Docker).
- The outbox (`hedera_events`) and receipts (`hedera_receipts`) tables live in
  the same SQLite file — Hedera transaction IDs and retry state survive
  restarts by design (UNIQUE dedupe keys prevent double-mint).
- **Never** run two instances against the same storage dir.

### Backup

```powershell
# Stop the service first for a consistent SQLite copy.
curl http://127.0.0.1:3000/health   # confirm up, then stop service
# Docker:
docker run --rm -v traceseal-data:/data -v ${PWD}:/backup alpine \
  tar czf /backup/traceseal-data-$(date +%F).tar.gz -C /data .
```

Restore: stop service, extract archive into the storage dir, restart.
Verify with `PRAGMA integrity_check` on the SQLite file.

## Deploy options

### A. Docker (recommended)

```bash
docker compose -f deploy/docker-compose.yml up -d --build
```

- Non-root user, healthcheck, restart policy, resource limits built in.
- Named volume `traceseal-data` holds all persistent state.
- Binds `127.0.0.1:3000` — put Caddy/nginx/Cloudflare Tunnel in front for HTTPS.

### B. Bare VM + systemd

See `deploy/traceseal.service`. Layout:

```
/opt/traceseal/bin/traceseal-core      # release binary
/opt/traceseal/hedera/src/cli.mjs      # sidecar
/opt/traceseal/hedera/node_modules/    # npm ci --omit=dev
/opt/traceseal/.env                    # HEDERA_* (chmod 600)
/var/lib/traceseal/evidence-store/     # SQLite + artifacts
```

Build the binary on the host or CI:
`cargo build --release --manifest-path core-engine/Cargo.toml`

### C. Vercel / serverless — NOT SUPPORTED

SQLite + filesystem artifact storage + a Node sidecar + long-running TLS
verification do not fit serverless. Do not deploy the backend to Vercel.
The frontend is embedded in the binary; there is nothing to deploy separately.

## Environment variables

See `deploy/.env.example`. Required for Hedera: `HEDERA_ACCOUNT_ID`,
`HEDERA_PRIVATE_KEY`, `HEDERA_TOPIC_ID`, `HEDERA_NFT_TOKEN_ID`.
Without them the API still works — evidence verifies and stores locally;
Hedera anchoring is simply skipped (outbox stays PENDING).

Secrets live only in `.env` (gitignored) or the host secret manager.
Never in frontend env vars, logs, or git.

## Security notes

- The app warns when binding non-loopback. Always front it with TLS
  (Caddy/nginx/Cloudflare Tunnel) and keep `--bind 127.0.0.1:3000`.
- This is a single-user demo prototype: there is NO authentication on the
  upload endpoint. Do not expose it publicly without adding authn/authz,
  rate limiting, and evidence-ownership controls first.
- Request size limits are enforced in the handler (16 MiB artifacts,
  64 KiB manifest).

## Current testnet resources (created 2026-11-07)

- Account: `0.0.11337423` (testnet, ED25519 key)
- HCS topic: `0.0.11349560` (memo `traceseal-audit`)
- HTS NFT: `0.0.11349565` "TraceSeal Verified Evidence" / TSVR
  (supply INFINITE — testnet rejected max_supply=1000 with
  INVALID_TOKEN_MAX_SUPPLY; revisit if a bounded supply is required)
