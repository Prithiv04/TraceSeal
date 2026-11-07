# TraceSeal Hedera sidecar

Node.js sidecar that gives the Rust `traceseal-core` backend access to the
official Hedera JavaScript SDK (`@hashgraph/sdk`) for HCS audit events, HTS
NFT receipts, and Mirror Node queries.

The Rust backend never signs transactions itself — it shells out to this
CLI and parses a single JSON line from stdout. Private keys live only in
environment variables.

## Setup

```bash
cd hedera
npm install
cp .env.example .env   # fill in real testnet values
```

Required environment variables (also read by `traceseal-core serve`):

| Variable | Purpose |
|---|---|
| `HEDERA_NETWORK` | `testnet` (default), `previewnet`, or `mainnet` |
| `HEDERA_ACCOUNT_ID` | Operator account, e.g. `0.0.12345` |
| `HEDERA_PRIVATE_KEY` | DER-encoded private key (`302e02…`) or raw hex |
| `HEDERA_TOPIC_ID` | HCS audit topic (create with `setup-topic`) |
| `HEDERA_NFT_TOKEN_ID` | TSVR NFT collection (create with `setup-nft`) |
| `HEDERA_MIRROR_NODE_URL` | Defaults to `https://<network>.mirrornode.hedera.com` |

## One-time provisioning

```bash
# 1. Create the HCS audit topic
node src/cli.mjs setup-topic
# → { "topic_id": "0.0.xxxxxx", ... }  → set HEDERA_TOPIC_ID

# 2. Create the TSVR NFT collection (max supply 1000)
node src/cli.mjs setup-nft
# → { "token_id": "0.0.xxxxxx", ... }  → set HEDERA_NFT_TOKEN_ID
```

## Commands

| Command | Purpose |
|---|---|
| `status` | Config + account balance (no secrets echoed) |
| `setup-topic` | Create HCS topic |
| `setup-nft` | Create TSVR NFT collection + KYC treasury |
| `publish --message <json>` | Submit HCS audit message |
| `mint --metadata-hex <hex>` | Mint NFT with hex metadata (≤100 bytes) |
| `mirror-topic --topic-id … --sequence …` | Fetch + decode HCS message |
| `mirror-nft --token-id … --serial …` | Fetch NFT info |
| `mirror-tx --transaction-id …` | Fetch transaction details |

Every command prints one JSON object to stdout; errors use
`{"ok":false,"error":{"code","message"}}`.

## Audit message schema

```json
{
  "schema": "traceseal.audit.v1",
  "event": "EVIDENCE_VERIFIED | RECEIPT_MINTED | EVIDENCE_REVERIFIED",
  "evidence_id": "ts1_…",
  "commitment": "sha256:…",
  "network": "testnet",
  "verifier_version": "…",
  "trust_policy_id": "…",
  "anchored_at": "…"
}
```

Only identifiers and hashes are published — never proof files, keys, or
disclosed response data.
