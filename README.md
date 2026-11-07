# TRACESEAL

TRACESEAL Phase 1 established TLSNotary feasibility. Phase 2 adds a local Rust Core Engine around the pinned TLSNotary attestation and presentation APIs. Phase 3 Steps C-E add verifier-derived evidence identity and local persistent storage. This remains a controlled demonstration, not a production trust service.

## Current scope

- TLSNotary Rust crates are pinned to `v0.1.0-alpha.15` (Git revision `47aee45b`). The separate `tlsnotary/` checkout remains at `d446234`, package version `0.1.0-alpha.15`.
- The CLI supports only `GET https://localhost:4443/trace-seal-{503,200,404,delay}` and only a finite set of explicit top-level response fields (`status`, `error`, `service`, `message`). It does not claim arbitrary public-site compatibility.
- The fixture serves deterministic TLS 1.2 responses. TLS 1.3 compatibility has not been tested or claimed.
- The Rust library has a local SQLite/filesystem evidence store.
- The `serve` command runs an HTTP API (loopback `127.0.0.1:3000` by default) with a built-in evidence console frontend at `/`. There is no authentication/ownership system and no Hedera integration.

## Build and test

Use the existing Rust/Cargo toolchain and an x64 Visual Studio developer environment so `cl.exe` and `link.exe` are on PATH. From the repository root:

```powershell
$env:RUSTUP_HOME = "$PWD\.toolchains\rustup"
$env:CARGO_HOME = "$PWD\.toolchains\cargo"
$env:CARGO_TARGET_DIR = "$PWD\tlsnotary\servers\target"
cargo build --locked --manifest-path core-engine/Cargo.toml
cargo test --locked --manifest-path core-engine/Cargo.toml
```

The integration test starts the controlled HTTPS fixture, conducts actual TLSNotary MPC-TLS proving, serializes an attestation and presentation, and starts a separate CLI verifier process. It also exercises HTTP 503/200/404, selected field disclosure, tampering, invalid/missing/malformed files, process startup failure/timeout, untrusted TLS, and unavailable fixture behavior. Storage tests cover SQLite initialization/reopen, exact-byte persistence, duplicate and concurrent submissions, immutable original verification records, separate reverification records, orphan recovery, database/artifact tampering, path traversal, and symlinks.

The crate's SQLite dependency is bundled and pinned so storage tests can run offline after the locked dependencies have been fetched once.

## Reproducible local demo

Open two x64 MSVC developer terminals at the repository root and set the existing toolchain variables as above. In the proving terminal, set the public, test-only demo attestor key. This known key is intentionally insecure and must not be used for real evidence.

```powershell
$env:TRACESEAL_TEST_ATTESTOR_KEY = '0101010101010101010101010101010101010101010101010101010101010101'
```

In terminal one, run the fixture:

```powershell
./tlsnotary/servers/target/debug/traceseal-core.exe fixture
```

In terminal two, generate and independently verify the 503 proof:

```powershell
./tlsnotary/servers/target/debug/traceseal-core.exe prove `
  --url https://localhost:4443/trace-seal-503 `
  --disclose status,error,service,message `
  --output ./artifacts
```

The command emits a JSON verification report and writes an atomic artifact package under `artifacts/` containing `request.json`, `attestation.tlsn`, `presentation.tlsn`, and `verification-report.json`. To independently re-run verification, use the emitted `Artifacts:` directory path:

```powershell
./tlsnotary/servers/target/debug/traceseal-core.exe verify `
  --attestation ./artifacts/<package>/attestation.tlsn `
  --presentation ./artifacts/<package>/presentation.tlsn
```

`inspect --package ./artifacts/<package>` displays the saved report; it does not perform a fresh verification. `--help` and `--version` describe the CLI.

## Architecture and disclosure model

`fixture` runs the project-owned HTTPS test service. `prove` validates the fixed HTTPS endpoint and disclosure allowlist, checks the TLS certificate with a preflight handshake, then makes the attested request over TLSNotary MPC-TLS. A local test notary signs the resulting authenticated commitments using the runtime demo key. The prover keeps `Secrets` in memory, uses the pinned TLSN JSON parser and reveals the selected key/value spans plus the HTTP request/status metadata, and writes only the attestation and portable presentation. The package is staged in a temporary directory and renamed into place only after the child verifier has returned a report.

`verify` calls the pinned TLSNotary `Presentation::verify` API, verifies the separately supplied attestation against the same signature, requires the configured demo signer key and trusted fixture CA, and checks the disclosed localhost GET and response status line. The presentation reveals response header names but masks header values. File presence or a matching hash alone never makes a report `VERIFIED`.

The JSON report contains `verification_status` (`VERIFIED`, `REJECTED`, or `ERROR`), actual HTTP status if disclosed, fields actually visible in the authenticated partial transcript, SHA-256 identifiers, CLI verifier version, process exit code when available, UTC verification time, and errors. The parser reports only selected fields visible in the proof. TLSNotary v0.1.0-alpha.15 provides transcript-range disclosure; TRACESEAL selects the whole top-level JSON key/value span. Nested-field selection, arbitrary JSON paths, request-body modes, arbitrary methods, redirects, compression, chunked responses, and arbitrary host handling are outside this implementation.

## Trust and security limits

The notary and prover run in the same local demo CLI process; only the presentation verifier runs as a separate process. The fixed test signer public key and local test CA demonstrate cryptographic consistency, not independent production attestor governance. The private demo key is supplied via `TRACESEAL_TEST_ATTESTOR_KEY`, is never written to artifacts or printed, and must be replaced by an independently operated notary before real use. The test TLS server keys are deliberately public test material. Do not reuse any of these keys or trust roots in deployed services.

Phase 1 artifacts remain in `phase1-artifacts/` with their original SHA-256 hashes documented in `docs/TECHNICAL_FEASIBILITY.md`. The root `.gitignore` excludes the workspace toolchain and nested upstream checkout; it does not exclude those Phase 1 artifacts.

The retained Phase 2 CLI demonstration is in `phase2-artifacts/1793930213453613000-20468/`; it contains the genuine 503 attestation/presentation, request manifest, and successful separate-verifier report.

## HTTP API and frontend

`traceseal-core serve` starts the Axum API on `127.0.0.1:3000` (override with `--bind`; non-loopback binds print a warning). Options: `--storage-dir` (default `evidence-store`), `--max-concurrency` (default 4), `--verifier-timeout-seconds` (default 60, capped at 120 by the engine).

Endpoints:

- `GET /` and `GET /app` â€” built-in evidence console (static HTML/JS, no build step, same-origin so no CORS is required).
- `GET /health` â€” service/schema/trust-policy status.
- `POST /api/v1/evidence` â€” multipart upload with fields `attestation`, `presentation`, `request_manifest`. Runs the real TLSNotary verifier subprocess, then stores the evidence. Returns `201` (`stored`) or `200` (`already_present`); `422` on cryptographic rejection, `413` on oversized fields, `503` when the verifier concurrency limit is reached.
- `GET /api/v1/evidence/{id}` â€” canonical evidence metadata plus the original verification report.
- `GET /api/v1/evidence/{id}/artifacts/{attestation|presentation|request_manifest}` â€” exact stored bytes with `ETag`/`x-artifact-sha256` headers.
- `GET /api/v1/evidence/{id}/verifications` â€” original plus reverification reports.
- `POST /api/v1/evidence/{id}/reverify` â€” re-runs the verifier on stored artifacts and appends a `REVERIFICATION` record.

The frontend submits real multipart uploads, displays verification outcomes, disclosed fields, artifact download links, and verification history, and surfaces backend errors. It contains no mock data.

For a guided walkthrough see `docs/SPONSOR_DEMO.md` (demonstration script) and `docs/DEMO_RUNBOOK.md` (exact startup commands). The end-to-end architecture is summarized in `docs/SPONSOR_DEMO.md` with a Mermaid diagram.

## Phase 3 Step E: local evidence storage

The library exposes `engine::verify_and_package`, which returns a `VerifiedEvidence` only after the controlled TLSNotary verifier succeeds and the Step C evidence payload and exact artifact hashes validate. Its fields and constructor are private; callers cannot pass a client report, `VERIFIED` flag, evidence ID, commitment, or filesystem path to the storage API. The prior `verify_and_identify` API remains available for callers that only need the identity record.

Initialize storage with an application-selected root path using `storage::EvidenceStore::open(root)`. Submit only the returned trusted value using `store(&verified)`, and retrieve validated metadata with `get_metadata(id)` or the metadata plus exact original bytes with `get(id)`. The current local layout is:

```text
<root>/
  metadata.sqlite3
  artifacts/<ts1_evidence_id>/
    attestation.tlsn
    presentation.tlsn
    request.json
  .staging/
```

SQLite schema version 1 stores the canonical Evidence Schema 1.0 record, searchable verification/proof/hash columns, a `READY` state, and three artifact-reference rows with generated storage keys, exact-byte SHA-256 values, and sizes. The trusted original verifier report is stored separately as an immutable `ORIGINAL` verification record. A subsequent successful `VerifiedEvidence` can be consumed by `record_reverification`; it appends a separate `REVERIFICATION` record and never changes the original, but it must have the same complete `EvidenceRecord`. An identical report cannot be replayed as a new verification record.

That equality is intentional in the approved identity design: the canonical payload committed by Step C contains both `verification.verifier_version` and `trust_policy_id`. Changing either field changes the canonical payload, commitment, and evidence ID. Step D currently accepts only the configured demo verifier and `demo-local-v1`, so it cannot produce a re-verification under a changed verifier version or policy. Do not loosen the storage equality check to attach a different-identity record to the old evidence ID. Supporting trust-policy/key rotation while retaining a stable evidence ID requires a future schema/identity version that separates immutable proof identity from append-only verification/trust assessments.

Files are staged and synced, then published under a generated evidence-ID directory before the SQLite transaction commits. The SQLite `BEGIN IMMEDIATE` transaction is acquired before staging and held through publication, so startup reconciliation and concurrent stores using the same database serialize with active writes. Identical records return `AlreadyPresent` after retrieval integrity checks; conflicting IDs are rejected without overwriting existing files. Startup reconciliation removes application staging entries and canonical evidence-ID directories with no committed database row. Unknown directories are left untouched.

Artifact retrieval rejects missing, symlinked, path-escaping, oversized, or modified files and rechecks file size, artifact SHA-256 values, payload hashes, canonical commitment, and evidence ID. On Unix, the storage root and child directories/files are mode 0700/0600 and directory entries are synced around publication. On Windows, filesystem permissions inherit the parent directory's ACL; this module does not configure or audit ACLs. SQLite and the filesystem are not one atomic transaction: incomplete uncommitted publications are cleaned on startup, while a committed record whose files are later lost or corrupted fails retrieval.

Filesystem safety is not race-proof against another local process that can modify the storage root concurrently. The implementation uses symlink metadata checks and canonical-path checks followed by ordinary path-based opens/reads; a privileged or same-user attacker able to swap filesystem entries between those steps may race a check. Restrictive root permissions/ACLs are part of the local threat boundary. Use an isolated storage directory not writable by untrusted local principals. Database/artifact hashes also do not authenticate both stores against an attacker able to rewrite them consistently.

This is local storage only. There is no HTTP surface, authentication, user ownership, or authorization; callers must not treat a matching evidence ID as access authorization. The current demo attestor key remains public and insecure, and prover/notary operation is not independent. Local hashes and SQLite consistency checks are not authenticated against an attacker who can rewrite both the database and artifact tree. Do not treat this implementation as production-secure or independently attested.

## Hedera anchoring (testnet)

TRACESEAL can anchor verified evidence to Hedera testnet as a public, independently inspectable audit layer. TLSNotary remains the cryptographic verification engine; Hedera provides timestamping and receipts only.

- **HCS** — audit topic receives `EVIDENCE_VERIFIED`, `RECEIPT_MINTED`, and `EVIDENCE_REVERIFIED` messages (evidence ID + commitment + metadata only; never proof files or disclosed data).
- **HTS** — the `TSVR` NFT collection ("TraceSeal Verified Evidence", max supply 1000) mints one receipt NFT per unique commitment; the 32-byte SHA-256 commitment is the NFT metadata.
- **Mirror Node** — `https://testnet.mirrornode.hedera.com` independently confirms on-chain records and compares commitments.

Architecture: a Node.js sidecar (`hedera/`, official `@hashgraph/sdk`) performs all signing and transactions; the Rust backend shells out to it and keeps an idempotent SQLite outbox (`hedera_events`, `hedera_receipts`, schema v2). Anchoring is asynchronous, deduplicated, and fully optional — local verification works with no Hedera configuration.

New API endpoints:

- `GET /api/v1/hedera/status` — configuration + account status (no secrets)
- `GET /api/v1/evidence/{id}/blockchain` — audit events + NFT receipt (`?verify=1` adds live Mirror Node checks)
- `POST /api/v1/evidence/{id}/anchor` — enqueue + drain the outbox (idempotent)

Setup: `cd hedera && npm install`, copy `.env.example` to `.env`, run `node src/cli.mjs setup-topic` and `setup-nft`, then set the `HEDERA_*` env vars before `traceseal-core serve`. See `hedera/README.md`.
