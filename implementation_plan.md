# TRACESEAL implementation plan

## Current status (2026-11-06)

The starting workspace was empty. Existing work was not overwritten.

### Phase 1 - TLSNotary feasibility: proof of concept passed

- [x] Inspect the official TLSNotary implementation and documentation.
- [x] Preserve `tlsn-extension` at commit `d446234`, package version `0.1.0-alpha.15`, and the verifier's TLSNotary tag `v0.1.0-alpha.15`.
- [x] Verify the MSVC x64 compiler and linker using Visual Studio 18 `VsDevCmd.bat`.
- [x] Build the official extension verifier and start it on port 7047; its `/health` endpoint returned `ok`.
- [x] Run the official TLSNotary core attestation example against the local HTTPS fixture, receiving HTTP 503 with the expected TRACESEAL JSON fields.
- [x] Persist the signed attestation and selectively disclosed presentation.
- [x] Verify the presentation in a separate official verifier process.
- [x] Tamper with a disclosed response field in the serialized presentation and confirm cryptographic verification failure.
- [x] Restore the original artifact and confirm its hash is unchanged.

**Phase 1 result:** TLSNotary's pinned Rust core can generate, serialize, independently verify, and reject a tampered attestation/presentation for a genuine HTTPS 503 exchange. The proof of concept uses the official core's local test Notary and explicit test CA; it does not establish a production trust model. The browser extension's `prove()` flow was not used to create this portable attestation. No TLS 1.3 support claim was tested or made.

### Later phases

- [x] Phase 2: Core Engine local proof pipeline (controlled localhost demo complete; production trust model remains a gate).
- [ ] Phase 3: evidence backend, secure storage, and canonical evidence commitments.
- [ ] Phase 4: genuine Hedera testnet HCS submission and Mirror Node lookup (requires configured account/topic and credentials).
- [ ] Phase 5: public receipts, verification, and tampering demonstration integrated with the application.
- [ ] Phase 6: frontend backed by actual service data.
- [ ] Phase 7: end-to-end validation and documentation.

## Current implementation result

Phase 1 feasibility and the controlled Phase 2 Core Engine vertical slice are demonstrated. No TRACESEAL frontend, application backend, or Hedera functionality has been implemented, and no Hedera transaction exists.

### Environment and commands

- Rust/Cargo `1.99.1` active from the existing workspace-local toolchain.
- Visual Studio 18 x64 environment initialized with `VsDevCmd.bat`; `where cl.exe`, `where link.exe`, and `cl.exe /Bv` succeeded. The plain PowerShell PATH does not expose these until the developer environment is initialized.
- `cargo run --locked -p tlsn-verifier-server` in `tlsnotary/servers/` compiled in 4m30s and launched the server on `0.0.0.0:7047`; `curl.exe http://localhost:7047/health` returned HTTP 200 and `ok`. The server was stopped after the health check.
- `cargo run --locked -p tlsn-server-fixture --bin tlsn-server-fixture` launched the pinned TLSN test fixture on port 4000.
- The pinned core's `attestation_prove` example generated `phase1-artifacts/example-json.attestation.tlsn` (3,114 bytes) and an intermediate secrets file. The secrets file was removed after presentation generation; it is not needed for verification.
- The `attestation_present` example generated `phase1-artifacts/example-json.presentation.tlsn` (5,897 bytes).
- The independent `attestation_verify` example exited 0 and verified `test-server.io`, HTTP `503 Service Unavailable`, and the disclosed JSON fields `status=503`, `error=Service Unavailable`, `service=TRACESEAL Demo API`, and the requested temporary-unavailability message.
- Tampering byte offset 4740 in the serialized `Service Unavailable` disclosure caused the verifier to reject with `TranscriptProofError { kind: Hash, source: "hash opening does not match any commitment" }` (exit 101). Original presentation SHA-256 after restoration: `FC35585F3B8BEE916B5CFF4B637D2329C95947FF98BE8631F138E6CEA63BF3E8`.
- Temporary test-only source edits were made to the Cargo-cached TLSN fixture/example to produce the requested HTTP 503 and disclose the relevant fields, then restored byte-for-byte. The `tlsn-extension` checkout remains at commit `d446234` with no source changes.
- No frontend, backend, or Hedera implementation was started.

## Phase 2 plan (2026-11-06)

### Audit findings

- TRACESEAL root has no Rust/Python package, root `README.md`, CLI, or root tests. Existing app-related code is entirely inside `tlsnotary/` and will remain untouched.
- Reusable protocol path is the pinned TLSN core attestation API and its `attestation_prove`, `attestation_present`, and `attestation_verify` examples in Cargo's checkout. Reusable TLS protocol/verification implementation remains the upstream `tlsn` crate; no custom proof format or cryptography will be introduced.
- The upstream extension verifier is built and has source-level integration tests, but its browser `prove()` path does not export the self-contained presentation used in Phase 1. Core Engine will use the pinned Rust core attestation/presentation workflow and a separate verifier subprocess.
- Phase 1 artifact hashes were rechecked and remain unchanged. The intermediate prover secrets file is absent.
- Existing TLSN crate lock/pins are preserved: extension `d446234` / `0.1.0-alpha.15`; `tlsn` `v0.1.0-alpha.15`.

### Phase 2 implementation files (TRACESEAL-owned only)

- `core-engine/Cargo.toml` - Rust package, explicit pinned upstream dependency and existing-version dependencies.
- `core-engine/src/lib.rs` - typed request/disclosure/report models, input/path validation, TLSN proving and presentation generation, independent verification, and report parsing.
- `core-engine/src/main.rs` - CLI (`fixture`, `prove`, `verify`, `inspect`) with JSON output and process-level verifier invocation.
- `core-engine/src/fixture.rs` - controlled TLS 1.2 HTTPS fixture with deterministic 503, 200, 404, and delayed routes.
- `core-engine/tests/engine.rs` - unit/error tests and real cryptographic integration tests, clearly separated by test name/configuration.
- `core-engine/tests/fixtures/README.md` plus public test-only CA/server certificate/key material, including an untrusted identity for TLS rejection coverage; never production trust.
- `phase2-artifacts/<id>/` - retained genuine HTTPS 503 attestation, presentation, request manifest, and verifier report from the CLI demo.
- `README.md` - Core Engine setup, exact Phase 2 workflow, limitations, commands, test results.
- `docs/TECHNICAL_FEASIBILITY.md` - append actual Core Engine architecture, results, and remaining trust/runtime limits.
- `implementation_plan.md` - update this checklist and record the final Phase 2 commands and results.

### Implementation order and acceptance

1. [x] Create the crate and fixture using project-owned source and test-only TLS materials; leave Cargo cache and `tlsnotary/` untouched.
2. [x] Implement `prove` with fixed HTTPS endpoint/disclosure validation, genuine TLSN MPC-TLS request, signed attestation, selected transcript-range presentation, non-persistent prover secrets, and temporary-package publication.
3. [x] Implement separate-process `verify` using pinned TLSNotary presentation verification, trusted demo key/CA checks, transcript parsing, and JSON evidence reporting.
4. [x] Add input/path/error tests, modified attestation and presentation rejection, missing/malformed artifacts, verifier startup/timeout, connection/TLS/HTTP timeout behavior.
5. [x] Run real HTTPS fixture proofs and independent verification for 503, 200, and 404. Tampering and invalid/missing artifacts fail closed.

### Phase 2 execution result (2026-11-06)

- Root Git branch: local `development`, based on fetched `origin/main` (`25e871b`). GitHub exposed only `main`; no remote development branch existed. The workspace changes are unpushed. Root `.gitignore` excludes `.toolchains/` and the nested upstream `tlsnotary/` checkout; no `git add .` was used.
- MSVC x64 compiler and linker were resolved from the Visual Studio 18 developer environment: `cl.exe` 19.51.36260 and `link.exe` 14.51.36260. With `RUSTUP_HOME=.toolchains/rustup` and `CARGO_HOME=.toolchains/cargo`, `rustc`/`cargo` are 1.99.1.
- The extension checkout remains `d446234`, version `0.1.0-alpha.15`; the Core Engine direct TLSNotary dependencies are `v0.1.0-alpha.15`, resolved to `47aee45b`. No upstream cache source was edited.
- The first scaffold build attempt failed because `core-engine/src/main.rs` did not yet exist. After implementation, `cargo check --offline --manifest-path core-engine/Cargo.toml` succeeded.
- **Final test command:** `cargo test --locked --offline --manifest-path core-engine/Cargo.toml` — 7 passed, 0 failed. Six unit/error tests plus the separately named genuine cryptographic integration test passed. The integration test generated real TLSNotary proofs from the fixture for HTTP 503, 200, and 404, verified them in a separate CLI process, asserted all four 503 fields, and rejected tampered presentation, tampered attestation, missing attestation/presentation, malformed presentation, invalid input, untrusted TLS, timeout, unavailable fixture, verifier startup failure, and verifier timeout.
- **Retained CLI demo:** `traceseal-core.exe fixture`; then `traceseal-core.exe prove --url https://localhost:4443/trace-seal-503 --disclose status,error,service,message --output phase2-artifacts`; then a separate `traceseal-core.exe verify --attestation ... --presentation ...`. The report returned `VERIFIED`, actual HTTP 503, and the fixture's four selected fields; the verifier process exit code was 0. Package: `phase2-artifacts/1793930213453613000-20468/`. Attestation SHA-256: `1ceb8878590f9404111fea7d2e6310f9d78cf11e33a1e53bc73a5891e1fe1286`; presentation SHA-256: `608fab65a7b4c41790fce705abd137fde47c299f69fa820067ac3422d7e2f9a3`.
- Phase 1 artifact hashes remain unchanged: attestation `2BEC862147BD592E179F48A7BC3DB9B4E25501A2658B2998B9E93EE43BA8D99E`; presentation `FC35585F3B8BEE916B5CFF4B637D2329C95947FF98BE8631F138E6CEA63BF3E8`.
- CLI `--version` and `--help` ran successfully. The fixture/key and attestor are deliberately test-only. The workflow is a controlled local demonstration, not production trust. Hedera Phase 3 remains gated on independent notary governance and key distribution.
