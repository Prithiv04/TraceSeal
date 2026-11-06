# TRACESEAL

TRACESEAL Phase 1 established TLSNotary feasibility. Phase 2 adds a local Rust Core Engine around the pinned TLSNotary attestation and presentation APIs. It is a controlled demonstration, not a production trust service.

## Current scope

- TLSNotary Rust crates are pinned to `v0.1.0-alpha.15` (Git revision `47aee45b`). The separate `tlsnotary/` checkout remains at `d446234`, package version `0.1.0-alpha.15`.
- The CLI supports only `GET https://localhost:4443/trace-seal-{503,200,404,delay}` and only a finite set of explicit top-level response fields (`status`, `error`, `service`, `message`). It does not claim arbitrary public-site compatibility.
- The fixture serves deterministic TLS 1.2 responses. TLS 1.3 compatibility has not been tested or claimed.
- No frontend, application backend, or Hedera integration is implemented.

## Build and test

Use the existing Rust/Cargo toolchain and an x64 Visual Studio developer environment so `cl.exe` and `link.exe` are on PATH. From the repository root:

```powershell
$env:RUSTUP_HOME = "$PWD\.toolchains\rustup"
$env:CARGO_HOME = "$PWD\.toolchains\cargo"
$env:CARGO_TARGET_DIR = "$PWD\tlsnotary\servers\target"
cargo build --locked --manifest-path core-engine/Cargo.toml
cargo test --locked --manifest-path core-engine/Cargo.toml
```

The integration test starts the controlled HTTPS fixture, conducts actual TLSNotary MPC-TLS proving, serializes an attestation and presentation, and starts a separate CLI verifier process. It also exercises HTTP 503/200/404, selected field disclosure, tampering, invalid/missing/malformed files, process startup failure/timeout, untrusted TLS, and unavailable fixture behavior.

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
