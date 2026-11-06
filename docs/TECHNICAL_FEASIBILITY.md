# TLSNotary technical feasibility

Research date: 2026-11-06. Phase 1 proof of concept was completed against the official TLSNotary core pinned by the current `tlsn-extension` verifier.

## Selected implementation

The maintained implementation is the Rust [tlsn protocol repository](https://github.com/tlsnotary/tlsn), with the official [tlsn-extension monorepo](https://github.com/tlsnotary/tlsn-extension) providing an operational browser prover, plugin SDK, and Rust verifier server. The extension consumes `tlsn-wasm`; the mobile client uses a native Rust prover. The older `tlsn-js` repository is not the current integration path, and the original `tlsnotary/tlsnotary` repository is archived.

For a hackathon integration, the extension's plugin API is the clearest documented path for a user-selected HTTPS API request. A backend-only Python HTTP request cannot be retroactively turned into a TLSNotary proof. The browser prover must conduct the original TLS exchange through the verifier's proxy. The documented workspace expects Node.js 18+, Rust for the verifier, and Chrome/Chromium for extension development. The upstream setup is `git clone https://github.com/tlsnotary/tlsn-extension.git`, `npm install`, then `cd servers; cargo run -p tlsn-verifier-server`; extension development uses `npm run dev` and loads `packages/extension/build/` unpacked in Chrome.

## Actual interface and workflow documented upstream

The current verifier exposes `GET /health`, WebSocket `/session`, `/verifier?sessionId=...`, and `/proxy?token=<host>`. The prover connects to `/session`, negotiates transcript limits and session metadata, and uses the verifier/proxy WebSockets to participate in MPC-TLS with the target. The extension's plugin session manager exposes `prove(request, config)`. Its configuration includes `verifierUrl`, `proxyUrl`, transcript limits, and selective-disclosure handlers. Handlers identify sent/received HTTP components and can reveal or commit data. The upstream example demonstrates revealing a response JSON field. The official documentation warns that prover and verifier versions must match.

The extension's current `prove()` response exposes handler results after the live verifier has checked the protocol. The extension/verifier flow does not establish portable proof export. Separately, the pinned TLSN core has an official attestation workflow: the prover sends an attestation request to an attestor, saves a signed `Attestation` and secrets, builds a selectively disclosed `Presentation`, and a separate verifier can validate that self-contained presentation using the attestor's public key. The successful feasibility demonstration below used this official core attestation path. It should not be conflated with proof export from the browser extension's `prove()` API.

## Protocol and compatibility limits

The current official pages inspected do not make a sufficiently specific, authoritative TLS-version compatibility promise for this integration. The README presents arbitrary HTTPS API targets but does not assert TLS 1.2 versus 1.3 support. TRACESEAL will not claim either version until verified from the selected release's source or an actual test. HTTP parsing and response disclosures are performed by the extension's handler/reveal-range implementation; supported HTTP edge cases, body size limits, redirects, compression, and chunked responses must be confirmed against the checked-out revision. The protocol is actively developed and upstream warns of breaking changes; pin matching prover and verifier revisions.

## Feasibility gate and test workflow - completed proof of concept

Required proof-of-concept:

1. Run a controlled HTTPS service with a certificate trusted by the prover and a deterministic HTTP 503 JSON response.
2. Use the actual TLSNotary prover to make the original request through its verifier/proxy, disclosing the relevant status and body fields.
3. Persist the genuine upstream proof artifact/serialized result and disclosed data, if the selected APIs support portable export.
4. Verify it with the independent official verifier path, not a hash comparison alone.
5. Alter a copy's proof/disclosed data and demonstrate cryptographic or transcript verification failure.

The official pinned core attestation example successfully completed this workflow against its local HTTPS test fixture, temporarily extended to return the target 503 JSON. The fixture's test CA was explicitly added to the TLSN prover and verifier trust stores; certificate validation was not disabled. The example performed the request during the original MPC-TLS exchange, and its attestor signed the authenticated transcript commitments. It wrote a serialized attestation and a selectively disclosed presentation. A separate run of the official presentation verifier succeeded and displayed the authenticated `test-server.io` identity, HTTP status line `503 Service Unavailable`, and all four requested JSON fields.

Tamper test: one byte in the serialized `Service Unavailable` disclosure was changed in the presentation. The independent verifier exited 101 with `TranscriptProofError { kind: Hash, source: Some("hash opening does not match any commitment") }`. The original presentation was restored; its SHA-256 remained `FC35585F3B8BEE916B5CFF4B637D2329C95947FF98BE8631F138E6CEA63BF3E8`.

Artifacts retained in `phase1-artifacts/` are `example-json.attestation.tlsn` (3,114 bytes; SHA-256 `2BEC862147BD592E179F48A7BC3DB9B4E25501A2658B2998B9E93EE43BA8D99E`) and `example-json.presentation.tlsn` (5,897 bytes; SHA-256 above). The intermediate `example-json.secrets.tlsn` file was removed after presentation generation because it is unnecessary for independent verification and contains prover-side secret material.

This was a test-only local attestor using the upstream example's deterministic signing key and test CA. Verification proves consistency with that key; a production verifier must obtain and trust an independently governed attestor key. This demonstration does not make a TLS 1.3 support claim and does not establish that the browser extension API exports this portable artifact.

## Build environment and local feasibility attempts

The official `tlsn-extension` repository is checked out at commit `d446234`, package version `0.1.0-alpha.15`. Its `node_modules` and `servers/Cargo.lock` are already present. The verifier pins `tlsn` to tag `v0.1.0-alpha.15`. Rust/Cargo `1.99.1` are installed workspace-locally under `.toolchains/`. On resume, `cargo run --offline` showed that the pinned TLSNotary Git dependency was not yet cached. An online Cargo retry fetched that dependency once, then the existing verifier build failed with:

> linker `link.exe` not found - MSVC targets require Visual Studio or Build Tools with the Visual C++ option.

At the start of the resumed session the default PowerShell PATH did not expose `cl.exe` or `link.exe`. `vswhere` then found Visual Studio 18 Build Tools at `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools`. Calling its `Common7\Tools\VsDevCmd.bat -arch=x64 -host_arch=x64` made both x64 tools resolvable; `cl.exe /Bv` reported compiler 19.51.36260 and linker 14.51.36260. Rust/Cargo 1.99.1 were confirmed active.

The first plain-environment compile correctly failed with `linker 'link.exe' not found`. Retrying with the Visual Studio developer environment succeeded: `cargo run --locked -p tlsn-verifier-server` finished in 4m30s and started on `0.0.0.0:7047`. `curl.exe http://localhost:7047/health` returned HTTP 200 `ok`. The extension checkout remains at commit `d446234`, package version `0.1.0-alpha.15`; the verifier's TLSN dependency remains pinned to `v0.1.0-alpha.15` (commit `47aee45b`).

For the attestation demonstration, the pinned core's documented `tlsn-server-fixture` and `attestation_prove`, `attestation_present`, and `attestation_verify` examples were used. Temporary modifications were limited to the Cargo-cached example fixture and example selection/reveal fields; the response was HTTP 503 JSON, and those source files were restored byte-for-byte after testing. The test fixture and local attestor were stopped after completion. The separate extension verifier had already been built, health-checked, and stopped. The Docker daemon remains unavailable but was not needed for the successful native proof-of-concept.

Phase 1 feasibility is demonstrated. Product integration still needs a deliberate choice between the portable core attestation/presentation workflow and the browser extension's in-session verifier result, plus an independently governed production attestor key. No application or Hedera integration was started in this phase.

## Phase 2 Core Engine

The TRACESEAL-owned Rust package is under `core-engine/`. It pins `tlsn` and `tlsn-formats` to `v0.1.0-alpha.15` / commit `47aee45b`. The CLI has `fixture`, `prove`, `verify`, and `inspect` commands. The Core Engine uses the pinned TLSNotary attestation, transcript commitment, selective presentation, and `Presentation::verify` APIs; it adds no proof cryptography.

`prove` accepts a fixed HTTPS localhost fixture URL, checks TLS trust in a preliminary handshake, then performs the original GET through TLSNotary MPC-TLS. A local test notary in the same CLI process signs the committed transcript using a runtime-only known test key. The CLI keeps prover `Secrets` in memory and never writes them. It reveals request metadata, response header names without values, and explicit complete top-level JSON key/value transcript spans. It writes bincode-serialized TLSNotary attestation and presentation, request manifest JSON, and verification report JSON to a unique staging directory. It publishes the package by same-volume rename only after the separate verifier process returns.

`verify` runs as that separate process and calls the official pinned TLSNotary `Presentation::verify` API, validates the attestation signature against the locally pinned demo public key, validates the localhost identity against the test CA, checks the proved GET/request target and actual HTTP status line, and extracts JSON values from the authenticated partial transcript. The report includes `VERIFIED`, `REJECTED`, or `ERROR`, actual revealed fields, optional HTTP status, SHA-256 artifact identifiers, Core Engine and TLSNotary versions, the child verifier exit code when available, UTC timestamp, and error messages. Verification is never inferred from file presence.

### Actual Phase 2 validation

- The project-owned fixture supports deterministic HTTPS 503, 200, 404, and delayed responses. The valid local certificate chains to the included test CA; the optional untrusted-certificate mode is used to test TLS rejection. The fixture negotiates TLS 1.2 only.
- `cargo check --offline --manifest-path core-engine/Cargo.toml` completed successfully using the existing Cargo cache and shared target. `cargo test --locked --offline --manifest-path core-engine/Cargo.toml` passed **7 tests, 0 failed**. The unit/error tests cover request/disclosure validation, report serialization, invalid output paths, missing/malformed artifacts, verifier startup failure, and verifier timeout. The separately named genuine cryptographic integration test generated actual local TLSNotary proofs and separate-process verification for HTTP 503, 200, and 404; it rejected modified presentation/attestation, missing and malformed artifacts, untrusted TLS, delayed response, and unavailable fixture.
- A retained manual CLI run generated `phase2-artifacts/1793930213453613000-20468/`. The separate verifier reported `VERIFIED`, HTTP 503, all four selected JSON fields, verifier exit code 0. The retained attestation SHA-256 is `1ceb8878590f9404111fea7d2e6310f9d78cf11e33a1e53bc73a5891e1fe1286`; the presentation SHA-256 is `608fab65a7b4c41790fce705abd137fde47c299f69fa820067ac3422d7e2f9a3`.
- The original Phase 1 artifact files remain unchanged: attestation SHA-256 `2BEC862147BD592E179F48A7BC3DB9B4E25501A2658B2998B9E93EE43BA8D99E`; presentation SHA-256 `FC35585F3B8BEE916B5CFF4B637D2329C95947FF98BE8631F138E6CEA63BF3E8`.

### Trust and supported inputs

The key used by this local demonstration is deliberately public, test-only material, supplied by `TRACESEAL_TEST_ATTESTOR_KEY`; the matching public key is fixed in the demo verifier. This verifies consistency with the known local test notary, not a production attestor trust model. Prover and notary are in the same process; only presentation verification is a separate process. An independently governed production attestor and key distribution remain necessary before production or Hedera use.

Only HTTPS GET to the four fixed `localhost:4443` paths and four allowlisted top-level JSON keys are supported. Disclosures are transcript ranges (complete key/value pairs), not arbitrary nested JSON pointers. TLS 1.3, arbitrary public hosts, redirects, compression, chunked responses, auth headers, other methods, and production trust guarantees are not claimed. The preflight TLS handshake is a certificate/connectivity check; only the subsequent TLSNotary exchange is the attested request.

Phase 2 reaches a controlled local end-to-end demonstration. Phase 3 Steps C-E now provide canonical evidence identity, trusted-verifier integration, and local persistent storage. These additions do not replace the demo trust profile: the public demo attestor key and same-process prover/notary still prevent production claims. No HTTP API, authentication/ownership system, frontend, or Hedera integration has been implemented.

## Phase 3 Steps C-E: evidence identity and local storage

Step C defines the versioned Evidence Schema 1.0 payload, exact-byte SHA-256 artifact hashes, RFC 8785 canonicalization, and the domain-separated commitment/evidence ID. Step D invokes the existing TLSNotary verifier as the sole cryptographic verification path and constructs a trusted internal result only after successful process exit, explicit `VERIFIED` output, active demo trust-policy checks, and manifest/transcript consistency checks.

Step E adds a Rust storage module that accepts only that non-publicly-constructible trusted result. SQLite `user_version=1` stores evidence metadata and artifact references; original attestation, presentation, and manifest bytes are stored separately under application-generated paths. The original verifier report is immutable and separate from append-only `REVERIFICATION` reports created from later successful verifier runs. Ingestion uses exact bytes, staged writes, a SQLite `BEGIN IMMEDIATE` transaction, and a `READY` record committed only after filesystem publication. The write lock is acquired before staging and held through publication; recovery uses the same lock before cleanup, so recovery on another store instance waits for an active write and then observes either a committed record or an orphan publication. Duplicate identical evidence is idempotent, conflicting IDs are rejected, and retrieval rechecks metadata, artifact sizes, exact-byte hashes, and the canonical evidence identity.

Schema 1.0 intentionally includes `verification.verifier_version` and `trust_policy_id` in the canonical evidence payload. Both therefore contribute to the commitment and evidence ID. `record_reverification` requires full `EvidenceRecord` equality, including those identity fields and the proof artifact hashes. This is correct for the current identity definition, not an accidental comparison bug. Step D only supports one verifier profile and `demo-local-v1`; a later successful result under a different verifier or policy cannot be attached to the original ID. To support rotations without changing proof identity, a future schema must separate a stable proof/artifact commitment from versioned verification assessments, rather than weakening the current check.

The storage implementation has no HTTP API, ownership enforcement, or authorization. Unix file modes are restricted; on Windows, storage inherits the parent directory ACL, which this code does not configure or audit. Symlink and canonical-path checks precede ordinary path-based filesystem operations, leaving a TOCTOU race if an attacker can mutate the storage tree concurrently; this implementation is not race-proof. The database and artifact tree are not cryptographically authenticated against an attacker able to rewrite both. The current local demo trust model remains insecure and does not provide independent attestation. HTTP API, ownership/authentication, production storage and trust configuration, Hedera anchoring, and release validation remain future work.

## Hedera integration approach

After genuine proof verification, the application can anchor a compact JSON commitment with the official Hedera SDK: evidence ID, package SHA-256, schema/proof-format identifiers, and minimal non-sensitive metadata. A backend-controlled testnet account/topic holds signing authority. The transaction result/receipt supplies real network identifiers; the Hedera Mirror Node is then queried to confirm the exact message. Account/key/topic configuration and the correct current SDK operations still need to be verified against Hedera's official SDK documentation before implementation. No Hedera credentials are present in this workspace.

## Risks and workarounds

- **Browser-mediated proving:** A browser extension is needed for the documented current user-facing prover path. A Python server cannot silently replace it. The likely architecture is a web frontend that communicates with a browser extension/plugin and a separately version-matched verifier service.
- **Verifier participation:** The TLSNotary verifier is a protocol participant, so independent verification must rely on the cryptographic proof/result and explicit binding to disclosed data, not a trusted backend status flag.
- **Portable proofs:** Current extension docs describe proof generation and verifier handling, but do not establish a stable portable artifact export API. Confirm in source/runtime before designing evidence storage.
- **TLS/HTTP claims:** Do not claim version or feature support absent source validation and a live demonstration.
- **Controlled certificates:** A locally trusted CA or publicly trusted test hostname is needed; disabling certificate validation is not acceptable.
- **Hedera configuration:** Real anchoring requires testnet operator account/key and topic. Missing credentials mean anchoring must report unconfigured rather than simulate success.
- **Privacy and SSRF:** User-selected endpoints and headers require strict allowlisting, destination revalidation, size/time limits, and separation of private disclosures from public HCS data.

## Sources

- [Official TLSNotary quick start](https://tlsnotary.org/docs/quick_start/)
- [Official TLSNotary Rust implementation](https://github.com/tlsnotary/tlsn)
- [Official TLSNotary clients and plugin monorepo](https://github.com/tlsnotary/tlsn-extension)
- [Official verifier protocol and endpoints](https://github.com/tlsnotary/tlsn-extension/blob/main/VERIFIER.md)
- [Archived original implementation](https://github.com/tlsnotary/tlsnotary)
- [TLSNotary release notes](https://github.com/tlsnotary/tlsn/releases)
- [Hedera Consensus Service documentation](https://docs.hedera.com/hedera/sdks-and-apis/consensus-service)

## Commands and outcomes

- Official documentation and GitHub sources were consulted on 2026-11-06, including the [official Rust quick start](https://tlsnotary.org/docs/quick_start/rust/) and its attestation example.
- The extension verifier built and ran; `/health` returned HTTP 200 `ok`.
- The pinned core's HTTPS 503 attestation, portable presentation, independent verification, and tamper-rejection workflow passed as recorded above.
- The initial linker failure was resolved by invoking the installed Visual Studio 18 x64 developer environment; dependency versions were not changed. Some previously uncached example-only Rust crates were downloaded when compiling the official attestation examples. Existing npm dependencies were not reinstalled.
- `cargo test --locked --offline --manifest-path core-engine/Cargo.toml` passed: 31 unit tests, 7 integration tests, and 0 failures. The integration suite includes a genuine local TLSNotary proof persisted and retrieved through Step E.
- `cargo fmt --manifest-path core-engine/Cargo.toml -- --check` and `git diff --check` passed.
- No HTTP API, frontend, or Hedera transaction was implemented or tested; these remain future work.
