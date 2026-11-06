# Local HTTPS fixture certificates

These files are a test-only development CA and a `localhost` TLS server keypair used by the controlled TRACESEAL fixture. The TLSNotary prover and local test attestor explicitly trust `ca-cert.pem`; normal TLS certificate checks remain enabled. The server key is deliberately public test material and has no production value; it is needed to reproduce fixture integration tests.

The `server-key.pem` key is intentionally public test material and must never be reused for any deployed service. The CA private key was discarded after signing the server certificate. This keypair is not a production trust anchor. The local demo attestor key is supplied at runtime using `TRACESEAL_TEST_ATTESTOR_KEY`; it is never written to artifacts or logs.

The Phase 2 fixture is pinned to TLS 1.2 because the selected `tlsn` v0.1.0-alpha.15 attestation API uses the TLS 1.2 certificate binding. No TLS 1.3 claim is made.
