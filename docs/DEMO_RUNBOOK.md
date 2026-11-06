# TRACESEAL Demo Runbook (Windows / PowerShell)

## Prerequisites

- Windows x64 with Visual Studio Build Tools (MSVC `cl.exe`/`link.exe`).
- Workspace-local Rust toolchain under `.toolchains/`.
- Built binary: `tlsnotary/servers/target/debug/traceseal-core.exe` (built via `cargo build --locked --manifest-path core-engine/Cargo.toml` with `CARGO_TARGET_DIR=tlsnotary/servers/target`).

Set up the environment once per terminal:

```powershell
$env:RUSTUP_HOME = "$PWD\.toolchains\rustup"
$env:CARGO_HOME  = "$PWD\.toolchains\cargo"
$env:PATH        = "$PWD\.toolchains\cargo\bin;$env:PATH"
$env:CARGO_TARGET_DIR = "$PWD\tlsnotary\servers\target"
```

## Terminal 1 — fixture (test HTTPS service)

```powershell
$env:TRACESEAL_TEST_ATTESTOR_KEY = '0101010101010101010101010101010101010101010101010101010101010101'
.\tlsnotary\servers\target\debug\traceseal-core.exe fixture --bind 127.0.0.1:4443
```

The key above is **public test-only material** — never use it outside the demo.

## Terminal 2 — API + frontend

```powershell
.\tlsnotary\servers\target\debug\traceseal-core.exe serve --bind 127.0.0.1:3000 --storage-dir .\demo-store
```

Open `http://127.0.0.1:3000` (or `/app`). Health badge should read `healthy`.

## Generate a genuine proof (Terminal 3)

```powershell
$env:TRACESEAL_TEST_ATTESTOR_KEY = '0101010101010101010101010101010101010101010101010101010101010101'
.\tlsnotary\servers\target\debug\traceseal-core.exe prove `
  --url https://localhost:4443/trace-seal-503 `
  --disclose status,error,service,message `
  --output .\demo-artifacts
```

Note the `Artifacts:` path printed to stderr, e.g. `demo-artifacts\<id>\`.

## Submit via the frontend

In the console, choose the three files from that package folder:

- `attestation` ← `attestation.tlsn`
- `presentation` ← `presentation.tlsn`
- `request_manifest` ← `request.json`

Click **Verify & store evidence**. Expect `stored` + a `ts1_…` ID, then the lookup panel auto-loads.

## Demonstrate tampering

```powershell
$pkg = ".\demo-artifacts\<id>"
$bytes = [System.IO.File]::ReadAllBytes("$pkg\presentation.tlsn")
$bytes[$bytes.Length/2] = $bytes[$bytes.Length/2] -bxor 0x20
[System.IO.File]::WriteAllBytes(".\demo-artifacts\tampered.tlsn", $bytes)
```

Resubmit with `presentation` ← `tampered.tlsn` → UI shows `Submission failed: The TLSNotary verifier rejected the cryptographic proof` (HTTP 422).

## Restart persistence

Stop the `serve` process (Ctrl+C), rerun the same `serve` command with the same `--storage-dir`, look up the evidence ID — metadata, artifacts, and reverification history persist.

## CLI-only verification

```powershell
.\tlsnotary\servers\target\debug\traceseal-core.exe verify `
  --attestation .\demo-artifacts\<id>\attestation.tlsn `
  --presentation .\demo-artifacts\<id>\presentation.tlsn
```

Prints a JSON report; exit code 0 only when `verification_status` is `VERIFIED`.

## Troubleshooting

- **Port 4443/3000 in use:** another `traceseal-core` process is running — `Get-Process traceseal-core | Stop-Process`.
- **`prove` times out:** fixture not running, or `TRACESEAL_TEST_ATTESTOR_KEY` unset in that terminal.
- **TLS preflight failed:** fixture started with `--untrusted-cert`, or wrong port.
- **`serve` storage errors:** delete `demo-store` only if it is disposable demo data.
