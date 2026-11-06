use std::{
    fs,
    io::Read,
    process::{Command, Output, Stdio},
    time::Duration,
};

use tempfile::tempdir;
use traceseal_core::{
    prove, run_process_with_timeout, run_verifier, validate_endpoint, verify_files, EvidenceReport,
};

const KEY: &str = "0101010101010101010101010101010101010101010101010101010101010101";

struct FixtureGuard(std::process::Child);
impl Drop for FixtureGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

async fn start_fixture(exe: &str, untrusted: bool) -> FixtureGuard {
    let mut cmd = Command::new(exe);
    cmd.args(["fixture", "--bind", "127.0.0.1:4443"]);
    if untrusted {
        cmd.arg("--untrusted-cert");
    }
    let mut child = FixtureGuard(
        cmd.stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    for _ in 0..80 {
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut error = String::new();
            if let Some(mut pipe) = child.0.stderr.take() {
                let _ = pipe.read_to_string(&mut error);
            }
            panic!("fixture exited before listening ({status}): {error}");
        }
        if tokio::time::timeout(
            Duration::from_millis(100),
            tokio::net::TcpStream::connect("127.0.0.1:4443"),
        )
        .await
        .is_ok_and(|r| r.is_ok())
        {
            return child;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("fixture did not listen within 8 seconds");
}

fn run_prove(exe: &str, url: &str, fields: &str, output: &std::path::Path, timeout: u64) -> Output {
    Command::new(exe)
        .args([
            "prove",
            "--url",
            url,
            "--disclose",
            fields,
            "--output",
            output.to_str().unwrap(),
            "--request-timeout-seconds",
            &timeout.to_string(),
        ])
        .env("TRACESEAL_TEST_ATTESTOR_KEY", KEY)
        .output()
        .unwrap()
}

fn package_path(result: &Output) -> std::path::PathBuf {
    std::path::PathBuf::from(
        String::from_utf8_lossy(&result.stderr)
            .lines()
            .find_map(|line| line.strip_prefix("Artifacts: "))
            .expect("artifact path in stderr"),
    )
}

#[test]
fn request_and_disclosure_validation() {
    let fields = vec!["status".to_owned(), "message".to_owned()];
    assert!(validate_endpoint("https://localhost:4443/trace-seal-503", &fields).is_ok());
    assert!(validate_endpoint("http://localhost:4443/trace-seal-503", &fields).is_err());
    assert!(validate_endpoint("https://127.0.0.1:4443/trace-seal-503", &fields).is_err());
    assert!(validate_endpoint("https://localhost:4443/trace-seal-503?x=1", &fields).is_err());
    assert!(validate_endpoint("https://localhost:4443/trace-seal-503", &[]).is_err());
    assert!(validate_endpoint(
        "https://localhost:4443/trace-seal-503",
        &["authorization".into()]
    )
    .is_err());
    assert!(validate_endpoint("https://localhost:4443/other", &fields).is_err());
}

#[test]
fn report_round_trips_as_json() {
    let report = EvidenceReport {
        schema_version: "1.0".into(),
        verification_status: "REJECTED".into(),
        http_status: None,
        disclosed_evidence: Default::default(),
        attestation: serde_json::from_value(serde_json::json!({"identifier":null,"sha256":null}))
            .unwrap(),
        presentation: serde_json::from_value(serde_json::json!({"identifier":null,"sha256":null}))
            .unwrap(),
        verifier: serde_json::from_value(serde_json::json!({"version":"0.1.0","exit_code":1}))
            .unwrap(),
        verified_at: "2026-01-01T00:00:00Z".into(),
        errors: vec!["invalid input".into()],
    };
    let encoded = serde_json::to_vec(&report).unwrap();
    let decoded: EvidenceReport = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded.verification_status, "REJECTED");
    assert_eq!(decoded.verifier.exit_code, Some(1));
}

#[test]
fn missing_and_malformed_artifacts_fail_closed() {
    let temp = tempdir().unwrap();
    let missing = verify_files(
        &temp.path().join("missing.attestation"),
        &temp.path().join("missing.presentation"),
    );
    assert_eq!(missing.verification_status, "ERROR");
    assert!(missing.attestation.sha256.is_none());
    let att = temp.path().join("attestation.tlsn");
    let pres = temp.path().join("presentation.tlsn");
    fs::write(&att, b"not a TLSN attestation").unwrap();
    fs::write(&pres, b"not a TLSN presentation").unwrap();
    let bad = verify_files(&att, &pres);
    assert_eq!(bad.verification_status, "REJECTED");
    assert!(!bad.errors.is_empty());
}

#[tokio::test]
async fn verifier_process_start_failure_is_reported() {
    let temp = tempdir().unwrap();
    let result = run_verifier(
        &temp.path().join("missing-verifier.exe"),
        &temp.path().join("attestation"),
        &temp.path().join("presentation"),
        Duration::from_secs(1),
    )
    .await;
    assert!(result
        .unwrap_err()
        .contains("verifier process failed to start"));
}

#[tokio::test]
async fn verifier_process_timeout_is_reported_and_killed() {
    let mut command = tokio::process::Command::new("powershell.exe");
    command.args(["-NoProfile", "-Command", "Start-Sleep -Seconds 5"]);
    let result = run_process_with_timeout(&mut command, Duration::from_millis(100)).await;
    assert!(result.unwrap_err().contains("timed out"));
}

#[tokio::test]
async fn output_path_must_be_a_directory() {
    let temp = tempdir().unwrap();
    let file = temp.path().join("output");
    fs::write(&file, b"preserve").unwrap();
    let result = prove(
        "https://localhost:4443/trace-seal-503",
        &["status".into()],
        &file,
        Duration::from_secs(1),
    )
    .await;
    assert!(result
        .unwrap_err()
        .contains("cannot create output directory"));
    assert_eq!(fs::read(file).unwrap(), b"preserve");
}

// Genuine cryptographic integration: starts the local TLS 1.2 fixture, runs the actual TLSNotary
// MPC prover and local test attestor, then launches a separate verifier CLI process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn genuine_503_proof_verifies_and_tampering_is_rejected() {
    let exe = env!("CARGO_BIN_EXE_traceseal-core");
    let mut fixture = start_fixture(exe, false).await;
    let temp = tempdir().unwrap();
    let result = run_prove(
        exe,
        "https://localhost:4443/trace-seal-503",
        "status,error,service,message",
        temp.path(),
        60,
    );
    if !result.status.success() {
        panic!(
            "genuine prove command failed: {}\n{}",
            String::from_utf8_lossy(&result.stderr),
            String::from_utf8_lossy(&result.stdout)
        );
    }
    let report: EvidenceReport = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report.verification_status, "VERIFIED");
    assert_eq!(report.http_status, Some(503));
    let package = package_path(&result);
    assert_eq!(
        report.disclosed_evidence.get("status").unwrap(),
        &serde_json::json!(503)
    );
    assert_eq!(
        report.disclosed_evidence.get("error").unwrap(),
        &serde_json::json!("Service Unavailable")
    );
    assert_eq!(
        report.disclosed_evidence.get("service").unwrap(),
        &serde_json::json!("TRACESEAL Demo API")
    );
    assert_eq!(
        report.disclosed_evidence.get("message").unwrap(),
        &serde_json::json!("The service is temporarily unavailable.")
    );
    assert_eq!(report.verifier.exit_code, Some(0));
    assert!(package.join("request.json").exists());
    assert!(package.join("verification-report.json").exists());

    let valid_att = package.join("attestation.tlsn");
    let valid_pres = package.join("presentation.tlsn");
    let verify = |att: &std::path::Path, pres: &std::path::Path| {
        Command::new(exe)
            .args([
                "verify",
                "--attestation",
                att.to_str().unwrap(),
                "--presentation",
                pres.to_str().unwrap(),
            ])
            .output()
            .unwrap()
    };
    let original = fs::read(&valid_pres).unwrap();
    let mut changed = original.clone();
    let changed_at = changed.len() / 2;
    changed[changed_at] ^= 0x20;
    let tampered = temp.path().join("tampered.presentation.tlsn");
    fs::write(&tampered, changed).unwrap();
    let rejected = verify(&valid_att, &tampered);
    assert!(!rejected.status.success());
    let rejection: EvidenceReport = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(rejection.verification_status, "REJECTED");

    let mut invalid_att = fs::read(&valid_att).unwrap();
    let invalid_at = invalid_att.len() / 2;
    invalid_att[invalid_at] ^= 0x40;
    let invalid_att_path = temp.path().join("invalid.attestation.tlsn");
    fs::write(&invalid_att_path, invalid_att).unwrap();
    let rejected = verify(&invalid_att_path, &valid_pres);
    assert!(!rejected.status.success());
    assert_eq!(
        serde_json::from_slice::<EvidenceReport>(&rejected.stdout)
            .unwrap()
            .verification_status,
        "REJECTED"
    );

    let missing = verify(&package.join("missing.tlsn"), &valid_pres);
    assert!(!missing.status.success());
    assert_eq!(
        serde_json::from_slice::<EvidenceReport>(&missing.stdout)
            .unwrap()
            .verification_status,
        "ERROR"
    );
    let missing = verify(&valid_att, &package.join("missing-presentation.tlsn"));
    assert!(!missing.status.success());
    assert_eq!(
        serde_json::from_slice::<EvidenceReport>(&missing.stdout)
            .unwrap()
            .verification_status,
        "ERROR"
    );

    let malformed = temp.path().join("malformed.presentation.tlsn");
    fs::write(&malformed, b"bad presentation bytes").unwrap();
    let malformed = verify(&valid_att, &malformed);
    assert!(!malformed.status.success());
    assert_eq!(
        serde_json::from_slice::<EvidenceReport>(&malformed.stdout)
            .unwrap()
            .verification_status,
        "REJECTED"
    );

    let result_200 = run_prove(
        exe,
        "https://localhost:4443/trace-seal-200",
        "status,service",
        temp.path(),
        60,
    );
    assert!(
        result_200.status.success(),
        "{}",
        String::from_utf8_lossy(&result_200.stderr)
    );
    let report_200: EvidenceReport = serde_json::from_slice(&result_200.stdout).unwrap();
    assert_eq!(report_200.verification_status, "VERIFIED");
    assert_eq!(report_200.http_status, Some(200));
    assert_eq!(
        report_200.disclosed_evidence.get("status"),
        Some(&serde_json::json!(200))
    );

    let result_404 = run_prove(
        exe,
        "https://localhost:4443/trace-seal-404",
        "error,service",
        temp.path(),
        60,
    );
    assert!(
        result_404.status.success(),
        "{}",
        String::from_utf8_lossy(&result_404.stderr)
    );
    let report_404: EvidenceReport = serde_json::from_slice(&result_404.stdout).unwrap();
    assert_eq!(report_404.verification_status, "VERIFIED");
    assert_eq!(report_404.http_status, Some(404));
    fixture.0.kill().ok();
    fixture.0.wait().ok();

    let delayed = run_prove(
        exe,
        "https://localhost:4443/trace-seal-delay",
        "status,message",
        temp.path(),
        1,
    );
    assert!(!delayed.status.success());
    assert!(String::from_utf8_lossy(&delayed.stderr).contains("timed out"));

    fixture = start_fixture(exe, true).await;
    let tls_failure = run_prove(
        exe,
        "https://localhost:4443/trace-seal-503",
        "status",
        temp.path(),
        8,
    );
    assert!(!tls_failure.status.success());
    assert!(
        String::from_utf8_lossy(&tls_failure.stderr).contains("TLS preflight failed"),
        "{}",
        String::from_utf8_lossy(&tls_failure.stderr)
    );
    fixture.0.kill().ok();
    fixture.0.wait().ok();

    let unavailable = run_prove(
        exe,
        "https://localhost:4443/trace-seal-503",
        "status",
        temp.path(),
        2,
    );
    assert!(!unavailable.status.success());
    assert!(
        String::from_utf8_lossy(&unavailable.stderr).contains("connection"),
        "{}",
        String::from_utf8_lossy(&unavailable.stderr)
    );
}
