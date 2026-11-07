//! Hedera anchoring integration tests.
//!
//! These tests run WITHOUT Hedera credentials: they verify that the
//! outbox/idempotency layer works, that anchoring degrades gracefully when
//! unconfigured, and that the API surfaces real local records. Real testnet
//! transactions are covered separately (see hedera/README.md).

use std::io::Read;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::tempdir;
use tower::ServiceExt;
use traceseal_core::api::{create_router, AppState};
use traceseal_core::storage::EvidenceStore;

fn attestor_key() -> String {
    "01".repeat(32)
}

struct FixtureGuard(std::process::Child);
impl Drop for FixtureGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
    }
}

async fn start_fixture(exe: &str) -> FixtureGuard {
    let mut cmd = Command::new(exe);
    cmd.args(["fixture", "--bind", "127.0.0.1:4443"]);
    let mut child = FixtureGuard(
        cmd.stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn fixture"),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut error = String::new();
            if let Some(mut pipe) = child.0.stderr.take() {
                let _ = pipe.read_to_string(&mut error);
            }
            panic!("fixture exited before listening ({status}): {error}");
        }
        if tokio::time::timeout(Duration::from_millis(100), async {
            tokio::net::TcpStream::connect("127.0.0.1:4443").await
        })
        .await
        .is_ok()
        {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "fixture did not listen");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    child
}

fn run_prove(exe: &str, url: &str, fields: &str, output: &Path, timeout: u64) -> Output {
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
        .env("TRACESEAL_TEST_ATTESTOR_KEY", attestor_key())
        .output()
        .expect("run prove")
}

fn package_path(result: &Output) -> std::path::PathBuf {
    std::path::PathBuf::from(
        String::from_utf8_lossy(&result.stderr)
            .lines()
            .find(|l| l.starts_with("Artifacts: "))
            .expect("package path in stderr")
            .trim_start_matches("Artifacts: "),
    )
}

fn create_multipart_body(boundary: &str, parts: &[(&str, &str, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, filename, data) in parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

async fn submit(app: &axum::Router, body: Vec<u8>, boundary: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/evidence")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn get_json(app: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn post_json(app: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

/// Poll the blockchain endpoint until at least `n` audit events appear.
async fn wait_for_events(app: &axum::Router, id: &str, n: usize) -> Value {
    for _ in 0..50 {
        let (_, json) = get_json(app, &format!("/api/v1/evidence/{id}/blockchain")).await;
        let count = json["audit_events"].as_array().map(|a| a.len()).unwrap_or(0);
        if count >= n {
            return json;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("timed out waiting for {n} hedera events");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hedera_outbox_lifecycle_without_credentials() {
    let exe = env!("CARGO_BIN_EXE_traceseal-core");
    let _fixture = start_fixture(exe).await;
    let temp = tempdir().unwrap();

    // Generate a genuine proof package.
    let prove_dir = temp.path().join("prove");
    let prove = run_prove(
        exe,
        "https://localhost:4443/trace-seal-503",
        "status,error,service,message",
        &prove_dir,
        30,
    );
    assert!(prove.status.success(), "prove failed: {:?}", prove);
    let pkg = package_path(&prove);
    let att = std::fs::read(pkg.join("attestation.tlsn")).unwrap();
    let pres = std::fs::read(pkg.join("presentation.tlsn")).unwrap();
    let man = std::fs::read(pkg.join("request.json")).unwrap();

    let store = EvidenceStore::open(temp.path().join("store")).unwrap();
    let state = Arc::new(AppState::with_options(store, 2, Duration::from_secs(60)));
    let app = create_router(state);

    // 1. Submit evidence — Hedera events should be enqueued asynchronously.
    let boundary = "----tsboundary";
    let body = create_multipart_body(
        boundary,
        &[
            ("attestation", "attestation.tlsn", &att),
            ("presentation", "presentation.tlsn", &pres),
            ("request_manifest", "request.json", &man),
        ],
    );
    let (status, receipt) = submit(&app, body, boundary).await;
    assert_eq!(status, StatusCode::CREATED, "submit failed: {receipt}");
    let evidence_id = receipt["evidence_id"].as_str().unwrap().to_string();
    assert!(evidence_id.starts_with("ts1_"));

    // 2. Wait for the async anchor task to enqueue EVIDENCE_VERIFIED.
    let bc = wait_for_events(&app, &evidence_id, 1).await;
    let events = bc["audit_events"].as_array().unwrap();
    assert_eq!(events[0]["event_type"], "EVIDENCE_VERIFIED");
    // Unconfigured: stays PENDING, never falsely CONFIRMED.
    assert_eq!(events[0]["status"], "PENDING");

    // 3. NFT receipt is only reserved when HEDERA_NFT_TOKEN_ID is configured.
    // Without credentials the receipt stays absent — never falsely minted.
    let receipt_row = &bc["nft_receipt"];
    assert!(receipt_row.is_null(), "unexpected nft_receipt: {receipt_row}");

    // 4. Duplicate submission → already_present, no duplicate events.
    let body2 = create_multipart_body(
        boundary,
        &[
            ("attestation", "attestation.tlsn", &att),
            ("presentation", "presentation.tlsn", &pres),
            ("request_manifest", "request.json", &man),
        ],
    );
    let (status2, receipt2) = submit(&app, body2, boundary).await;
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(receipt2["disposition"], "already_present");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let bc2 = get_json(&app, &format!("/api/v1/evidence/{evidence_id}/blockchain")).await.1;
    let verified_count = bc2["audit_events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["event_type"] == "EVIDENCE_VERIFIED")
        .count();
    assert_eq!(verified_count, 1, "duplicate EVIDENCE_VERIFIED events");

    // 5. Manual anchor is idempotent and reports unconfigured skip.
    let (anchor_status, anchor) =
        post_json(&app, &format!("/api/v1/evidence/{evidence_id}/anchor")).await;
    assert_eq!(anchor_status, StatusCode::OK, "anchor failed: {anchor}");
    assert_eq!(anchor["skipped_unconfigured"], true);

    // 6. Re-verification enqueues EVIDENCE_REVERIFIED.
    let (rv_status, rv) = post_json(
        &app,
        &format!("/api/v1/evidence/{evidence_id}/reverify"),
    )
    .await;
    assert_eq!(rv_status, StatusCode::OK, "reverify failed: {rv}");
    let bc3 = wait_for_events(&app, &evidence_id, 2).await;
    let types: Vec<&str> = bc3["audit_events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event_type"].as_str().unwrap())
        .collect();
    assert!(types.contains(&"EVIDENCE_REVERIFIED"), "events: {types:?}");

    // 7. Invalid evidence ID rejected.
    let (bad_status, _) = get_json(&app, "/api/v1/evidence/not-an-id/blockchain").await;
    assert_eq!(bad_status, StatusCode::BAD_REQUEST);

    // 8. Hedera status endpoint reports unconfigured state honestly.
    let (hs_status, hs) = get_json(&app, "/api/v1/hedera/status").await;
    assert_eq!(hs_status, StatusCode::OK);
    assert_eq!(hs["configured"], false);
    assert_eq!(hs["network"], "testnet");
    assert!(hs["missing"].as_array().unwrap().len() >= 4);
}
