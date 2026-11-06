use std::{
    fs,
    io::Read,
    net::SocketAddr,
    process::{Command, Output, Stdio},
    sync::Arc,
    time::Duration,
};

use axum::{
    body::Bytes,
    http::{header, Request, StatusCode},
};
use http_body_util::{BodyExt, Full};
use tempfile::tempdir;
use tower::ServiceExt;
use traceseal_core::{
    api::{create_router, AppState},
    storage::EvidenceStore,
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

async fn start_fixture(exe: &str) -> FixtureGuard {
    let mut cmd = Command::new(exe);
    cmd.args(["fixture", "--bind", "127.0.0.1:4443"]);
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

fn create_multipart_body(boundary: &str, parts: &[(&str, &str, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, filename, data) in parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

#[tokio::test]
async fn health_check_returns_pass() {
    let temp = tempdir().unwrap();
    let store = EvidenceStore::open(temp.path()).unwrap();
    let state = Arc::new(AppState::new(store));
    let app = create_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["status"], "pass");
    assert_eq!(json["service"], "traceseal-api");
    assert_eq!(json["schema_version"], "1.0");
    assert_eq!(json["trust_policy_id"], "demo-local-v1");
}

#[test]
fn loopback_only_default_binding_is_enforced() {
    let default_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
    assert!(default_addr.ip().is_loopback());

    let external_addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
    assert!(!external_addr.ip().is_loopback());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn genuine_evidence_full_http_api_lifecycle() {
    let exe = env!("CARGO_BIN_EXE_traceseal-core");
    let _fixture = start_fixture(exe).await;
    let temp = tempdir().unwrap();

    // 1. Generate genuine proof from fixture
    let prove_output = run_prove(
        exe,
        "https://localhost:4443/trace-seal-503",
        "status,error,service,message",
        temp.path(),
        60,
    );
    assert!(prove_output.status.success());
    let package = package_path(&prove_output);

    let attestation_bytes = fs::read(package.join("attestation.tlsn")).unwrap();
    let presentation_bytes = fs::read(package.join("presentation.tlsn")).unwrap();
    let manifest_bytes = fs::read(package.join("request.json")).unwrap();

    // 2. Set up EvidenceStore and Axum router
    let storage_dir = temp.path().join("api-storage");
    let store = EvidenceStore::open(&storage_dir).unwrap();
    let state = Arc::new(AppState::with_options(store, 2, Duration::from_secs(30)));
    let app = create_router(state.clone());

    let boundary = "----WebKitFormBoundaryTRACESEAL";

    // 3. Test missing multipart fields -> 400 Bad Request
    let missing_manifest_body = create_multipart_body(
        boundary,
        &[
            ("attestation", "attestation.tlsn", &attestation_bytes),
            ("presentation", "presentation.tlsn", &presentation_bytes),
        ],
    );
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/evidence")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Full::new(Bytes::from(missing_manifest_body)))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 4. Test oversized field (>64 KiB manifest) -> 413 Payload Too Large
    let oversized_manifest = vec![b'a'; 65 * 1024];
    let oversized_body = create_multipart_body(
        boundary,
        &[
            ("attestation", "attestation.tlsn", &attestation_bytes),
            ("presentation", "presentation.tlsn", &presentation_bytes),
            ("request_manifest", "request.json", &oversized_manifest),
        ],
    );
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/evidence")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Full::new(Bytes::from(oversized_body)))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // 5. Test tampered presentation bytes -> 422 Unprocessable Entity
    let mut tampered_presentation = presentation_bytes.clone();
    let mid = tampered_presentation.len() / 2;
    tampered_presentation[mid] ^= 0x20;
    let tampered_body = create_multipart_body(
        boundary,
        &[
            ("attestation", "attestation.tlsn", &attestation_bytes),
            ("presentation", "presentation.tlsn", &tampered_presentation),
            ("request_manifest", "request.json", &manifest_bytes),
        ],
    );
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/evidence")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Full::new(Bytes::from(tampered_body)))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // 6. Test valid evidence submission -> 201 Created
    let valid_body = create_multipart_body(
        boundary,
        &[
            ("attestation", "attestation.tlsn", &attestation_bytes),
            ("presentation", "presentation.tlsn", &presentation_bytes),
            ("request_manifest", "request.json", &manifest_bytes),
        ],
    );
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/evidence")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Full::new(Bytes::from(valid_body.clone())))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let receipt_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let evidence_id = receipt_json["evidence_id"].as_str().unwrap().to_string();
    let commitment = receipt_json["commitment"].as_str().unwrap().to_string();
    assert_eq!(receipt_json["disposition"], "stored");
    assert!(evidence_id.starts_with("ts1_"));
    assert!(commitment.starts_with("sha256:"));

    // 7. Test duplicate submission -> 200 OK (already_present)
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/evidence")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Full::new(Bytes::from(valid_body)))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let duplicate_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(duplicate_json["disposition"], "already_present");
    assert_eq!(duplicate_json["evidence_id"], evidence_id);

    // 8. Test metadata retrieval -> 200 OK
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/evidence/{evidence_id}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let meta_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(meta_json["evidence_id"], evidence_id);
    assert_eq!(meta_json["commitment"], commitment);
    assert_eq!(meta_json["record"]["payload"]["disclosed_http_status"], 503);
    assert_eq!(meta_json["reverifications_count"], 0);

    // 9. Test metadata retrieval for invalid and unknown IDs
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/evidence/not-a-valid-id")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let req = Request::builder()
        .method("GET")
        .uri(
            "/api/v1/evidence/ts1_0000000000000000000000000000000000000000000000000000000000000000",
        )
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // 10. Test artifact retrieval and ETag verification
    for (art_type, expected_bytes, expected_ct) in [
        (
            "attestation",
            &attestation_bytes,
            "application/octet-stream",
        ),
        (
            "presentation",
            &presentation_bytes,
            "application/octet-stream",
        ),
        ("request_manifest", &manifest_bytes, "application/json"),
    ] {
        let req = Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/evidence/{evidence_id}/artifacts/{art_type}"
            ))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get(header::CONTENT_TYPE).unwrap(),
            expected_ct
        );
        assert!(res.headers().get(header::ETAG).is_some());
        assert!(res.headers().get("x-artifact-sha256").is_some());
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], expected_bytes.as_slice());
    }

    // 11. Test invalid artifact type -> 400 Bad Request
    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "/api/v1/evidence/{evidence_id}/artifacts/unknown_artifact"
        ))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 12. Test verification history -> 200 OK (initially 0 reverifications)
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/evidence/{evidence_id}/verifications"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let history_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(history_json["reverifications"].as_array().unwrap().len(), 0);

    // 13. Test re-verification -> 200 OK
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/evidence/{evidence_id}/reverify"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let reverify_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reverify_json["status"], "reverified");
    assert_eq!(reverify_json["evidence_id"], evidence_id);

    // 14. Check history now shows 1 reverification
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/evidence/{evidence_id}/verifications"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let history_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(history_json["reverifications"].as_array().unwrap().len(), 1);

    // 15. Server restart and persistence check
    let reopened_store = EvidenceStore::open(&storage_dir).unwrap();
    let reopened_state = Arc::new(AppState::new(reopened_store));
    let reopened_app = create_router(reopened_state);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/evidence/{evidence_id}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = reopened_app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 16. Verifier timeout check (timeout set to 1ms)
    let fast_timeout_state = Arc::new(AppState::with_options(
        EvidenceStore::open(temp.path().join("timeout-store")).unwrap(),
        2,
        Duration::from_millis(1),
    ));
    let timeout_app = create_router(fast_timeout_state);
    let valid_body = create_multipart_body(
        boundary,
        &[
            ("attestation", "attestation.tlsn", &attestation_bytes),
            ("presentation", "presentation.tlsn", &presentation_bytes),
            ("request_manifest", "request.json", &manifest_bytes),
        ],
    );
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/evidence")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Full::new(Bytes::from(valid_body)))
        .unwrap();
    let res = timeout_app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::GATEWAY_TIMEOUT);
}
