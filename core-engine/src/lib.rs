pub mod engine;
pub mod evidence;
pub mod fixture;
pub mod storage;

use std::{
    collections::BTreeMap,
    fs,
    future::IntoFuture,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::evidence::{VerifiedRequest, PROOF_FORMAT, TLSNOTARY_VERSION, TRUST_POLICY_ID};
use chrono::{SecondsFormat, Utc};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tlsn::{
    attestation::{
        presentation::Presentation,
        request::{Request as AttestationRequest, RequestConfig},
        signing::Secp256k1Signer,
        Attestation, AttestationConfig, CryptoProvider, Secrets,
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig, verifier::VerifierConfig,
    },
    connection::{CertBinding, ConnectionInfo, HandshakeData, ServerName, TranscriptLength},
    prover::ProverOutput,
    transcript::{ContentType, TranscriptCommitConfig},
    verifier::{ServerCertVerifier, VerifierCommitStart, VerifierOutput},
    webpki::{CertificateDer as TlsCertificateDer, RootCertStore},
    Session,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

const CA_PEM: &[u8] = include_bytes!("../tests/fixtures/ca-cert.pem");
const SERVER_DOMAIN: &str = "localhost";
const SERVER_ADDR: &str = "127.0.0.1:4443";
const TRUSTED_DEMO_KEY: &str = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";
const ALLOWED_FIELDS: &[&str] = &["status", "error", "service", "message"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReport {
    pub schema_version: String,
    pub verification_status: String,
    pub http_status: Option<u16>,
    pub disclosed_evidence: BTreeMap<String, serde_json::Value>,
    pub attestation: ArtifactInfo,
    pub presentation: ArtifactInfo,
    pub verifier: VerifierInfo,
    pub verified_at: String,
    pub errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tlsnotary_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_request: Option<VerifiedRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInfo {
    pub identifier: Option<String>,
    pub sha256: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierInfo {
    pub version: String,
    pub exit_code: Option<i32>,
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn validate_endpoint(url: &str, disclosures: &[String]) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid request URL: {e}"))?;
    if parsed.scheme() != "https"
        || parsed.host_str() != Some(SERVER_DOMAIN)
        || parsed.port_or_known_default() != Some(4443)
        || ![
            "/trace-seal-503",
            "/trace-seal-200",
            "/trace-seal-404",
            "/trace-seal-delay",
        ]
        .contains(&parsed.path())
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(
            "only https://localhost:4443/trace-seal-{503,200,404,delay} is supported".into(),
        );
    }
    if disclosures.is_empty() {
        return Err("select at least one response field to disclose".into());
    }
    for field in disclosures {
        if !ALLOWED_FIELDS.contains(&field.as_str()) {
            return Err(format!("unsupported disclosure field: {field}"));
        }
    }
    Ok(())
}

pub async fn prove(
    url: &str,
    disclosures: &[String],
    output: &Path,
    request_timeout: std::time::Duration,
) -> Result<EvidenceReport, String> {
    validate_endpoint(url, disclosures)?;
    let parsed = url::Url::parse(url).map_err(|e| e.to_string())?;
    fs::create_dir_all(output).map_err(|e| format!("cannot create output directory: {e}"))?;
    let out =
        fs::canonicalize(output).map_err(|e| format!("cannot resolve output directory: {e}"))?;
    let id = format!(
        "{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos(),
        std::process::id()
    );
    let package = out.join(&id);
    let (attestation, secrets, actual_status) = run_prover(parsed.path(), request_timeout).await?;
    let provider = CryptoProvider::default();
    let transcript = HttpTranscript::parse(secrets.transcript()).map_err(|e| e.to_string())?;
    let mut proof_builder = secrets.transcript_proof_builder();
    let request = &transcript.requests[0];
    proof_builder
        .reveal_sent(request.without_data())
        .map_err(|e| e.to_string())?;
    proof_builder
        .reveal_sent(&request.request.target)
        .map_err(|e| e.to_string())?;
    for header in &request.headers {
        if header.name.as_str().eq_ignore_ascii_case("host") {
            proof_builder
                .reveal_sent(header)
                .map_err(|e| e.to_string())?;
        } else {
            proof_builder
                .reveal_sent(header.without_value())
                .map_err(|e| e.to_string())?;
        }
    }
    let response = &transcript.responses[0];
    proof_builder
        .reveal_recv(response.without_data())
        .map_err(|e| e.to_string())?;
    for header in &response.headers {
        proof_builder
            .reveal_recv(header.without_value())
            .map_err(|e| e.to_string())?;
    }
    let json_fields = match response.body.as_ref().map(|b| &b.content) {
        Some(tlsn_formats::http::BodyContent::Json(doc)) => match &doc.root {
            tlsn_formats::json::JsonValue::Object(object) => &object.elems,
            _ => return Err("fixture JSON response root is not an object".into()),
        },
        _ => return Err("fixture response was not parsed as JSON".into()),
    };
    for field in disclosures {
        let pair = json_fields
            .iter()
            .find(|pair| pair.key.view().as_str().as_ref() == field)
            .ok_or_else(|| format!("requested field missing from actual response: {field}"))?;
        proof_builder.reveal_recv(pair).map_err(|e| e.to_string())?;
    }
    let transcript_proof = proof_builder.build().map_err(|e| e.to_string())?;
    let mut presentation_builder = attestation.presentation_builder(&provider);
    presentation_builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    let presentation: Presentation = presentation_builder.build().map_err(|e| e.to_string())?;
    let att_bytes = bincode::serialize(&attestation).map_err(|e| e.to_string())?;
    let pres_bytes = bincode::serialize(&presentation).map_err(|e| e.to_string())?;
    let staging = tempfile::Builder::new()
        .prefix(".traceseal-staging-")
        .tempdir_in(&out)
        .map_err(|e| format!("cannot create temporary artifact directory: {e}"))?;
    let attestation_path = staging.path().join("attestation.tlsn");
    let presentation_path = staging.path().join("presentation.tlsn");
    write_new(&attestation_path, &att_bytes)?;
    write_new(&presentation_path, &pres_bytes)?;
    let manifest = serde_json::json!({"schema_version":"1.0","url":url,"method":"GET","disclosures":disclosures,"created_at":now()});
    write_new(
        &staging.path().join("request.json"),
        &serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?,
    )?;
    // Independent verifier process: its JSON output, exit code, and actual proof are authoritative.
    let exe =
        std::env::current_exe().map_err(|e| format!("cannot locate verifier executable: {e}"))?;
    let child = run_verifier(
        &exe,
        &attestation_path,
        &presentation_path,
        std::time::Duration::from_secs(30),
    )
    .await?;
    let mut report: EvidenceReport = serde_json::from_slice(&child.stdout).map_err(|e| {
        format!(
            "verifier returned invalid report (exit {:?}): {e}; stderr: {}",
            child.status.code(),
            String::from_utf8_lossy(&child.stderr)
        )
    })?;
    report.verifier.exit_code = child.status.code();
    if report.verification_status == "VERIFIED" && !child.status.success() {
        report.verification_status = "ERROR".into();
        report.errors.push(format!(
            "verifier process exited unsuccessfully with {:?}",
            child.status.code()
        ));
    }
    if report.verification_status == "VERIFIED"
        && report.http_status != Some(actual_status.as_u16())
    {
        return Err("independent verifier status did not match the prover's HTTP response".into());
    }
    write_new(
        &staging.path().join("verification-report.json"),
        &serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )?;
    let staged_path = staging.path().to_path_buf();
    fs::rename(&staged_path, &package).map_err(|e| {
        format!("cannot publish verified artifact package without overwriting: {e}")
    })?;
    drop(staging);
    eprintln!("Artifacts: {}", package.display());
    Ok(report)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("safe create failed for {}: {e}", path.display()))?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

fn root_store() -> RootCertStore {
    let mut reader = std::io::BufReader::new(CA_PEM);
    let cert = rustls_pemfile::certs(&mut reader)
        .next()
        .expect("CA cert exists")
        .expect("CA PEM parses");
    RootCertStore {
        roots: vec![TlsCertificateDer(cert.as_ref().to_vec())],
    }
}

async fn run_prover(
    uri: &str,
    timeout: std::time::Duration,
) -> Result<(Attestation, Secrets, StatusCode), String> {
    tls_preflight(timeout).await?;
    let tcp = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(SERVER_ADDR))
        .await
        .map_err(|_| {
            format!(
                "fixture connection timed out after {} seconds",
                timeout.as_secs()
            )
        })?
        .map_err(|e| format!("fixture connection failed before TLSNotary session setup: {e}"))?;
    let (notary_socket, prover_socket) = tokio::io::duplex(1 << 23);
    let notary_task = tokio::spawn(async move { notary(notary_socket).await });
    let prover_result = match tokio::time::timeout(timeout, prover(prover_socket, tcp, uri)).await {
        Ok(result) => result,
        Err(_) => {
            notary_task.abort();
            return Err(format!(
                "HTTPS proving request timed out after {} seconds",
                timeout.as_secs()
            ));
        }
    };
    if let Err(prover_error) = prover_result {
        let notary_error =
            match tokio::time::timeout(std::time::Duration::from_secs(2), notary_task).await {
                Ok(Ok(Err(error))) => format!("; local attestor reported: {error}"),
                Ok(Err(error)) => format!("; local attestor task failed: {error}"),
                Err(_) => String::new(),
                Ok(Ok(Ok(()))) => String::new(),
            };
        return Err(format!("{prover_error}{notary_error}"));
    }
    tokio::time::timeout(timeout, notary_task)
        .await
        .map_err(|_| "local attestor timed out".to_string())?
        .map_err(|e| format!("local attestor task failed: {e}"))??;
    prover_result
}

async fn tls_preflight(timeout: std::time::Duration) -> Result<(), String> {
    let mut roots = rustls::RootCertStore::empty();
    let mut pem = std::io::BufReader::new(CA_PEM);
    for cert in rustls_pemfile::certs(&mut pem) {
        roots
            .add(cert.map_err(|e| format!("invalid local CA certificate: {e}"))?)
            .map_err(|e| format!("invalid local CA certificate: {e}"))?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let tcp = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(SERVER_ADDR))
        .await
        .map_err(|_| {
            format!(
                "TLS preflight connection timed out after {} seconds",
                timeout.as_secs()
            )
        })?
        .map_err(|e| format!("TLS preflight connection failed: {e}"))?;
    let name = rustls::pki_types::ServerName::try_from(SERVER_DOMAIN.to_owned())
        .map_err(|e| format!("invalid server name: {e}"))?;
    let tls = tokio::time::timeout(timeout, connector.connect(name, tcp))
        .await
        .map_err(|_| {
            format!(
                "TLS handshake timed out after {} seconds",
                timeout.as_secs()
            )
        })?
        .map_err(|e| format!("TLS preflight failed: {e}"))?;
    drop(tls);
    Ok(())
}

async fn prover<S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static>(
    socket: S,
    tcp: tokio::net::TcpStream,
    uri: &str,
) -> Result<(Attestation, Secrets, StatusCode), String> {
    let (driver, mut handle) = Session::new(socket.compat()).split();
    let driver_task = tokio::spawn(driver);
    let prover = handle
        .new_prover(ProverConfig::builder().build().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?
        .commit(
            MpcTlsConfig::builder()
                .max_sent_data(1 << 12)
                .max_recv_data(1 << 14)
                .build()
                .map_err(|e| e.to_string())?,
        )
        .await
        .map_err(|e| e.to_string())?;
    let (tls, prover) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(
                    SERVER_DOMAIN
                        .try_into()
                        .map_err(|e| format!("server name: {e:?}"))?,
                ))
                .root_store(root_store())
                .build()
                .map_err(|e| e.to_string())?,
            tcp.compat(),
        )
        .map_err(|e| e.to_string())?;
    let tls = TokioIo::new(tls.compat());
    let prover_task = tokio::spawn(prover.into_future());
    let (mut sender, conn) = hyper::client::conn::http1::handshake(tls)
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let req = Request::builder()
        .uri(uri)
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "application/json")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
        .map_err(|e| e.to_string())?;
    let response = sender
        .send_request(req)
        .await
        .map_err(|e| format!("HTTPS request failed: {e}"))?;
    let status = response.status();
    let _response_bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("HTTP response body failed: {e}"))?
        .to_bytes();
    let mut prover = prover_task
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    let transcript = HttpTranscript::parse(prover.transcript()).map_err(|e| e.to_string())?;
    let mut commit = TranscriptCommitConfig::builder(prover.transcript());
    DefaultHttpCommitter::default()
        .commit_transcript(&mut commit, &transcript)
        .map_err(|e| e.to_string())?;
    let commit = commit.build().map_err(|e| e.to_string())?;
    let mut request_config = RequestConfig::builder();
    request_config.transcript_commit(commit);
    let request_config = request_config.build().map_err(|e| e.to_string())?;
    let mut prove = ProveConfig::builder(prover.transcript());
    if let Some(commit) = request_config.transcript_commit() {
        prove.transcript_commit(commit.clone());
    }
    let output = prove.build().map_err(|e| e.to_string())?;
    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&output).await.map_err(|e| e.to_string())?;
    let prover_transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await.map_err(|e| e.to_string())?;
    let mut req = AttestationRequest::builder(&request_config);
    req.server_name(ServerName::Dns(
        SERVER_DOMAIN
            .try_into()
            .map_err(|e| format!("server name: {e:?}"))?,
    ))
    .handshake_data(HandshakeData {
        certs: tls_transcript
            .server_cert_chain()
            .ok_or("server certificate unavailable")?
            .to_vec(),
        sig: tls_transcript
            .server_signature()
            .ok_or("server signature unavailable")?
            .clone(),
        binding: tls_transcript.certificate_binding().clone(),
    })
    .transcript(prover_transcript)
    .transcript_commitments(transcript_secrets, transcript_commitments);
    let request_config = req
        .build(&CryptoProvider::default())
        .map_err(|e| e.to_string())?;
    let (request, secrets) = request_config;
    handle.close();
    let mut socket = driver_task
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    let bytes = bincode::serialize(&request).map_err(|e| e.to_string())?;
    socket.write_all(&bytes).await.map_err(|e| e.to_string())?;
    socket.close().await.map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    socket
        .read_to_end(&mut bytes)
        .await
        .map_err(|e| e.to_string())?;
    let attestation: Attestation = bincode::deserialize(&bytes)
        .map_err(|e| format!("malformed attestation from local attestor: {e}"))?;
    request
        .validate(&attestation, &CryptoProvider::default())
        .map_err(|e| e.to_string())?;
    Ok((attestation, secrets, status))
}

async fn notary<S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static>(
    socket: S,
) -> Result<(), String> {
    let (driver, mut handle) = Session::new(socket.compat()).split();
    let driver_task = tokio::spawn(driver);
    let config = VerifierConfig::builder()
        .root_store(root_store())
        .build()
        .map_err(|e| e.to_string())?;
    let verifier = match handle
        .new_verifier(config)
        .map_err(|e| e.to_string())?
        .commit()
        .await
        .map_err(|e| e.to_string())?
    {
        VerifierCommitStart::Mpc(v) => v
            .accept()
            .await
            .map_err(|e| e.to_string())?
            .run()
            .await
            .map_err(|e| e.to_string())?,
        VerifierCommitStart::Proxy(v) => {
            v.reject(Some("TRACESEAL fixture uses MPC TLS"))
                .await
                .map_err(|e| e.to_string())?;
            return Err("unexpected proxy protocol".into());
        }
    };
    let (
        VerifierOutput {
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier
        .verify()
        .await
        .map_err(|e| e.to_string())?
        .accept()
        .await
        .map_err(|e| e.to_string())?;
    let tls = verifier.tls_transcript().clone();
    verifier.close().await.map_err(|e| e.to_string())?;
    let sent = tls
        .sent()
        .iter()
        .filter(|r| matches!(r.typ, ContentType::ApplicationData))
        .map(|r| r.ciphertext.len())
        .sum::<usize>();
    let recv = tls
        .recv()
        .iter()
        .filter(|r| matches!(r.typ, ContentType::ApplicationData))
        .map(|r| r.ciphertext.len())
        .sum::<usize>();
    handle.close();
    let mut socket = driver_task
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    socket
        .read_to_end(&mut bytes)
        .await
        .map_err(|e| e.to_string())?;
    let request: AttestationRequest = bincode::deserialize(&bytes).map_err(|e| e.to_string())?;
    let key_hex = std::env::var("TRACESEAL_TEST_ATTESTOR_KEY").map_err(|_| {
        "TRACESEAL_TEST_ATTESTOR_KEY is required for the local test attestor".to_string()
    })?;
    let key = hex::decode(key_hex)
        .map_err(|_| "TRACESEAL_TEST_ATTESTOR_KEY must be 64 hexadecimal characters".to_string())?;
    if key.len() != 32 {
        return Err("TRACESEAL_TEST_ATTESTOR_KEY must decode to 32 bytes".into());
    }
    let signer = Box::new(
        Secp256k1Signer::new(&key).map_err(|_| "local test attestor key is invalid".to_string())?,
    );
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);
    let mut cfg = AttestationConfig::builder();
    cfg.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    let cfg = cfg.build().map_err(|e| e.to_string())?;
    let CertBinding::V1_2(binding) = tls.certificate_binding() else {
        return Err("pinned TLSNotary attestation path only supports TLS 1.2 binding".into());
    };
    let mut builder = Attestation::builder(&cfg)
        .accept_request(request)
        .map_err(|e| e.to_string())?;
    builder
        .connection_info(ConnectionInfo {
            time: tls.time(),
            version: tls.version(),
            transcript_length: TranscriptLength {
                sent: sent as u32,
                received: recv as u32,
            },
        })
        .server_ephemeral_key(binding.server_ephemeral_key.clone())
        .transcript_commitments(transcript_commitments);
    let attestation = builder.build(&provider).map_err(|e| e.to_string())?;
    let bytes = bincode::serialize(&attestation).map_err(|e| e.to_string())?;
    socket.write_all(&bytes).await.map_err(|e| e.to_string())?;
    socket.close().await.map_err(|e| e.to_string())?;
    Ok(())
}

pub fn verify_files(attestation_path: &Path, presentation_path: &Path) -> EvidenceReport {
    let att_bytes = fs::read(attestation_path);
    let pres_bytes = fs::read(presentation_path);
    let mut report = EvidenceReport {
        schema_version: "1.0".into(),
        verification_status: "ERROR".into(),
        http_status: None,
        disclosed_evidence: BTreeMap::new(),
        attestation: artifact(att_bytes.as_deref().unwrap_or_default()),
        presentation: artifact(pres_bytes.as_deref().unwrap_or_default()),
        verifier: VerifierInfo {
            version: format!(
                "traceseal-core {}; tlsn v0.1.0-alpha.15",
                env!("CARGO_PKG_VERSION")
            ),
            exit_code: None,
        },
        verified_at: now(),
        errors: vec![],
        proof_format: None,
        tlsnotary_version: None,
        trust_policy_id: None,
        verified_request: None,
    };
    let (Ok(att_bytes), Ok(pres_bytes)) = (att_bytes, pres_bytes) else {
        report
            .errors
            .push("attestation or presentation artifact is missing or unreadable".into());
        return report;
    };
    let att: Attestation = match bincode::deserialize(&att_bytes) {
        Ok(v) => v,
        Err(e) => {
            report.verification_status = "REJECTED".into();
            report
                .errors
                .push(format!("invalid attestation encoding: {e}"));
            return report;
        }
    };
    let pres: Presentation = match bincode::deserialize(&pres_bytes) {
        Ok(v) => v,
        Err(e) => {
            report.verification_status = "REJECTED".into();
            report.errors.push(format!("malformed presentation: {e}"));
            return report;
        }
    };
    if hex::encode(&pres.verifying_key().data) != TRUSTED_DEMO_KEY {
        report.verification_status = "REJECTED".into();
        report
            .errors
            .push("attestation signing key is not the configured local demo trust key".into());
        return report;
    }
    let root = root_store();
    let provider = match ServerCertVerifier::new(&root) {
        Ok(cert) => CryptoProvider {
            cert,
            ..Default::default()
        },
        Err(e) => {
            report
                .errors
                .push(format!("cannot initialize verifier: {e}"));
            return report;
        }
    };
    let att_presentation = match att.presentation_builder(&provider).build() {
        Ok(v) => v,
        Err(e) => {
            report.verification_status = "REJECTED".into();
            report
                .errors
                .push(format!("attestation signature rejected: {e}"));
            return report;
        }
    };
    let att_check = match att_presentation.verify(&provider) {
        Ok(v) => v.attestation,
        Err(e) => {
            report.verification_status = "REJECTED".into();
            report
                .errors
                .push(format!("attestation signature rejected: {e}"));
            return report;
        }
    };
    let output = match pres.verify(&provider) {
        Ok(v) => v,
        Err(e) => {
            report.verification_status = "REJECTED".into();
            report.errors.push(format!("presentation rejected: {e}"));
            return report;
        }
    };
    if bincode::serialize(&att_check).ok() != bincode::serialize(&att).ok() {
        report.verification_status = "REJECTED".into();
        report
            .errors
            .push("presentation is bound to a different attestation".into());
        return report;
    }
    if output
        .server_name
        .as_ref()
        .map(ToString::to_string)
        .as_deref()
        != Some(SERVER_DOMAIN)
    {
        report.verification_status = "REJECTED".into();
        report
            .errors
            .push("presentation is not bound to localhost".into());
        return report;
    }
    let Some(mut transcript) = output.transcript else {
        report.verification_status = "REJECTED".into();
        report
            .errors
            .push("verified presentation has no disclosed transcript".into());
        return report;
    };
    transcript.set_unauthed(b'X');
    let sent = String::from_utf8_lossy(transcript.sent_unsafe());
    let request_line = sent.lines().next().unwrap_or_default();
    let request_parts = request_line.split_whitespace().collect::<Vec<_>>();
    let host_headers = sent
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim())
        .collect::<Vec<_>>();
    if request_parts.len() != 3
        || request_parts[0] != "GET"
        || ![
            "/trace-seal-503",
            "/trace-seal-200",
            "/trace-seal-404",
            "/trace-seal-delay",
        ]
        .contains(&request_parts[1])
        || request_parts[2] != "HTTP/1.1"
        || host_headers.as_slice() != ["localhost"]
    {
        report.verification_status = "REJECTED".into();
        report
            .errors
            .push("presentation does not disclose the expected GET request to localhost".into());
        return report;
    }
    let verified_request = VerifiedRequest {
        scheme: "https".into(),
        host: SERVER_DOMAIN.into(),
        method: request_parts[0].into(),
        path: request_parts[1].into(),
    };
    let recv = transcript.received_unsafe();
    let Some(split) = recv.windows(4).position(|w| w == b"\r\n\r\n") else {
        report.verification_status = "REJECTED".into();
        report
            .errors
            .push("disclosed HTTP response headers are incomplete".into());
        return report;
    };
    let headers = String::from_utf8_lossy(&recv[..split]);
    let Some(line) = headers.lines().next() else {
        report.verification_status = "REJECTED".into();
        report.errors.push("HTTP status line is missing".into());
        return report;
    };
    report.http_status = line.split_whitespace().nth(1).and_then(|s| s.parse().ok());
    let body = &recv[split + 4..];
    for field in ALLOWED_FIELDS {
        let needle = format!("\"{field}\"");
        if let Some(pos) = find_bytes(body, needle.as_bytes()) {
            let after = &body[pos + needle.len()..];
            if let Some(colon) = after.iter().position(|b| *b == b':') {
                let value = trim_ascii(&after[colon + 1..]);
                let end = value
                    .windows(2)
                    .position(|w| w == b"X\"")
                    .or_else(|| value.iter().position(|b| *b == b'X'))
                    .unwrap_or(value.len());
                let mut value = &value[..end];
                while value.last() == Some(&b'X') {
                    value = &value[..value.len() - 1];
                }
                let mut de =
                    serde_json::Deserializer::from_slice(value).into_iter::<serde_json::Value>();
                if let Some(Ok(v)) = de.next() {
                    report.disclosed_evidence.insert((*field).to_owned(), v);
                }
            }
        }
    }
    if report.http_status.is_none() {
        report.verification_status = "REJECTED".into();
        report
            .errors
            .push("HTTP status code was not disclosed".into());
    } else {
        report.verification_status = "VERIFIED".into();
        report.proof_format = Some(PROOF_FORMAT.into());
        report.tlsnotary_version = Some(TLSNOTARY_VERSION.into());
        report.trust_policy_id = Some(TRUST_POLICY_ID.into());
        report.verified_request = Some(verified_request);
    }
    report
}

fn artifact(bytes: &[u8]) -> ArtifactInfo {
    if bytes.is_empty() {
        ArtifactInfo {
            identifier: None,
            sha256: None,
        }
    } else {
        let hash = sha256(bytes);
        ArtifactInfo {
            identifier: Some(hash.clone()),
            sha256: Some(hash),
        }
    }
}

pub async fn run_verifier(
    executable: &Path,
    attestation: &Path,
    presentation: &Path,
    timeout: std::time::Duration,
) -> Result<std::process::Output, String> {
    let mut cmd = tokio::process::Command::new(executable);
    cmd.args([
        "verify",
        "--attestation",
        attestation
            .to_str()
            .ok_or("attestation path is not valid Unicode")?,
        "--presentation",
        presentation
            .to_str()
            .ok_or("presentation path is not valid Unicode")?,
    ])
    .kill_on_drop(true);
    run_process_with_timeout(&mut cmd, timeout).await
}

pub async fn run_process_with_timeout(
    cmd: &mut tokio::process::Command,
    timeout: std::time::Duration,
) -> Result<std::process::Output, String> {
    cmd.kill_on_drop(true);
    tokio::time::timeout(timeout, cmd.output())
        .await
        .map_err(|_| {
            format!(
                "independent verifier timed out after {} seconds",
                timeout.as_secs()
            )
        })?
        .map_err(|e| format!("verifier process failed to start: {e}"))
}
fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while s.first().is_some_and(u8::is_ascii_whitespace) {
        s = &s[1..]
    }
    s
}
