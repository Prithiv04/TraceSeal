//! Hedera anchoring layer for TraceSeal.
//!
//! Architecture: the Rust backend never holds Hedera keys in-process for
//! signing. All Hedera operations (HCS publish, HTS mint, Mirror Node reads)
//! are delegated to a Node.js sidecar (`hedera/src/cli.mjs`) that uses the
//! official `@hashgraph/sdk`. The sidecar is located relative to the
//! `traceseal-core` executable or via `HEDERA_SIDECAR` env override.
//!
//! Reliability model:
//! - Every Hedera operation is recorded in the `hedera_events` outbox table
//!   *before* it is attempted, keyed by a deterministic dedupe key so retries
//!   and restarts can never duplicate an on-chain operation.
//! - NFT minting is guarded by a UNIQUE constraint on the commitment hex in
//!   `hedera_receipts`, so one commitment can only ever mint one NFT.
//! - A successful TLSNotary verification is fully independent of Hedera
//!   outcomes: if Hedera is unconfigured or fails, evidence remains stored
//!   and verifiable.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use tokio::process::Command;

use crate::storage::EvidenceStore;

pub const AUDIT_SCHEMA: &str = "traceseal.audit.v1";
pub const SIDECAR_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, Error)]
pub enum HederaError {
    #[error("hedera is not configured: {0}")]
    NotConfigured(String),
    #[error("sidecar execution failed: {0}")]
    Sidecar(String),
    #[error("sidecar returned invalid output: {0}")]
    BadOutput(String),
    #[error("hedera operation rejected: {0}")]
    Rejected(String),
    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),
}

/// Non-secret Hedera configuration derived from the environment.
#[derive(Debug, Clone)]
pub struct HederaConfig {
    pub network: String,
    pub account_id: Option<String>,
    pub topic_id: Option<String>,
    pub nft_token_id: Option<String>,
    pub mirror_node_url: String,
    pub sidecar_path: PathBuf,
}

/// Load `hedera/.env` (next to the sidecar's parent dir) into the process
/// environment for any HEDERA_* var not already set. Real environment
/// variables always win. No external crate — tiny KEY=VALUE parser.
fn load_env_file(sidecar_path: &Path) {
    // sidecar_path = <repo>/hedera/src/cli.mjs → .env is ../../.env
    let env_path = sidecar_path
        .parent() // src/
        .and_then(|p| p.parent()) // hedera/
        .map(|d| d.join(".env"));
    let Some(path) = env_path else { return };
    let Ok(contents) = std::fs::read_to_string(&path) else { return };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim();
        if !key.starts_with("HEDERA_") {
            continue;
        }
        let mut value = value.trim().to_string();
        if (value.starts_with('"') && value.ends_with('"') && value.len() >= 2)
            || (value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2)
        {
            value = value[1..value.len() - 1].to_string();
        }
        // Never override a variable already present in the real environment.
        if std::env::var_os(key).is_none() {
            std::env::set_var(key, &value);
        }
    }
}

impl HederaConfig {
    pub fn from_env() -> Self {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        // Prefer <repo>/hedera/src/cli.mjs discovered by walking up from the
        // executable; fall back to HEDERA_SIDECAR override or cwd-relative.
        let mut candidates = Vec::new();
        if let Ok(custom) = std::env::var("HEDERA_SIDECAR") {
            candidates.push(PathBuf::from(custom));
        }
        for ancestor in exe_dir.ancestors() {
            candidates.push(ancestor.join("hedera").join("src").join("cli.mjs"));
        }
        candidates.push(PathBuf::from("hedera").join("src").join("cli.mjs"));
        let sidecar_path = candidates
            .into_iter()
            .find(|p| p.is_file())
            .unwrap_or_else(|| PathBuf::from("hedera").join("src").join("cli.mjs"));

        // Load hedera/.env for any HEDERA_* var not already in the environment.
        load_env_file(&sidecar_path);

        let network = std::env::var("HEDERA_NETWORK")
            .unwrap_or_else(|_| "testnet".to_string())
            .to_lowercase();
        let mirror_node_url = std::env::var("HEDERA_MIRROR_NODE_URL").unwrap_or_else(|_| {
            format!("https://{network}.mirrornode.hedera.com")
        });
        Self {
            network,
            account_id: std::env::var("HEDERA_ACCOUNT_ID").ok().filter(|s| !s.is_empty()),
            topic_id: std::env::var("HEDERA_TOPIC_ID").ok().filter(|s| !s.is_empty()),
            nft_token_id: std::env::var("HEDERA_NFT_TOKEN_ID")
                .ok()
                .filter(|s| !s.is_empty()),
            mirror_node_url,
            sidecar_path,
        }
    }

    /// Credentials are present only when account id + private key are set.
    /// The private key itself is never stored in this struct.
    pub fn credentials_present(&self) -> bool {
        self.account_id.is_some()
            && std::env::var("HEDERA_PRIVATE_KEY")
                .map(|k| !k.is_empty())
                .unwrap_or(false)
    }

    pub fn is_fully_configured(&self) -> bool {
        self.credentials_present() && self.topic_id.is_some() && self.nft_token_id.is_some()
    }

    /// Human-readable list of missing configuration (no secret values).
    pub fn missing(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.account_id.is_none() {
            missing.push("HEDERA_ACCOUNT_ID");
        }
        if !self
            .credentials_present()
            && std::env::var("HEDERA_PRIVATE_KEY")
                .map(|k| k.is_empty())
                .unwrap_or(true)
        {
            missing.push("HEDERA_PRIVATE_KEY");
        }
        if self.topic_id.is_none() {
            missing.push("HEDERA_TOPIC_ID");
        }
        if self.nft_token_id.is_none() {
            missing.push("HEDERA_NFT_TOKEN_ID");
        }
        missing
    }
}

/// Invoke the Node sidecar and parse its single-line JSON response.
pub async fn run_sidecar(
    config: &HederaConfig,
    args: &[String],
) -> Result<Value, HederaError> {
    if !config.sidecar_path.is_file() {
        return Err(HederaError::Sidecar(format!(
            "sidecar not found at {}",
            config.sidecar_path.display()
        )));
    }
    let mut cmd = Command::new("node");
    cmd.arg(&config.sidecar_path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Pass through Hedera env vars; the sidecar reads them itself.
    for var in [
        "HEDERA_NETWORK",
        "HEDERA_ACCOUNT_ID",
        "HEDERA_PRIVATE_KEY",
        "HEDERA_TOPIC_ID",
        "HEDERA_NFT_TOKEN_ID",
        "HEDERA_MIRROR_NODE_URL",
    ] {
        if let Ok(v) = std::env::var(var) {
            cmd.env(var, v);
        }
    }
    let output = tokio::time::timeout(SIDECAR_TIMEOUT, cmd.output())
        .await
        .map_err(|_| HederaError::Sidecar("sidecar timed out".into()))?
        .map_err(|e| HederaError::Sidecar(format!("failed to spawn node: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let line = stdout.lines().last().unwrap_or("").trim();
    let parsed: Value = serde_json::from_str(line).map_err(|_| {
        HederaError::BadOutput(format!(
            "non-JSON sidecar output (stderr: {})",
            stderr.chars().take(300).collect::<String>()
        ))
    })?;
    if parsed.get("ok").and_then(Value::as_bool) != Some(true) {
        let code = parsed
            .pointer("/error/code")
            .and_then(Value::as_str)
            .unwrap_or("SIDECAR_ERROR");
        let message = parsed
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("unknown sidecar error");
        return Err(HederaError::Rejected(format!("{code}: {message}")));
    }
    Ok(parsed)
}

/* ------------------------- audit event payloads ------------------------ */

/// Build the canonical audit message for an HCS publish.
pub fn audit_message(
    event: &str,
    evidence_id: &str,
    commitment: &str,
    config: &HederaConfig,
    verifier_version: &str,
    trust_policy_id: &str,
    extra: Value,
) -> Value {
    let mut msg = json!({
        "schema": AUDIT_SCHEMA,
        "event": event,
        "evidence_id": evidence_id,
        "commitment": commitment,
        "network": config.network,
        "verifier_version": verifier_version,
        "trust_policy_id": trust_policy_id,
        "anchored_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    if let (Some(obj), Value::Object(extra_obj)) = (msg.as_object_mut(), extra) {
        for (k, v) in extra_obj {
            obj.insert(k, v);
        }
    }
    msg
}

/// Deterministic dedupe key for an outbox event — retries reuse it.
pub fn dedupe_key(event: &str, evidence_id: &str, discriminator: &str) -> String {
    format!("{event}:{evidence_id}:{discriminator}")
}

/// Extract the 32-byte commitment hex (without `sha256:` prefix) for NFT metadata.
pub fn commitment_hex(commitment: &str) -> Option<String> {
    commitment
        .strip_prefix("sha256:")
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|h| h.to_ascii_lowercase())
}

/// Hex-encode bytes for the sidecar `--metadata-hex` argument.
pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Locate the sidecar for status reporting.
pub fn sidecar_exists(config: &HederaConfig) -> bool {
    config.sidecar_path.is_file()
}

/// Store reference kept for API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HederaEventRecord {
    pub event_id: i64,
    pub evidence_id: String,
    pub event_type: String,
    pub dedupe_key: String,
    pub status: String,
    pub topic_id: Option<String>,
    pub sequence_number: Option<String>,
    pub consensus_timestamp: Option<String>,
    pub transaction_id: Option<String>,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HederaReceiptRecord {
    pub evidence_id: String,
    pub commitment: String,
    pub token_id: String,
    pub serial_number: String,
    pub mint_transaction_id: Option<String>,
    pub mint_consensus_timestamp: Option<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Convenience: enqueue + drain helpers live on EvidenceStore (storage.rs)
/// so the outbox shares the same SQLite connection handling.
pub fn _unused_store_marker(_: &EvidenceStore) {}

/* --------------------------- orchestration ---------------------------- */

/// Result of a drain pass, for API responses and tests.
#[derive(Debug, Clone, Serialize)]
pub struct DrainReport {
    pub published: usize,
    pub minted: usize,
    pub failed: usize,
    pub skipped_unconfigured: bool,
}

/// Enqueue the Hedera lifecycle for a freshly stored evidence record and
/// drain the outbox. Safe to call for `already_present` receipts too —
/// dedupe keys make every step idempotent.
pub async fn anchor_evidence(
    store: &EvidenceStore,
    config: &HederaConfig,
    evidence_id: &str,
) -> Result<DrainReport, HederaError> {
    let metadata = store.get_metadata(evidence_id)?;
    let record = &metadata.record;
    let report = &metadata.original_verification;

    // 1. EVIDENCE_VERIFIED audit event (deduped per evidence).
    let msg = audit_message(
        "EVIDENCE_VERIFIED",
        evidence_id,
        record.commitment(),
        config,
        &report.verifier.version,
        report.trust_policy_id.as_deref().unwrap_or("unknown"),
        json!({}),
    );
    let key = dedupe_key("EVIDENCE_VERIFIED", evidence_id, "original");
    store.enqueue_hedera_event(
        evidence_id,
        "EVIDENCE_VERIFIED",
        &key,
        &serde_json::to_string(&msg).map_err(|e| HederaError::BadOutput(e.to_string()))?,
    )?;

    // 2. Reserve the NFT receipt slot (UNIQUE commitment_hex = no double mint).
    if let Some(hex) = commitment_hex(record.commitment()) {
        if config.nft_token_id.is_some() {
            store.reserve_hedera_receipt(
                evidence_id,
                record.commitment(),
                &hex,
                config.nft_token_id.as_deref().unwrap(),
            )?;
        }
    }

    drain_outbox(store, config).await
}

/// Enqueue an EVIDENCE_REVERIFIED audit event after a successful
/// re-verification, then drain. No new NFT is minted (receipt already exists).
pub async fn anchor_reverification(
    store: &EvidenceStore,
    config: &HederaConfig,
    evidence_id: &str,
) -> Result<DrainReport, HederaError> {
    let metadata = store.get_metadata(evidence_id)?;
    let record = &metadata.record;
    let count = metadata.reverifications.len();
    let latest = metadata.reverifications.last();
    let (verifier_version, trust_policy) = latest
        .map(|r| {
            (
                r.verifier.version.clone(),
                r.trust_policy_id.clone().unwrap_or_else(|| "unknown".into()),
            )
        })
        .unwrap_or_else(|| ("unknown".into(), "unknown".into()));
    let msg = audit_message(
        "EVIDENCE_REVERIFIED",
        evidence_id,
        record.commitment(),
        config,
        &verifier_version,
        &trust_policy,
        json!({ "reverification_index": count }),
    );
    let key = dedupe_key("EVIDENCE_REVERIFIED", evidence_id, &count.to_string());
    store.enqueue_hedera_event(
        evidence_id,
        "EVIDENCE_REVERIFIED",
        &key,
        &serde_json::to_string(&msg).map_err(|e| HederaError::BadOutput(e.to_string()))?,
    )?;
    drain_outbox(store, config).await
}

/// Process the outbox: publish pending HCS events, then mint pending NFT
/// receipts (each mint enqueues a RECEIPT_MINTED event published in the
/// same pass). Never marks anything confirmed without sidecar success.
pub async fn drain_outbox(
    store: &EvidenceStore,
    config: &HederaConfig,
) -> Result<DrainReport, HederaError> {
    let mut report = DrainReport {
        published: 0,
        minted: 0,
        failed: 0,
        skipped_unconfigured: false,
    };
    if !config.credentials_present() {
        report.skipped_unconfigured = true;
        return Ok(report);
    }

    // Pass 1: publish pending audit events.
    for event in store.pending_hedera_events(50)? {
        let payload: Value = match serde_json::from_str(&event.payload_json) {
            Ok(v) => v,
            Err(e) => {
                let _ = store.mark_hedera_event_failed(&event.dedupe_key, &format!("bad payload: {e}"));
                report.failed += 1;
                continue;
            }
        };
        match run_sidecar(
            config,
            &[
                "publish".into(),
                "--message".into(),
                payload.to_string(),
            ],
        )
        .await
        {
            Ok(res) => {
                let topic = res
                    .get("topic_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let seq = res
                    .get("sequence_number")
                    .map(|v| v.to_string().trim_matches('"').to_string())
                    .unwrap_or_default();
                let ts = res
                    .get("consensus_timestamp")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let tx = res
                    .get("transaction_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                store.mark_hedera_event_submitted(
                    &event.dedupe_key, &topic, &seq, &ts, &tx,
                )?;
                report.published += 1;
            }
            Err(e) => {
                let _ = store.mark_hedera_event_failed(&event.dedupe_key, &e.to_string());
                report.failed += 1;
            }
        }
    }

    // Pass 2: mint pending NFT receipts.
    for receipt in store.pending_hedera_receipts()? {
        let Some(token_id) = config.nft_token_id.clone() else {
            report.skipped_unconfigured = true;
            break;
        };
        if receipt.token_id != token_id {
            // Config changed since reservation — skip rather than mint to wrong collection.
            continue;
        }
        match run_sidecar(
            config,
            &[
                "mint".into(),
                "--metadata-hex".into(),
                receipt.commitment_hex.clone(),
            ],
        )
        .await
        {
            Ok(res) => {
                let serial = res
                    .get("serial_number")
                    .map(|v| v.to_string().trim_matches('"').to_string())
                    .unwrap_or_default();
                let tx = res
                    .get("transaction_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let ts = res
                    .get("consensus_timestamp")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                store.mark_hedera_receipt_minted(
                    &receipt.evidence_id, &serial, &tx, &ts,
                )?;
                report.minted += 1;

                // Enqueue RECEIPT_MINTED audit event referencing the mint.
                if let Ok(meta) = store.get_metadata(&receipt.evidence_id) {
                    let msg = audit_message(
                        "RECEIPT_MINTED",
                        &receipt.evidence_id,
                        &receipt.commitment,
                        config,
                        &meta.original_verification.verifier.version,
                        meta.original_verification
                            .trust_policy_id
                            .as_deref()
                            .unwrap_or("unknown"),
                        json!({
                            "nft_token_id": token_id,
                            "nft_serial": serial,
                            "mint_transaction_id": tx,
                        }),
                    );
                    let key = dedupe_key(
                        "RECEIPT_MINTED",
                        &receipt.evidence_id,
                        &serial,
                    );
                    if let Ok(payload) = serde_json::to_string(&msg) {
                        let _ = store.enqueue_hedera_event(
                            &receipt.evidence_id,
                            "RECEIPT_MINTED",
                            &key,
                            &payload,
                        );
                    }
                }
            }
            Err(e) => {
                let _ = store.mark_hedera_receipt_failed(&receipt.evidence_id, &e.to_string());
                report.failed += 1;
            }
        }
    }

    // Pass 3: publish any RECEIPT_MINTED events enqueued in pass 2.
    for event in store.pending_hedera_events(50)? {
        if event.event_type != "RECEIPT_MINTED" {
            continue;
        }
        let payload: Value = match serde_json::from_str(&event.payload_json) {
            Ok(v) => v,
            Err(_) => continue,
        };
        match run_sidecar(
            config,
            &["publish".into(), "--message".into(), payload.to_string()],
        )
        .await
        {
            Ok(res) => {
                let topic = res
                    .get("topic_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let seq = res
                    .get("sequence_number")
                    .map(|v| v.to_string().trim_matches('"').to_string())
                    .unwrap_or_default();
                let ts = res
                    .get("consensus_timestamp")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let tx = res
                    .get("transaction_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                store.mark_hedera_event_submitted(
                    &event.dedupe_key, &topic, &seq, &ts, &tx,
                )?;
                report.published += 1;
            }
            Err(e) => {
                let _ = store.mark_hedera_event_failed(&event.dedupe_key, &e.to_string());
                report.failed += 1;
            }
        }
    }

    Ok(report)
}

/* ------------------------- mirror node checks ------------------------- */

/// HashScan explorer base for the configured network.
pub fn hashscan_base(network: &str) -> &'static str {
    match network {
        "mainnet" => "https://hashscan.io/mainnet",
        "previewnet" => "https://hashscan.io/previewnet",
        _ => "https://hashscan.io/testnet",
    }
}

/// Verify on-chain state for one evidence record via Mirror Node:
/// - HCS: fetch each CONFIRMED event's message, decode, compare commitment.
/// - NFT: fetch the minted NFT, compare metadata commitment hex.
/// Returns a JSON report; never trusts local flags alone.
pub async fn mirror_verify_evidence(
    store: &EvidenceStore,
    config: &HederaConfig,
    evidence_id: &str,
) -> Result<Value, HederaError> {
    let metadata = store.get_metadata(evidence_id)?;
    let commitment = metadata.record.commitment().to_string();
    let commitment_hex = commitment_hex(&commitment).unwrap_or_default();

    let mut hcs_results = Vec::new();
    for event in store.hedera_events_for(evidence_id)? {
        if event.status != "CONFIRMED" {
            hcs_results.push(json!({
                "event_type": event.event_type,
                "local_status": event.status,
                "mirror": "not_applicable",
            }));
            continue;
        }
        let seq = event.sequence_number.clone().unwrap_or_default();
        let topic = event
            .topic_id
            .clone()
            .or_else(|| config.topic_id.clone())
            .unwrap_or_default();
        match run_sidecar(
            config,
            &[
                "mirror-topic".into(),
                "--topic-id".into(),
                topic.clone(),
                "--sequence".into(),
                seq.clone(),
            ],
        )
        .await
        {
            Ok(res) => {
                let found = res.get("found").and_then(Value::as_bool).unwrap_or(false);
                let msg_commitment = res
                    .pointer("/message/commitment")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let msg_evidence = res
                    .pointer("/message/evidence_id")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                hcs_results.push(json!({
                    "event_type": event.event_type,
                    "local_status": event.status,
                    "topic_id": topic,
                    "sequence_number": seq,
                    "consensus_timestamp": res.get("consensus_timestamp"),
                    "transaction_id": res.get("transaction_id"),
                    "mirror_found": found,
                    "mirror_evidence_id": msg_evidence,
                    "mirror_commitment": msg_commitment,
                    "commitment_match": found && msg_commitment == commitment && msg_evidence == evidence_id,
                }));
            }
            Err(e) => {
                hcs_results.push(json!({
                    "event_type": event.event_type,
                    "local_status": event.status,
                    "topic_id": topic,
                    "sequence_number": seq,
                    "mirror_found": false,
                    "mirror_error": e.to_string(),
                }));
            }
        }
    }

    // NFT mirror check.
    let mut nft_result = Value::Null;
    if let Some(receipt) = store.hedera_receipt_for(evidence_id)? {
        if receipt.status == "MINTED" {
            if let (Some(serial), Some(token)) =
                (receipt.serial_number.clone(), config.nft_token_id.clone())
            {
                match run_sidecar(
                    config,
                    &[
                        "mirror-nft".into(),
                        "--token-id".into(),
                        token.clone(),
                        "--serial".into(),
                        serial.clone(),
                    ],
                )
                .await
                {
                    Ok(res) => {
                        let found = res.get("found").and_then(Value::as_bool).unwrap_or(false);
                        let meta = res.get("metadata").and_then(Value::as_str).unwrap_or("");
                        nft_result = json!({
                            "token_id": token,
                            "serial_number": serial,
                            "local_status": receipt.status,
                            "mirror_found": found,
                            "mirror_metadata": meta,
                            "commitment_match": found && meta.eq_ignore_ascii_case(&commitment_hex),
                            "consensus_timestamp": res.get("consensus_timestamp"),
                            "transaction_id": res.get("transaction_id"),
                        });
                    }
                    Err(e) => {
                        nft_result = json!({
                            "token_id": token,
                            "serial_number": serial,
                            "local_status": receipt.status,
                            "mirror_found": false,
                            "mirror_error": e.to_string(),
                        });
                    }
                }
            }
        } else {
            nft_result = json!({
                "local_status": receipt.status,
                "last_error": receipt.last_error,
            });
        }
    }

    Ok(json!({
        "evidence_id": evidence_id,
        "commitment": commitment,
        "network": config.network,
        "hcs_events": hcs_results,
        "nft_receipt": nft_result,
    }))
}
