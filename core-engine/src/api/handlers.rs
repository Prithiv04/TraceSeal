use std::sync::Arc;

use axum::{
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

use crate::{
    api::{
        error::ApiError,
        models::{
            EvidenceMetadataResponse, EvidenceSubmissionReceipt, HealthResponse,
            ReverificationResponse, VerificationHistoryResponse,
        },
        AppState,
    },
    engine::{verify_and_package, EvidencePackage},
    evidence::{SCHEMA_VERSION, TLSNOTARY_VERSION, TRUST_POLICY_ID},
    hedera,
    storage::{HederaEventRow, HederaReceiptRow, StoreDisposition},
};

const MAX_ATTESTATION_BYTES: usize = 16 * 1024 * 1024;
const MAX_PRESENTATION_BYTES: usize = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "pass",
        service: "traceseal-api",
        version: env!("CARGO_PKG_VERSION"),
        schema_version: SCHEMA_VERSION,
        tlsnotary_version: TLSNOTARY_VERSION,
        trust_policy_id: TRUST_POLICY_ID,
    })
}

pub async fn submit_evidence(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<EvidenceSubmissionReceipt>), ApiError> {
    let mut attestation: Option<Vec<u8>> = None;
    let mut presentation: Option<Vec<u8>> = None;
    let mut request_manifest: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::Multipart(e.to_string()))?
    {
        let name = field
            .name()
            .ok_or_else(|| ApiError::Multipart("missing field name".into()))?
            .to_string();

        match name.as_str() {
            "attestation" => {
                if attestation.is_some() {
                    return Err(ApiError::Multipart("duplicate 'attestation' field".into()));
                }
                attestation =
                    Some(read_field_bytes(field, MAX_ATTESTATION_BYTES, "attestation").await?);
            }
            "presentation" => {
                if presentation.is_some() {
                    return Err(ApiError::Multipart("duplicate 'presentation' field".into()));
                }
                presentation =
                    Some(read_field_bytes(field, MAX_PRESENTATION_BYTES, "presentation").await?);
            }
            "request_manifest" => {
                if request_manifest.is_some() {
                    return Err(ApiError::Multipart(
                        "duplicate 'request_manifest' field".into(),
                    ));
                }
                request_manifest =
                    Some(read_field_bytes(field, MAX_MANIFEST_BYTES, "request_manifest").await?);
            }
            other => {
                return Err(ApiError::InvalidPackage(format!(
                    "unrecognized multipart field '{other}'"
                )));
            }
        }
    }

    let attestation = attestation
        .ok_or_else(|| ApiError::InvalidPackage("missing 'attestation' field".into()))?;
    let presentation = presentation
        .ok_or_else(|| ApiError::InvalidPackage("missing 'presentation' field".into()))?;
    let request_manifest = request_manifest
        .ok_or_else(|| ApiError::InvalidPackage("missing 'request_manifest' field".into()))?;

    let package = EvidencePackage {
        attestation: &attestation,
        presentation: &presentation,
        request_manifest: &request_manifest,
    };

    let _permit = state
        .verifier_semaphore
        .try_acquire()
        .map_err(|_| ApiError::ConcurrencyLimitReached)?;

    let verified = verify_and_package(package, state.verifier_timeout).await?;
    let receipt = state.store.store(&verified)?;

    // Hedera anchoring runs after local storage succeeds. It is fully
    // idempotent and never blocks or fails the submission response.
    if receipt.disposition == StoreDisposition::Stored {
        let store = state.store.clone();
        let config = state.hedera.clone();
        let evidence_id = receipt.evidence_id.clone();
        tokio::spawn(async move {
            let _ = hedera::anchor_evidence(&store, &config, &evidence_id).await;
        });
    }

    let status = match receipt.disposition {
        StoreDisposition::Stored => StatusCode::CREATED,
        StoreDisposition::AlreadyPresent => StatusCode::OK,
    };

    Ok((status, Json(receipt.into())))
}

pub async fn get_evidence_metadata(
    State(state): State<Arc<AppState>>,
    Path(evidence_id): Path<String>,
) -> Result<Json<EvidenceMetadataResponse>, ApiError> {
    validate_evidence_id(&evidence_id)?;
    let metadata = state.store.get_metadata(&evidence_id)?;
    Ok(Json(metadata.into()))
}

pub async fn get_verification_history(
    State(state): State<Arc<AppState>>,
    Path(evidence_id): Path<String>,
) -> Result<Json<VerificationHistoryResponse>, ApiError> {
    validate_evidence_id(&evidence_id)?;
    let metadata = state.store.get_metadata(&evidence_id)?;
    Ok(Json(metadata.into()))
}

pub async fn get_artifact(
    State(state): State<Arc<AppState>>,
    Path((evidence_id, artifact_type)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    validate_evidence_id(&evidence_id)?;
    let stored = state.store.get(&evidence_id)?;
    let payload = stored.metadata.record.payload();

    let (bytes, content_type, sha256) = match artifact_type.as_str() {
        "attestation" => (
            stored.artifacts.attestation,
            "application/octet-stream",
            &payload.proof.attestation_sha256,
        ),
        "presentation" => (
            stored.artifacts.presentation,
            "application/octet-stream",
            &payload.proof.presentation_sha256,
        ),
        "request_manifest" => (
            stored.artifacts.request_manifest,
            "application/json",
            &payload.proof.request_manifest_sha256,
        ),
        _ => return Err(ApiError::InvalidArtifactType),
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&bytes.len().to_string())
            .map_err(|_| ApiError::Internal("invalid header".into()))?,
    );
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"sha256:{sha256}\""))
            .map_err(|_| ApiError::Internal("invalid header".into()))?,
    );
    headers.insert(
        header::HeaderName::from_static("x-artifact-sha256"),
        HeaderValue::from_str(sha256).map_err(|_| ApiError::Internal("invalid header".into()))?,
    );

    Ok((headers, bytes).into_response())
}

pub async fn reverify_evidence(
    State(state): State<Arc<AppState>>,
    Path(evidence_id): Path<String>,
) -> Result<Json<ReverificationResponse>, ApiError> {
    validate_evidence_id(&evidence_id)?;
    let stored = state.store.get(&evidence_id)?;

    let package = EvidencePackage {
        attestation: &stored.artifacts.attestation,
        presentation: &stored.artifacts.presentation,
        request_manifest: &stored.artifacts.request_manifest,
    };

    let _permit = state
        .verifier_semaphore
        .try_acquire()
        .map_err(|_| ApiError::ConcurrencyLimitReached)?;

    let verified = verify_and_package(package, state.verifier_timeout).await?;
    let report = verified.original_verification().clone();
    state.store.record_reverification(verified)?;

    // Anchor the re-verification event on Hedera (no new NFT is minted).
    {
        let store = state.store.clone();
        let config = state.hedera.clone();
        let eid = evidence_id.clone();
        tokio::spawn(async move {
            let _ = hedera::anchor_reverification(&store, &config, &eid).await;
        });
    }

    Ok(Json(ReverificationResponse {
        evidence_id,
        status: "reverified",
        verification: report,
    }))
}

/* ------------------------- Hedera endpoints ------------------------- */

fn hedera_event_json(e: &HederaEventRow) -> serde_json::Value {
    serde_json::json!({
        "event_id": e.event_id,
        "event_type": e.event_type,
        "dedupe_key": e.dedupe_key,
        "status": e.status,
        "topic_id": e.topic_id,
        "sequence_number": e.sequence_number,
        "consensus_timestamp": e.consensus_timestamp,
        "transaction_id": e.transaction_id,
        "attempts": e.attempts,
        "last_error": e.last_error,
        "created_at": e.created_at,
        "updated_at": e.updated_at,
        "payload": serde_json::from_str::<serde_json::Value>(&e.payload_json).ok(),
    })
}

fn hedera_receipt_json(r: &HederaReceiptRow) -> serde_json::Value {
    serde_json::json!({
        "evidence_id": r.evidence_id,
        "commitment": r.commitment,
        "commitment_hex": r.commitment_hex,
        "token_id": r.token_id,
        "serial_number": r.serial_number,
        "mint_transaction_id": r.mint_transaction_id,
        "mint_consensus_timestamp": r.mint_consensus_timestamp,
        "status": r.status,
        "last_error": r.last_error,
        "created_at": r.created_at,
        "updated_at": r.updated_at,
    })
}

/// GET /api/v1/hedera/status — configuration + live account status.
/// Never exposes private key material.
pub async fn hedera_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let config = &state.hedera;
    let missing = config.missing();
    let mut body = serde_json::json!({
        "configured": config.is_fully_configured(),
        "credentials_present": config.credentials_present(),
        "network": config.network,
        "mirror_node_url": config.mirror_node_url,
        "account_id": config.account_id,
        "topic_id": config.topic_id,
        "nft_token_id": config.nft_token_id,
        "nft_name": "TraceSeal Verified Evidence",
        "nft_symbol": "TSVR",
        "missing": missing,
        "sidecar_available": hedera::sidecar_exists(config),
        "hashscan_base": hedera::hashscan_base(&config.network),
    });
    // Live balance check via sidecar (best-effort).
    if config.credentials_present() {
        match hedera::run_sidecar(config, &["status".to_string()]).await {
            Ok(res) => {
                body["balance_tinybars"] = res.get("balance_tinybars").cloned().unwrap_or(serde_json::Value::Null);
                body["account_error"] = res.get("account_error").cloned().unwrap_or(serde_json::Value::Null);
            }
            Err(e) => {
                body["account_error"] = serde_json::Value::String(e.to_string());
            }
        }
    }
    Ok(Json(body))
}

/// GET /api/v1/evidence/{id}/blockchain — local Hedera records + optional
/// mirror verification (?verify=1 triggers live Mirror Node checks).
pub async fn evidence_blockchain(
    State(state): State<Arc<AppState>>,
    Path(evidence_id): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    validate_evidence_id(&evidence_id)?;
    // Ensure the evidence exists.
    state.store.get_metadata(&evidence_id)?;

    let events: Vec<_> = state
        .store
        .hedera_events_for(&evidence_id)?
        .iter()
        .map(hedera_event_json)
        .collect();
    let receipt = state
        .store
        .hedera_receipt_for(&evidence_id)?
        .map(|r| hedera_receipt_json(&r));

    let mut body = serde_json::json!({
        "evidence_id": evidence_id,
        "network": state.hedera.network,
        "topic_id": state.hedera.topic_id,
        "nft_token_id": state.hedera.nft_token_id,
        "hashscan_base": hedera::hashscan_base(&state.hedera.network),
        "configured": state.hedera.is_fully_configured(),
        "audit_events": events,
        "nft_receipt": receipt,
    });

    if params.get("verify").map(|v| v == "1" || v == "true").unwrap_or(false) {
        match hedera::mirror_verify_evidence(&state.store, &state.hedera, &evidence_id).await {
            Ok(report) => body["mirror_verification"] = report,
            Err(e) => {
                body["mirror_verification"] = serde_json::json!({
                    "error": e.to_string(),
                });
            }
        }
    }
    Ok(Json(body))
}

/// POST /api/v1/evidence/{id}/anchor — enqueue (if needed) and drain the
/// Hedera outbox for this evidence. Idempotent; safe to call repeatedly.
pub async fn anchor_evidence_now(
    State(state): State<Arc<AppState>>,
    Path(evidence_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    validate_evidence_id(&evidence_id)?;
    state.store.get_metadata(&evidence_id)?;
    let report = hedera::anchor_evidence(&state.store, &state.hedera, &evidence_id)
        .await
        .map_err(|e| ApiError::Internal(format!("hedera anchoring failed: {e}")))?;
    Ok(Json(serde_json::json!({
        "evidence_id": evidence_id,
        "published": report.published,
        "minted": report.minted,
        "failed": report.failed,
        "skipped_unconfigured": report.skipped_unconfigured,
    })))
}

async fn read_field_bytes(
    mut field: axum::extract::multipart::Field<'_>,
    limit: usize,
    field_name: &str,
) -> Result<Vec<u8>, ApiError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|e| ApiError::Multipart(e.to_string()))?
    {
        if bytes.len() + chunk.len() > limit {
            return Err(ApiError::PayloadTooLarge(format!(
                "field '{field_name}' exceeds limit of {limit} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Err(ApiError::InvalidPackage(format!(
            "field '{field_name}' cannot be empty"
        )));
    }
    Ok(bytes)
}

fn validate_evidence_id(id: &str) -> Result<(), ApiError> {
    if id.len() == 68
        && id.starts_with("ts1_")
        && id[4..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(ApiError::InvalidEvidenceId)
    }
}
