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
    storage::StoreDisposition,
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

    Ok(Json(ReverificationResponse {
        evidence_id,
        status: "reverified",
        verification: report,
    }))
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
