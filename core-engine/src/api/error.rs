// src/api/error.rs
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::{engine::VerificationError, evidence::EvidenceError, storage::StorageError};

#[derive(Debug)]
pub enum ApiError {
    InvalidPackage(String),
    InvalidEvidenceId,
    InvalidArtifactType,
    PayloadTooLarge(String),
    Multipart(String),
    NotFound,
    Conflict,
    VerificationRejected,
    InvalidVerifierOutput,
    VerifierTimeout,
    ConcurrencyLimitReached,
    Internal(String),
    /// Storage subsystem is unavailable (e.g., DB cannot be opened).
    StorageUnavailable,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::InvalidPackage(msg) => (
                StatusCode::BAD_REQUEST,
                "INVALID_PACKAGE",
                format!("The evidence package is invalid: {msg}"),
            ),
            Self::InvalidEvidenceId => (
                StatusCode::BAD_REQUEST,
                "INVALID_EVIDENCE_ID",
                "The evidence ID must be a 68-character lowercase hexadecimal string starting with ts1_".into(),
            ),
            Self::InvalidArtifactType => (
                StatusCode::BAD_REQUEST,
                "INVALID_ARTIFACT_TYPE",
                "The artifact type must be 'attestation', 'presentation', or 'request_manifest'".into(),
            ),
            Self::PayloadTooLarge(msg) => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "PAYLOAD_TOO_LARGE",
                format!("Upload exceeds maximum allowed size: {msg}"),
            ),
            Self::Multipart(msg) => (
                StatusCode::BAD_REQUEST,
                "MALFORMED_MULTIPART",
                format!("Multipart request error: {msg}"),
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "EVIDENCE_NOT_FOUND",
                "The requested evidence was not found".into(),
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "EVIDENCE_CONFLICT",
                "The evidence already exists with conflicting data or verification report".into(),
            ),
            Self::VerificationRejected => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "VERIFICATION_REJECTED",
                "The TLSNotary verifier rejected the cryptographic proof".into(),
            ),
            Self::InvalidVerifierOutput => (
                StatusCode::BAD_GATEWAY,
                "INVALID_VERIFIER_OUTPUT",
                "The verifier returned invalid or incomplete output".into(),
            ),
            Self::VerifierTimeout => (
                StatusCode::GATEWAY_TIMEOUT,
                "VERIFIER_TIMEOUT",
                "The verifier process timed out while validating the proof".into(),
            ),
            Self::ConcurrencyLimitReached => (
                StatusCode::SERVICE_UNAVAILABLE,
                "CONCURRENCY_LIMIT_REACHED",
                "The server has reached maximum concurrent verification capacity; try again shortly".into(),
            ),
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "An internal storage or execution error occurred".into(),
            ),
            Self::StorageUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "STORAGE_UNAVAILABLE",
                "Evidence storage is unavailable".into(),
            ),
        };

        let body = Json(ErrorEnvelope {
            error: ErrorDetail { code, message },
        });

        (status, body).into_response()
    }
}

impl From<VerificationError> for ApiError {
    fn from(err: VerificationError) -> Self {
        match err {
            VerificationError::InvalidPackage(msg) => Self::InvalidPackage(msg.to_string()),
            VerificationError::Timeout => Self::VerifierTimeout,
            VerificationError::Process => {
                Self::Internal("Verifier process execution failed".into())
            }
            VerificationError::Rejected => Self::VerificationRejected,
            VerificationError::InvalidVerifierOutput => Self::InvalidVerifierOutput,
            VerificationError::Identity(e) => Self::InvalidPackage(e.to_string()),
        }
    }
}

impl From<EvidenceError> for ApiError {
    fn from(err: EvidenceError) -> Self {
        Self::InvalidPackage(err.to_string())
    }
}

impl From<StorageError> for ApiError {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::InvalidEvidenceId => Self::InvalidEvidenceId,
            StorageError::NotFound => Self::NotFound,
            StorageError::Conflict => Self::Conflict,
            StorageError::Corrupt => {
                Self::Internal("Evidence integrity corruption detected".into())
            }
            StorageError::UnsafePath => Self::Internal("Storage path safety violation".into()),
            StorageError::UnsupportedSchemaVersion => {
                Self::Internal("Unsupported database schema".into())
            }
            StorageError::Io(_) => Self::Internal("Storage I/O failure".into()),
            StorageError::Database(_) => Self::StorageUnavailable,
        }
    }
}
