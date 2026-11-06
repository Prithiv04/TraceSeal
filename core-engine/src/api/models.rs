use serde::{Deserialize, Serialize};

use crate::{
    evidence::EvidenceRecord,
    storage::{StorageReceipt, StoreDisposition, StoredMetadata},
    EvidenceReport,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
    pub schema_version: &'static str,
    pub tlsnotary_version: &'static str,
    pub trust_policy_id: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSubmissionReceipt {
    pub evidence_id: String,
    pub commitment: String,
    pub stored_at: String,
    pub disposition: String,
}

impl From<StorageReceipt> for EvidenceSubmissionReceipt {
    fn from(receipt: StorageReceipt) -> Self {
        Self {
            evidence_id: receipt.evidence_id,
            commitment: receipt.commitment,
            stored_at: receipt.stored_at,
            disposition: match receipt.disposition {
                StoreDisposition::Stored => "stored".to_string(),
                StoreDisposition::AlreadyPresent => "already_present".to_string(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceMetadataResponse {
    pub evidence_id: String,
    pub commitment: String,
    pub stored_at: String,
    pub record: EvidenceRecord,
    pub original_verification: EvidenceReport,
    pub reverifications_count: usize,
}

impl From<StoredMetadata> for EvidenceMetadataResponse {
    fn from(meta: StoredMetadata) -> Self {
        Self {
            evidence_id: meta.record.evidence_id().to_owned(),
            commitment: meta.record.commitment().to_owned(),
            stored_at: meta.stored_at,
            reverifications_count: meta.reverifications.len(),
            original_verification: meta.original_verification,
            record: meta.record,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationHistoryResponse {
    pub evidence_id: String,
    pub original_verification: EvidenceReport,
    pub reverifications: Vec<EvidenceReport>,
}

impl From<StoredMetadata> for VerificationHistoryResponse {
    fn from(meta: StoredMetadata) -> Self {
        Self {
            evidence_id: meta.record.evidence_id().to_owned(),
            original_verification: meta.original_verification,
            reverifications: meta.reverifications,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverificationResponse {
    pub evidence_id: String,
    pub status: &'static str,
    pub verification: EvidenceReport,
}

