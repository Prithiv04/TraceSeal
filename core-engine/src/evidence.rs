use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SCHEMA_VERSION: &str = "1.0";
pub const PROOF_FORMAT: &str = "tlsnotary-presentation-bincode1-v0.1.0-alpha.15";
pub const TLSNOTARY_VERSION: &str = "0.1.0-alpha.15";
pub const TRUST_POLICY_ID: &str = "demo-local-v1";
pub const ALLOWED_DISCLOSURE_FIELDS: &[&str] = &["status", "error", "service", "message"];
const COMMITMENT_DOMAIN: &[u8] = b"TRACESEAL:EVIDENCE:V1\0";
const MAX_DISCLOSED_STRING_BYTES: usize = 4096;
const MAX_VERIFIER_VERSION_BYTES: usize = 128;
const ALLOWED_PATHS: &[&str] = &[
    "/trace-seal-503",
    "/trace-seal-200",
    "/trace-seal-404",
    "/trace-seal-delay",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    commitment: String,
    evidence_id: String,
    payload: EvidencePayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePayload {
    pub disclosed_fields: BTreeMap<String, DisclosedValue>,
    pub disclosed_http_status: u16,
    pub proof: ProofInfo,
    pub schema_version: String,
    pub trust_policy_id: String,
    pub verification: VerificationInfo,
    pub verified_request: VerifiedRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DisclosedValue {
    Integer(i64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofInfo {
    pub attestation_sha256: String,
    pub format: String,
    pub presentation_sha256: String,
    pub request_manifest_sha256: String,
    pub tlsnotary_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationInfo {
    pub result: String,
    pub verifier_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedRequest {
    pub host: String,
    pub method: String,
    pub path: String,
    pub scheme: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactHashes {
    pub attestation_sha256: String,
    pub presentation_sha256: String,
    pub request_manifest_sha256: String,
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("invalid evidence schema: {0}")]
    Invalid(String),
    #[error("artifact hash does not match the evidence payload: {0}")]
    ArtifactHashMismatch(&'static str),
    #[error("canonical JSON serialization failed: {0}")]
    Canonicalization(#[from] serde_json::Error),
}

impl ArtifactHashes {
    pub fn from_bytes(attestation: &[u8], presentation: &[u8], request_manifest: &[u8]) -> Self {
        Self {
            attestation_sha256: sha256_hex(attestation),
            presentation_sha256: sha256_hex(presentation),
            request_manifest_sha256: sha256_hex(request_manifest),
        }
    }
}

impl EvidencePayload {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(EvidenceError::Invalid(format!(
                "unsupported schema version: {}",
                self.schema_version
            )));
        }
        if self.proof.format != PROOF_FORMAT {
            return Err(EvidenceError::Invalid(format!(
                "unsupported proof format: {}",
                self.proof.format
            )));
        }
        if self.proof.tlsnotary_version != TLSNOTARY_VERSION {
            return Err(EvidenceError::Invalid(format!(
                "unsupported TLSNotary version: {}",
                self.proof.tlsnotary_version
            )));
        }
        if self.trust_policy_id != TRUST_POLICY_ID {
            return Err(EvidenceError::Invalid(format!(
                "unsupported trust policy: {}",
                self.trust_policy_id
            )));
        }
        if self.verification.result != "VERIFIED" {
            return Err(EvidenceError::Invalid(
                "verification result must be VERIFIED".into(),
            ));
        }
        if self.verification.verifier_version.is_empty()
            || self.verification.verifier_version.len() > MAX_VERIFIER_VERSION_BYTES
        {
            return Err(EvidenceError::Invalid(
                "verifier version must be 1 to 128 UTF-8 bytes".into(),
            ));
        }
        validate_sha256(&self.proof.attestation_sha256, "attestation_sha256")?;
        validate_sha256(&self.proof.presentation_sha256, "presentation_sha256")?;
        validate_sha256(
            &self.proof.request_manifest_sha256,
            "request_manifest_sha256",
        )?;

        if !(100..=599).contains(&self.disclosed_http_status) {
            return Err(EvidenceError::Invalid(
                "disclosed HTTP status must be between 100 and 599".into(),
            ));
        }
        if self.verified_request.scheme != "https"
            || self.verified_request.host != "localhost"
            || self.verified_request.method != "GET"
            || !ALLOWED_PATHS.contains(&self.verified_request.path.as_str())
        {
            return Err(EvidenceError::Invalid(
                "request must be an allowed HTTPS GET to localhost".into(),
            ));
        }

        for (name, value) in &self.disclosed_fields {
            match (name.as_str(), value) {
                ("status", DisclosedValue::Integer(status))
                    if (100..=599).contains(status)
                        && *status == i64::from(self.disclosed_http_status) => {}
                ("status", _) => {
                    return Err(EvidenceError::Invalid(
                        "disclosed status must be an integer matching the HTTP status".into(),
                    ));
                }
                ("error" | "service" | "message", DisclosedValue::String(value))
                    if value.len() <= MAX_DISCLOSED_STRING_BYTES => {}
                ("error" | "service" | "message", _) => {
                    return Err(EvidenceError::Invalid(format!(
                        "disclosure {name} must be a string of at most {MAX_DISCLOSED_STRING_BYTES} UTF-8 bytes"
                    )));
                }
                _ => {
                    return Err(EvidenceError::Invalid(format!(
                        "unsupported disclosure field: {name}"
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EvidenceError> {
        self.validate()?;
        Ok(serde_json_canonicalizer::to_vec(self)?)
    }
}

impl EvidenceRecord {
    pub fn commitment(&self) -> &str {
        &self.commitment
    }

    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    pub fn payload(&self) -> &EvidencePayload {
        &self.payload
    }

    /// Builds an identity from verifier-derived metadata and checks exact artifact bytes.
    ///
    /// This does not perform TLSNotary verification; callers must verify the proof first.
    pub(crate) fn from_verified_payload(
        payload: EvidencePayload,
        attestation: &[u8],
        presentation: &[u8],
        request_manifest: &[u8],
    ) -> Result<Self, EvidenceError> {
        payload.validate()?;
        let actual = ArtifactHashes::from_bytes(attestation, presentation, request_manifest);
        if payload.proof.attestation_sha256 != actual.attestation_sha256 {
            return Err(EvidenceError::ArtifactHashMismatch("attestation.tlsn"));
        }
        if payload.proof.presentation_sha256 != actual.presentation_sha256 {
            return Err(EvidenceError::ArtifactHashMismatch("presentation.tlsn"));
        }
        if payload.proof.request_manifest_sha256 != actual.request_manifest_sha256 {
            return Err(EvidenceError::ArtifactHashMismatch("request.json"));
        }

        let (commitment, evidence_id) = derive_identity(&payload)?;
        Ok(Self {
            commitment,
            evidence_id,
            payload,
        })
    }

    pub fn validate(&self) -> Result<(), EvidenceError> {
        self.payload.validate()?;
        let (commitment, evidence_id) = derive_identity(&self.payload)?;
        if self.commitment != commitment || self.evidence_id != evidence_id {
            return Err(EvidenceError::Invalid(
                "evidence ID or commitment does not match the canonical payload".into(),
            ));
        }
        Ok(())
    }
}

fn derive_identity(payload: &EvidencePayload) -> Result<(String, String), EvidenceError> {
    let canonical_payload = payload.canonical_bytes()?;
    let mut hasher = Sha256::new();
    hasher.update(COMMITMENT_DOMAIN);
    hasher.update(canonical_payload);
    let commitment_hash = hex::encode(hasher.finalize());
    Ok((
        format!("sha256:{commitment_hash}"),
        format!("ts1_{commitment_hash}"),
    ))
}

fn validate_sha256(value: &str, field: &str) -> Result<(), EvidenceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EvidenceError::Invalid(format!(
            "{field} must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTESTATION: &[u8] = b"ATTESTATION\n";
    const PRESENTATION: &[u8] = b"PRESENTATION\n";
    const REQUEST_MANIFEST: &[u8] = b"{\"schema_version\":\"1.0\",\"url\":\"https://localhost:4443/trace-seal-503\",\"method\":\"GET\",\"disclosures\":[\"status\",\"service\"],\"created_at\":\"2026-11-06T01:57:09.831Z\"}\n";
    const CANONICAL_PAYLOAD: &str = "{\"disclosed_fields\":{\"service\":\"TRACESEAL Demo API\",\"status\":503},\"disclosed_http_status\":503,\"proof\":{\"attestation_sha256\":\"1f60b605fbdeefd4be08f82582e89a8a24b4fb2369e6e7a3989f4db53f8deeef\",\"format\":\"tlsnotary-presentation-bincode1-v0.1.0-alpha.15\",\"presentation_sha256\":\"d5ed2447205de0a7fa8dde1a1a830064b3b2541e6b8548c9bd659874bbd22119\",\"request_manifest_sha256\":\"f19494a7d7dfca78e60514dbeba7e5de96b0c3619b94ff7dba47351c8120ac73\",\"tlsnotary_version\":\"0.1.0-alpha.15\"},\"schema_version\":\"1.0\",\"trust_policy_id\":\"demo-local-v1\",\"verification\":{\"result\":\"VERIFIED\",\"verifier_version\":\"traceseal-core 0.1.0; tlsn v0.1.0-alpha.15\"},\"verified_request\":{\"host\":\"localhost\",\"method\":\"GET\",\"path\":\"/trace-seal-503\",\"scheme\":\"https\"}}";
    const COMMITMENT: &str =
        "sha256:965fd6eccfc9409717700f512b3c095b791d955c113745c14287f0e4121b5f59";
    const EVIDENCE_ID: &str =
        "ts1_965fd6eccfc9409717700f512b3c095b791d955c113745c14287f0e4121b5f59";

    fn sample_payload() -> EvidencePayload {
        let hashes = ArtifactHashes::from_bytes(ATTESTATION, PRESENTATION, REQUEST_MANIFEST);
        EvidencePayload {
            disclosed_fields: BTreeMap::from([
                (
                    "service".into(),
                    DisclosedValue::String("TRACESEAL Demo API".into()),
                ),
                ("status".into(), DisclosedValue::Integer(503)),
            ]),
            disclosed_http_status: 503,
            proof: ProofInfo {
                attestation_sha256: hashes.attestation_sha256,
                format: PROOF_FORMAT.into(),
                presentation_sha256: hashes.presentation_sha256,
                request_manifest_sha256: hashes.request_manifest_sha256,
                tlsnotary_version: TLSNOTARY_VERSION.into(),
            },
            schema_version: SCHEMA_VERSION.into(),
            trust_policy_id: TRUST_POLICY_ID.into(),
            verification: VerificationInfo {
                result: "VERIFIED".into(),
                verifier_version: "traceseal-core 0.1.0; tlsn v0.1.0-alpha.15".into(),
            },
            verified_request: VerifiedRequest {
                host: "localhost".into(),
                method: "GET".into(),
                path: "/trace-seal-503".into(),
                scheme: "https".into(),
            },
        }
    }

    fn sample_record() -> EvidenceRecord {
        EvidenceRecord::from_verified_payload(
            sample_payload(),
            ATTESTATION,
            PRESENTATION,
            REQUEST_MANIFEST,
        )
        .unwrap()
    }

    #[test]
    fn fixed_artifact_hashes_match_step_b2_vectors() {
        let hashes = ArtifactHashes::from_bytes(ATTESTATION, PRESENTATION, REQUEST_MANIFEST);
        assert_eq!(
            hashes.attestation_sha256,
            "1f60b605fbdeefd4be08f82582e89a8a24b4fb2369e6e7a3989f4db53f8deeef"
        );
        assert_eq!(
            hashes.presentation_sha256,
            "d5ed2447205de0a7fa8dde1a1a830064b3b2541e6b8548c9bd659874bbd22119"
        );
        assert_eq!(
            hashes.request_manifest_sha256,
            "f19494a7d7dfca78e60514dbeba7e5de96b0c3619b94ff7dba47351c8120ac73"
        );
    }

    #[test]
    fn canonical_payload_commitment_and_id_match_fixed_vector() {
        let record = sample_record();
        assert_eq!(
            record.payload.canonical_bytes().unwrap(),
            CANONICAL_PAYLOAD.as_bytes()
        );
        assert_eq!(record.commitment, COMMITMENT);
        assert_eq!(record.evidence_id, EVIDENCE_ID);
    }

    #[test]
    fn ids_are_deterministic() {
        let first = sample_record();
        let second = sample_record();
        assert_eq!(first, second);
    }

    #[test]
    fn empty_disclosures_are_valid() {
        let mut payload = sample_payload();
        payload.disclosed_fields.clear();
        assert!(payload.validate().is_ok());
    }

    #[test]
    fn rejects_unknown_schema_fields() {
        let json = r#"{"commitment":"x","evidence_id":"x","payload":{},"unexpected":true}"#;
        assert!(serde_json::from_str::<EvidenceRecord>(json).is_err());

        let mut payload = serde_json::to_value(sample_payload()).unwrap();
        payload["proof"]["extra"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<EvidencePayload>(payload).is_err());
    }

    #[test]
    fn rejects_invalid_schema_constants_and_hashes() {
        let mut payload = sample_payload();
        payload.proof.format = "client-controlled-format".into();
        assert!(payload.validate().is_err());

        let mut payload = sample_payload();
        payload.proof.attestation_sha256.make_ascii_uppercase();
        assert!(payload.validate().is_err());

        let mut payload = sample_payload();
        payload.trust_policy_id = "client-controlled-policy".into();
        assert!(payload.validate().is_err());
    }

    #[test]
    fn rejects_invalid_routes_and_statuses() {
        let mut payload = sample_payload();
        payload.verified_request.path = "/outside".into();
        assert!(payload.validate().is_err());

        let mut payload = sample_payload();
        payload.disclosed_http_status = 99;
        assert!(payload.validate().is_err());
    }

    #[test]
    fn rejects_invalid_disclosure_names_types_and_values() {
        let mut payload = sample_payload();
        payload
            .disclosed_fields
            .insert("unknown".into(), DisclosedValue::String("value".into()));
        assert!(payload.validate().is_err());

        let mut payload = sample_payload();
        payload
            .disclosed_fields
            .insert("status".into(), DisclosedValue::Integer(200));
        assert!(payload.validate().is_err());

        let mut payload = sample_payload();
        payload.disclosed_fields.insert(
            "message".into(),
            DisclosedValue::String("x".repeat(MAX_DISCLOSED_STRING_BYTES + 1)),
        );
        assert!(payload.validate().is_err());
    }

    #[test]
    fn rejects_modified_artifacts_and_manifest_bytes() {
        let payload = sample_payload();
        assert!(matches!(
            EvidenceRecord::from_verified_payload(
                payload.clone(),
                b"modified attestation",
                PRESENTATION,
                REQUEST_MANIFEST
            ),
            Err(EvidenceError::ArtifactHashMismatch("attestation.tlsn"))
        ));
        assert!(matches!(
            EvidenceRecord::from_verified_payload(
                payload.clone(),
                ATTESTATION,
                b"modified presentation",
                REQUEST_MANIFEST
            ),
            Err(EvidenceError::ArtifactHashMismatch("presentation.tlsn"))
        ));
        assert!(matches!(
            EvidenceRecord::from_verified_payload(
                payload,
                ATTESTATION,
                PRESENTATION,
                b"{\"modified\":true}\n"
            ),
            Err(EvidenceError::ArtifactHashMismatch("request.json"))
        ));
    }

    #[test]
    fn rejects_invalid_disclosure_json_types() {
        let mut payload = serde_json::to_value(sample_payload()).unwrap();
        payload["disclosed_fields"]["message"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<EvidencePayload>(payload).is_err());
    }

    #[test]
    fn rejects_a_tampered_record_commitment() {
        let mut record = sample_record();
        record.commitment =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into();
        assert!(record.validate().is_err());
    }

    #[test]
    fn complete_record_round_trips() {
        let record = sample_record();
        let json = serde_json::to_vec(&record).unwrap();
        let decoded: EvidenceRecord = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded, record);
    }
}
