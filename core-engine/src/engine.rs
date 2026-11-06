use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::Path,
    time::Duration,
};

use chrono::DateTime;
use serde::Deserialize;
use tempfile::TempDir;
use thiserror::Error;

use crate::{
    evidence::{
        ArtifactHashes, DisclosedValue, EvidenceError, EvidencePayload, EvidenceRecord, ProofInfo,
        VerificationInfo, VerifiedRequest, ALLOWED_DISCLOSURE_FIELDS, PROOF_FORMAT, SCHEMA_VERSION,
        TLSNOTARY_VERSION, TRUST_POLICY_ID,
    },
    run_verifier, EvidenceReport,
};

const MAX_ATTESTATION_BYTES: usize = 16 * 1024 * 1024;
const MAX_PRESENTATION_BYTES: usize = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_VERIFIER_STDOUT_BYTES: usize = 64 * 1024;
const MAX_VERIFIER_STDERR_BYTES: usize = 64 * 1024;
const MAX_VERIFICATION_SECONDS: u64 = 120;
const MANIFEST_SCHEMA_VERSION: &str = "1.0";
const ALLOWED_PATHS: &[&str] = &[
    "/trace-seal-503",
    "/trace-seal-200",
    "/trace-seal-404",
    "/trace-seal-delay",
];

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("invalid evidence package: {0}")]
    InvalidPackage(&'static str),
    #[error("TLSNotary verifier timed out")]
    Timeout,
    #[error("TLSNotary verifier could not be run")]
    Process,
    #[error("TLSNotary verifier rejected the evidence")]
    Rejected,
    #[error("TLSNotary verifier returned incomplete or malformed output")]
    InvalidVerifierOutput,
    #[error("evidence identity construction failed: {0}")]
    Identity(#[from] EvidenceError),
}

#[derive(Clone, Copy)]
pub struct EvidencePackage<'a> {
    pub attestation: &'a [u8],
    pub presentation: &'a [u8],
    pub request_manifest: &'a [u8],
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestManifest {
    schema_version: String,
    url: String,
    method: String,
    disclosures: Vec<String>,
    created_at: String,
}

pub async fn verify_and_identify(
    package: EvidencePackage<'_>,
    timeout: Duration,
) -> Result<EvidenceRecord, VerificationError> {
    validate_sizes(&package)?;
    if timeout.is_zero() || timeout > Duration::from_secs(MAX_VERIFICATION_SECONDS) {
        return Err(VerificationError::InvalidPackage(
            "verification timeout is outside the permitted range",
        ));
    }

    let manifest = parse_manifest(package.request_manifest)?;
    let workspace = stage_package(package)?;
    let executable = verifier_executable()?;
    let output = match run_verifier(
        &executable,
        &workspace.path().join("attestation.tlsn"),
        &workspace.path().join("presentation.tlsn"),
        timeout,
    )
    .await
    {
        Ok(output) => output,
        Err(error) if error.contains("timed out") => return Err(VerificationError::Timeout),
        Err(_) => return Err(VerificationError::Process),
    };

    if output.stdout.len() > MAX_VERIFIER_STDOUT_BYTES
        || output.stderr.len() > MAX_VERIFIER_STDERR_BYTES
    {
        return Err(VerificationError::InvalidVerifierOutput);
    }
    if !output.status.success() {
        return Err(VerificationError::Rejected);
    }

    let report = parse_verifier_report(&output.stdout)?;
    build_identity(package, &manifest, report)
}

fn verifier_executable() -> Result<std::path::PathBuf, VerificationError> {
    let current = std::env::current_exe().map_err(|_| VerificationError::Process)?;
    if current.file_stem().and_then(|name| name.to_str()) == Some("traceseal-core") {
        return Ok(current);
    }

    // Cargo integration-test binaries live in `target/<profile>/deps`; use only the
    // sibling application binary produced by the same build, never a caller path.
    let deps = current.parent().ok_or(VerificationError::Process)?;
    if deps.file_name().and_then(|name| name.to_str()) != Some("deps") {
        return Err(VerificationError::Process);
    }
    let profile = deps.parent().ok_or(VerificationError::Process)?;
    let mut candidate = profile.join("traceseal-core");
    if !std::env::consts::EXE_EXTENSION.is_empty() {
        candidate.set_extension(std::env::consts::EXE_EXTENSION);
    }
    if !candidate.is_file() {
        return Err(VerificationError::Process);
    }
    Ok(candidate)
}

fn validate_sizes(package: &EvidencePackage<'_>) -> Result<(), VerificationError> {
    if package.attestation.is_empty() || package.presentation.is_empty() {
        return Err(VerificationError::InvalidPackage(
            "attestation and presentation are required",
        ));
    }
    if package.attestation.len() > MAX_ATTESTATION_BYTES
        || package.presentation.len() > MAX_PRESENTATION_BYTES
        || package.request_manifest.is_empty()
        || package.request_manifest.len() > MAX_MANIFEST_BYTES
    {
        return Err(VerificationError::InvalidPackage(
            "artifact is empty or exceeds its size limit",
        ));
    }
    Ok(())
}

fn parse_manifest(bytes: &[u8]) -> Result<RequestManifest, VerificationError> {
    let manifest: RequestManifest = serde_json::from_slice(bytes)
        .map_err(|_| VerificationError::InvalidPackage("request manifest is malformed"))?;
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION
        || manifest.method != "GET"
        || DateTime::parse_from_rfc3339(&manifest.created_at).is_err()
    {
        return Err(VerificationError::InvalidPackage(
            "request manifest fields are invalid",
        ));
    }
    let mut disclosures = BTreeSet::new();
    for field in &manifest.disclosures {
        if !ALLOWED_DISCLOSURE_FIELDS.contains(&field.as_str())
            || !disclosures.insert(field.as_str())
        {
            return Err(VerificationError::InvalidPackage(
                "request manifest disclosures are invalid",
            ));
        }
    }
    let url = url::Url::parse(&manifest.url)
        .map_err(|_| VerificationError::InvalidPackage("request manifest URL is invalid"))?;
    if url.scheme() != "https"
        || url.host_str() != Some("localhost")
        || url.port_or_known_default() != Some(4443)
        || !ALLOWED_PATHS.contains(&url.path())
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(VerificationError::InvalidPackage(
            "request manifest URL is unsupported",
        ));
    }
    Ok(manifest)
}

fn stage_package(package: EvidencePackage<'_>) -> Result<TempDir, VerificationError> {
    let workspace = tempfile::Builder::new()
        .prefix("traceseal-verify-")
        .tempdir()
        .map_err(|_| VerificationError::Process)?;
    write_fixed_file(
        &workspace.path().join("attestation.tlsn"),
        package.attestation,
    )?;
    write_fixed_file(
        &workspace.path().join("presentation.tlsn"),
        package.presentation,
    )?;
    write_fixed_file(
        &workspace.path().join("request.json"),
        package.request_manifest,
    )?;
    Ok(workspace)
}

fn write_fixed_file(path: &Path, bytes: &[u8]) -> Result<(), VerificationError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| VerificationError::Process)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| VerificationError::Process)
}

fn parse_verifier_report(bytes: &[u8]) -> Result<EvidenceReport, VerificationError> {
    let report: EvidenceReport =
        serde_json::from_slice(bytes).map_err(|_| VerificationError::InvalidVerifierOutput)?;
    if report.verification_status != "VERIFIED" {
        return Err(VerificationError::Rejected);
    }
    if report.verifier.exit_code != Some(0) || !report.errors.is_empty() {
        return Err(VerificationError::InvalidVerifierOutput);
    }
    if report.schema_version != "1.0" {
        return Err(VerificationError::InvalidVerifierOutput);
    }
    Ok(report)
}

fn build_identity(
    package: EvidencePackage<'_>,
    manifest: &RequestManifest,
    report: EvidenceReport,
) -> Result<EvidenceRecord, VerificationError> {
    let request = report
        .verified_request
        .ok_or(VerificationError::InvalidVerifierOutput)?;
    if report.proof_format.as_deref() != Some(PROOF_FORMAT)
        || report.tlsnotary_version.as_deref() != Some(TLSNOTARY_VERSION)
        || report.trust_policy_id.as_deref() != Some(TRUST_POLICY_ID)
        || report.verifier.version != expected_verifier_version()
        || report.http_status.is_none()
        || report.attestation.sha256.is_none()
        || report.presentation.sha256.is_none()
    {
        return Err(VerificationError::InvalidVerifierOutput);
    }

    let url = url::Url::parse(&manifest.url)
        .map_err(|_| VerificationError::InvalidPackage("request manifest URL is invalid"))?;
    if request.scheme != url.scheme()
        || request.host != url.host_str().unwrap_or_default()
        || request.method != manifest.method
        || request.path != url.path()
    {
        return Err(VerificationError::Rejected);
    }

    let status = report
        .http_status
        .ok_or(VerificationError::InvalidVerifierOutput)?;
    let mut disclosed_fields = BTreeMap::new();
    for (name, value) in report.disclosed_evidence {
        let value = match (name.as_str(), value) {
            ("status", serde_json::Value::Number(number)) => number
                .as_i64()
                .map(DisclosedValue::Integer)
                .ok_or(VerificationError::InvalidVerifierOutput)?,
            ("error" | "service" | "message", serde_json::Value::String(value)) => {
                DisclosedValue::String(value)
            }
            _ => return Err(VerificationError::InvalidVerifierOutput),
        };
        disclosed_fields.insert(name, value);
    }
    let manifest_disclosures = manifest
        .disclosures
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if manifest_disclosures != disclosed_fields.keys().cloned().collect() {
        return Err(VerificationError::Rejected);
    }

    let hashes = ArtifactHashes::from_bytes(
        package.attestation,
        package.presentation,
        package.request_manifest,
    );
    if report.attestation.sha256.as_deref() != Some(hashes.attestation_sha256.as_str())
        || report.presentation.sha256.as_deref() != Some(hashes.presentation_sha256.as_str())
    {
        return Err(VerificationError::InvalidVerifierOutput);
    }

    let payload = EvidencePayload {
        disclosed_fields,
        disclosed_http_status: status,
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
            verifier_version: report.verifier.version,
        },
        verified_request: VerifiedRequest {
            scheme: request.scheme,
            host: request.host,
            method: request.method,
            path: request.path,
        },
    };
    Ok(EvidenceRecord::from_verified_payload(
        payload,
        package.attestation,
        package.presentation,
        package.request_manifest,
    )?)
}

fn expected_verifier_version() -> String {
    format!(
        "traceseal-core {}; tlsn v{}",
        env!("CARGO_PKG_VERSION"),
        TLSNOTARY_VERSION
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{ArtifactHashes, PROOF_FORMAT, TLSNOTARY_VERSION, TRUST_POLICY_ID};
    use crate::{ArtifactInfo, VerifierInfo};

    const ATTESTATION: &[u8] = b"attestation bytes";
    const PRESENTATION: &[u8] = b"presentation bytes";
    const MANIFEST: &[u8] = b"{\"schema_version\":\"1.0\",\"url\":\"https://localhost:4443/trace-seal-503\",\"method\":\"GET\",\"disclosures\":[\"status\",\"service\"],\"created_at\":\"2026-11-06T01:57:09.831Z\"}";

    fn report() -> EvidenceReport {
        let hashes = ArtifactHashes::from_bytes(ATTESTATION, PRESENTATION, MANIFEST);
        EvidenceReport {
            schema_version: "1.0".into(),
            verification_status: "VERIFIED".into(),
            http_status: Some(503),
            disclosed_evidence: BTreeMap::from([
                ("service".into(), serde_json::json!("TRACESEAL Demo API")),
                ("status".into(), serde_json::json!(503)),
            ]),
            attestation: ArtifactInfo {
                identifier: Some(hashes.attestation_sha256.clone()),
                sha256: Some(hashes.attestation_sha256),
            },
            presentation: ArtifactInfo {
                identifier: Some(hashes.presentation_sha256.clone()),
                sha256: Some(hashes.presentation_sha256),
            },
            verifier: VerifierInfo {
                version: "traceseal-core 0.1.0; tlsn v0.1.0-alpha.15".into(),
                exit_code: Some(0),
            },
            verified_at: "2026-11-06T01:57:09.859Z".into(),
            errors: Vec::new(),
            proof_format: Some(PROOF_FORMAT.into()),
            tlsnotary_version: Some(TLSNOTARY_VERSION.into()),
            trust_policy_id: Some(TRUST_POLICY_ID.into()),
            verified_request: Some(VerifiedRequest {
                scheme: "https".into(),
                host: "localhost".into(),
                method: "GET".into(),
                path: "/trace-seal-503".into(),
            }),
        }
    }

    fn parse_report_result(
        report: &EvidenceReport,
        exit_success: bool,
    ) -> Result<EvidenceRecord, VerificationError> {
        if !exit_success {
            return Err(VerificationError::Rejected);
        }
        let bytes = serde_json::to_vec(report).unwrap();
        let report = parse_verifier_report(&bytes)?;
        let manifest = parse_manifest(MANIFEST)?;
        build_identity(
            EvidencePackage {
                attestation: ATTESTATION,
                presentation: PRESENTATION,
                request_manifest: MANIFEST,
            },
            &manifest,
            report,
        )
    }

    #[test]
    fn only_successful_verifier_exit_and_report_can_create_identity() {
        assert!(parse_report_result(&report(), true).is_ok());
        assert!(matches!(
            parse_report_result(&report(), false),
            Err(VerificationError::Rejected)
        ));
        let mut failed = report();
        failed.verification_status = "REJECTED".into();
        assert!(matches!(
            parse_report_result(&failed, true),
            Err(VerificationError::Rejected)
        ));
    }

    #[test]
    fn malformed_or_incomplete_verifier_output_is_rejected() {
        assert!(matches!(
            parse_verifier_report(b"not JSON"),
            Err(VerificationError::InvalidVerifierOutput)
        ));
        let mut missing = report();
        missing.verified_request = None;
        assert!(matches!(
            parse_report_result(&missing, true),
            Err(VerificationError::InvalidVerifierOutput)
        ));
    }

    #[test]
    fn trust_policy_and_format_must_match_actual_verifier_profile() {
        let mut wrong_policy = report();
        wrong_policy.trust_policy_id = Some("untrusted-policy".into());
        assert!(matches!(
            parse_report_result(&wrong_policy, true),
            Err(VerificationError::InvalidVerifierOutput)
        ));

        let mut wrong_format = report();
        wrong_format.proof_format = Some("client-format".into());
        assert!(matches!(
            parse_report_result(&wrong_format, true),
            Err(VerificationError::InvalidVerifierOutput)
        ));
    }

    #[test]
    fn manifest_claims_cannot_override_verified_request_or_disclosures() {
        let mut contradiction = report();
        contradiction.verified_request.as_mut().unwrap().path = "/trace-seal-200".into();
        assert!(matches!(
            parse_report_result(&contradiction, true),
            Err(VerificationError::Rejected)
        ));
        let mut wrong_fields = report();
        wrong_fields.disclosed_evidence.remove("service");
        assert!(matches!(
            parse_report_result(&wrong_fields, true),
            Err(VerificationError::Rejected)
        ));
    }

    #[test]
    fn manifest_and_artifact_tampering_is_rejected() {
        let modified_manifest =
            b"{\"schema_version\":\"1.0\",\"url\":\"https://localhost:4443/trace-seal-200\",\"method\":\"GET\",\"disclosures\":[\"status\",\"service\"],\"created_at\":\"2026-11-06T01:57:09.831Z\"}";
        let modified = parse_manifest(modified_manifest).unwrap();
        assert!(matches!(
            build_identity(
                EvidencePackage {
                    attestation: ATTESTATION,
                    presentation: PRESENTATION,
                    request_manifest: modified_manifest,
                },
                &modified,
                report(),
            ),
            Err(VerificationError::Rejected)
        ));
    }

    #[test]
    fn manifest_rejects_unknown_path_fields_and_unsupported_schema() {
        let with_path = MANIFEST.strip_suffix(b"}").unwrap();
        let with_path = [with_path, b",\"attestation_path\":\"..\\\\outside\"}"].concat();
        assert!(matches!(
            parse_manifest(&with_path),
            Err(VerificationError::InvalidPackage(_))
        ));

        let unsupported = MANIFEST
            .windows(b"1.0".len())
            .position(|window| window == b"1.0")
            .map(|index| {
                let mut bytes = MANIFEST.to_vec();
                bytes[index + 2] = b'1';
                bytes
            })
            .unwrap();
        assert!(matches!(
            parse_manifest(&unsupported),
            Err(VerificationError::InvalidPackage(_))
        ));
    }

    #[test]
    fn package_size_limits_fail_before_verifier_invocation() {
        let oversized = vec![0u8; MAX_ATTESTATION_BYTES + 1];
        let package = EvidencePackage {
            attestation: &oversized,
            presentation: PRESENTATION,
            request_manifest: MANIFEST,
        };
        assert!(matches!(
            validate_sizes(&package),
            Err(VerificationError::InvalidPackage(_))
        ));
    }

    #[test]
    fn fabricated_success_report_cannot_ignore_process_exit_status() {
        let result = parse_report_result(&report(), false);
        assert!(result.is_err());
    }
}
