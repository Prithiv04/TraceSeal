use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use chrono::{SecondsFormat, Utc};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    engine::VerifiedEvidence,
    evidence::{ArtifactHashes, EvidenceRecord},
    EvidenceReport,
};

const DATABASE_VERSION: i64 = 2;
const MAX_ARTIFACT_SIZES: [u64; 3] = [16 * 1024 * 1024, 16 * 1024 * 1024, 64 * 1024];
const ARTIFACT_TYPES: [(&str, &str); 3] = [
    ("attestation", "attestation.tlsn"),
    ("presentation", "presentation.tlsn"),
    ("request_manifest", "request.json"),
];

/// Schema v2: Hedera outbox + NFT receipt tables.
const HEDERA_V2_SCHEMA: &str = "
    CREATE TABLE hedera_events (
        event_id INTEGER PRIMARY KEY,
        evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id),
        event_type TEXT NOT NULL CHECK (
            event_type IN ('EVIDENCE_VERIFIED', 'RECEIPT_MINTED', 'EVIDENCE_REVERIFIED')
        ),
        dedupe_key TEXT NOT NULL UNIQUE,
        payload_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK (
            status IN ('PENDING', 'SUBMITTED', 'CONFIRMED', 'FAILED')
        ) DEFAULT 'PENDING',
        topic_id TEXT,
        sequence_number TEXT,
        consensus_timestamp TEXT,
        transaction_id TEXT,
        attempts INTEGER NOT NULL DEFAULT 0,
        last_error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE INDEX hedera_events_status ON hedera_events(status);
    CREATE INDEX hedera_events_evidence ON hedera_events(evidence_id);
    CREATE TABLE hedera_receipts (
        evidence_id TEXT PRIMARY KEY REFERENCES evidence_records(evidence_id),
        commitment TEXT NOT NULL,
        commitment_hex TEXT NOT NULL UNIQUE,
        token_id TEXT NOT NULL,
        serial_number TEXT,
        mint_transaction_id TEXT,
        mint_consensus_timestamp TEXT,
        status TEXT NOT NULL CHECK (status IN ('PENDING', 'MINTED', 'FAILED')),
        last_error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    PRAGMA user_version = 2;";

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("invalid evidence identifier")]
    InvalidEvidenceId,
    #[error("evidence was not found")]
    NotFound,
    #[error("evidence already exists with conflicting contents")]
    Conflict,
    #[error("stored evidence is corrupted or inconsistent")]
    Corrupt,
    #[error("storage path is unsafe")]
    UnsafePath,
    #[error("unsupported metadata database schema version")]
    UnsupportedSchemaVersion,
    #[error("filesystem storage operation failed")]
    Io(#[source] std::io::Error),
    #[error("metadata database operation failed")]
    Database(#[source] rusqlite::Error),
}

impl From<std::io::Error> for StorageError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreDisposition {
    Stored,
    AlreadyPresent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageReceipt {
    pub evidence_id: String,
    pub commitment: String,
    pub stored_at: String,
    pub disposition: StoreDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMetadata {
    pub record: EvidenceRecord,
    pub original_verification: EvidenceReport,
    pub reverifications: Vec<EvidenceReport>,
    pub stored_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredArtifacts {
    pub attestation: Vec<u8>,
    pub presentation: Vec<u8>,
    pub request_manifest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvidence {
    pub metadata: StoredMetadata,
    pub artifacts: StoredArtifacts,
}

/// One row of the `hedera_events` outbox table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HederaEventRow {
    pub event_id: i64,
    pub evidence_id: String,
    pub event_type: String,
    pub dedupe_key: String,
    pub payload_json: String,
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

/// One row of the `hedera_receipts` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HederaReceiptRow {
    pub evidence_id: String,
    pub commitment: String,
    pub commitment_hex: String,
    pub token_id: String,
    pub serial_number: Option<String>,
    pub mint_transaction_id: Option<String>,
    pub mint_consensus_timestamp: Option<String>,
    pub status: String,
    pub last_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct EvidenceStore {
    root: PathBuf,
    artifacts_root: PathBuf,
    staging_root: PathBuf,
    database_path: PathBuf,
}

impl EvidenceStore {
    /// Perform a lightweight read‑only health check.
    ///
    /// Returns `Ok(())` if the SQLite metadata database can be opened in
    /// read‑only mode and a trivial SELECT query succeeds. This method does
    /// not create or modify any database structures, evidence records, or
    /// verification history.
    ///
    /// All errors are mapped to the existing `StorageError` variants.
    pub fn health_check(&self) -> Result<(), StorageError> {
        // Ensure the database file exists before attempting a read‑only open.
        if !self.database_path.is_file() {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "metadata database missing",
            )));
        }
        // Verify the file is not a symlink (same protection as normal `open`).
        reject_symlink_if_present(&self.database_path)?;
        // Open a read‑only SQLite connection.
        let conn = rusqlite::Connection::open_with_flags(
            &self.database_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(StorageError::Database)?;
        // Execute a simple harmless query.
        conn.prepare_cached("SELECT 1")
            .and_then(|mut stmt| stmt.query_row([], |_| Ok(())))
            .map_err(StorageError::Database)
    }

    fn connect(&self) -> Result<Connection, StorageError> {
        reject_symlink_if_present(&self.database_path)?;
        let connection = Connection::open(&self.database_path)?;
        connection.busy_timeout(Duration::from_secs(10))?;
        connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL;")?;
        Ok(connection)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        let configured_root = root.as_ref();
        match fs::symlink_metadata(configured_root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(StorageError::UnsafePath);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(configured_root)?;
            }
            Err(error) => return Err(StorageError::Io(error)),
        }
        let root = configured_root.canonicalize()?;
        set_directory_permissions(&root)?;
        let artifacts_root = root.join("artifacts");
        let staging_root = root.join(".staging");
        ensure_directory(&artifacts_root)?;
        ensure_directory(&staging_root)?;

        let database_path = root.join("metadata.sqlite3");
        reject_symlink_if_present(&database_path)?;
        let store = Self {
            root,
            artifacts_root,
            staging_root,
            database_path,
        };
        store.initialize_database()?;
        store.reconcile()?;
        Ok(store)
    }

    pub fn store(&self, verified: &VerifiedEvidence<'_>) -> Result<StorageReceipt, StorageError> {
        self.store_with_stage_hook(verified, || {})
    }

    fn store_with_stage_hook(
        &self,
        verified: &VerifiedEvidence<'_>,
        after_staging: impl FnOnce(),
    ) -> Result<StorageReceipt, StorageError> {
        ensure_existing_directory(&self.artifacts_root, &self.artifacts_root)?;
        ensure_existing_directory(&self.staging_root, &self.root)?;
        let record = verified.record();
        validate_trusted_evidence(verified)?;
        let (attestation, presentation, request_manifest) = verified.artifacts();
        let actual_hashes = ArtifactHashes::from_bytes(attestation, presentation, request_manifest);
        validate_evidence_id(record.evidence_id())?;

        let record_json = serde_json::to_string(record).map_err(|_| StorageError::Corrupt)?;
        let stored_at = now();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing = transaction
            .query_row(
                "SELECT commitment, record_json, stored_at, state
                 FROM evidence_records WHERE evidence_id = ?1",
                [record.evidence_id()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some((commitment, existing_json, existing_stored_at, state)) = existing {
            drop(transaction);
            if commitment != record.commitment() || existing_json != record_json || state != "READY"
            {
                return Err(StorageError::Conflict);
            }
            self.get(record.evidence_id())?;
            return Ok(StorageReceipt {
                evidence_id: record.evidence_id().to_owned(),
                commitment: record.commitment().to_owned(),
                stored_at: existing_stored_at,
                disposition: StoreDisposition::AlreadyPresent,
            });
        }

        let temp_directory = tempfile::Builder::new()
            .prefix("ingest-")
            .tempdir_in(&self.staging_root)?;
        ensure_directory(temp_directory.path())?;
        write_new(temp_directory.path().join("attestation.tlsn"), attestation)?;
        write_new(
            temp_directory.path().join("presentation.tlsn"),
            presentation,
        )?;
        write_new(temp_directory.path().join("request.json"), request_manifest)?;
        sync_directory(temp_directory.path())?;
        after_staging();

        let attestation_size =
            i64::try_from(attestation.len()).map_err(|_| StorageError::Corrupt)?;
        let presentation_size =
            i64::try_from(presentation.len()).map_err(|_| StorageError::Corrupt)?;
        let manifest_size =
            i64::try_from(request_manifest.len()).map_err(|_| StorageError::Corrupt)?;

        insert_record(&transaction, record, &record_json, &stored_at)?;
        insert_verification_entry(
            &transaction,
            record,
            verified.original_verification(),
            "ORIGINAL",
        )?;
        insert_artifact_rows(
            &transaction,
            record,
            &actual_hashes,
            [attestation_size, presentation_size, manifest_size],
        )?;

        let final_directory = self.artifacts_root.join(record.evidence_id());
        match fs::create_dir(&final_directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(StorageError::Conflict)
            }
            Err(error) => return Err(StorageError::Io(error)),
        }
        set_directory_permissions(&final_directory)?;
        let publish_result = (|| -> Result<(), StorageError> {
            for (_, filename) in ARTIFACT_TYPES {
                fs::rename(
                    temp_directory.path().join(filename),
                    final_directory.join(filename),
                )?;
            }
            sync_directory(&final_directory)?;
            sync_directory(&self.artifacts_root)?;
            Ok(())
        })();
        if let Err(error) = publish_result {
            let _ = fs::remove_dir_all(&final_directory);
            return Err(error);
        }

        if let Err(error) = transaction.commit() {
            // The commit outcome can be uncertain to the caller; retain published bytes so
            // a committed READY row is never left without its artifacts. Startup can reap
            // the directory if the transaction was rolled back.
            return Err(StorageError::Database(error));
        }

        Ok(StorageReceipt {
            evidence_id: record.evidence_id().to_owned(),
            commitment: record.commitment().to_owned(),
            stored_at,
            disposition: StoreDisposition::Stored,
        })
    }

    pub fn get_metadata(&self, evidence_id: &str) -> Result<StoredMetadata, StorageError> {
        validate_evidence_id(evidence_id)?;
        let connection = self.connect()?;
        load_metadata(&connection, evidence_id)
    }

    pub fn get(&self, evidence_id: &str) -> Result<StoredEvidence, StorageError> {
        validate_evidence_id(evidence_id)?;
        ensure_existing_directory(&self.artifacts_root, &self.artifacts_root)?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let metadata = load_metadata(&transaction, evidence_id)?;
        let artifact_rows = load_artifact_rows(&transaction, evidence_id)?;
        let artifacts = self.read_and_validate_artifacts(&metadata.record, artifact_rows)?;
        transaction.commit()?;
        Ok(StoredEvidence {
            metadata,
            artifacts,
        })
    }

    pub fn record_reverification(
        &self,
        verified: VerifiedEvidence<'_>,
    ) -> Result<(), StorageError> {
        validate_trusted_evidence(&verified)?;
        let record = verified.record();
        validate_evidence_id(record.evidence_id())?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = load_metadata(&transaction, record.evidence_id())?;
        if metadata.record != *record {
            return Err(StorageError::Conflict);
        }
        let persisted_artifacts = self.read_and_validate_artifacts(
            &metadata.record,
            load_artifact_rows(&transaction, record.evidence_id())?,
        )?;
        let (attestation, presentation, request_manifest) = verified.artifacts();
        if persisted_artifacts.attestation != attestation
            || persisted_artifacts.presentation != presentation
            || persisted_artifacts.request_manifest != request_manifest
        {
            return Err(StorageError::Conflict);
        }
        let report_json = serde_json::to_string(verified.original_verification())
            .map_err(|_| StorageError::Corrupt)?;
        let is_duplicate: bool = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM verification_records
                WHERE evidence_id = ?1 AND report_json = ?2
            )",
            params![record.evidence_id(), report_json],
            |row| row.get(0),
        )?;
        if is_duplicate {
            return Err(StorageError::Conflict);
        }
        insert_verification_entry(
            &transaction,
            record,
            verified.original_verification(),
            "REVERIFICATION",
        )?;
        transaction.commit()?;
        Ok(())
    }

    /* ---------------- Hedera outbox + receipts (schema v2) ---------------- */

    /// Enqueue a Hedera audit event. Idempotent via UNIQUE(dedupe_key):
    /// returns the existing event_id if the key was already enqueued.
    pub fn enqueue_hedera_event(
        &self,
        evidence_id: &str,
        event_type: &str,
        dedupe_key: &str,
        payload_json: &str,
    ) -> Result<i64, StorageError> {
        validate_evidence_id(evidence_id)?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now();
        transaction.execute(
            "INSERT INTO hedera_events (
                evidence_id, event_type, dedupe_key, payload_json, status, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, 'PENDING', ?5, ?5)
            ON CONFLICT(dedupe_key) DO NOTHING",
            params![evidence_id, event_type, dedupe_key, payload_json, now],
        )?;
        let event_id: i64 = transaction.query_row(
            "SELECT event_id FROM hedera_events WHERE dedupe_key = ?1",
            [dedupe_key],
            |row| row.get(0),
        )?;
        transaction.commit()?;
        Ok(event_id)
    }

    /// Fetch a single outbox event by dedupe key.
    pub fn get_hedera_event(
        &self,
        dedupe_key: &str,
    ) -> Result<Option<HederaEventRow>, StorageError> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT event_id, evidence_id, event_type, dedupe_key, payload_json, status,
                        topic_id, sequence_number, consensus_timestamp, transaction_id,
                        attempts, last_error, created_at, updated_at
                 FROM hedera_events WHERE dedupe_key = ?1",
                [dedupe_key],
                hedera_event_from_row,
            )
            .optional()
            .map_err(StorageError::Database)
    }

    /// List outbox events for one evidence record, oldest first.
    pub fn hedera_events_for(
        &self,
        evidence_id: &str,
    ) -> Result<Vec<HederaEventRow>, StorageError> {
        validate_evidence_id(evidence_id)?;
        let connection = self.connect()?;
        let mut stmt = connection.prepare(
            "SELECT event_id, evidence_id, event_type, dedupe_key, payload_json, status,
                    topic_id, sequence_number, consensus_timestamp, transaction_id,
                    attempts, last_error, created_at, updated_at
             FROM hedera_events WHERE evidence_id = ?1 ORDER BY event_id",
        )?;
        let rows = stmt.query_map([evidence_id], hedera_event_from_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// List PENDING/FAILED events eligible for retry, oldest first.
    pub fn pending_hedera_events(&self, limit: usize) -> Result<Vec<HederaEventRow>, StorageError> {
        let connection = self.connect()?;
        let mut stmt = connection.prepare(
            "SELECT event_id, evidence_id, event_type, dedupe_key, payload_json, status,
                    topic_id, sequence_number, consensus_timestamp, transaction_id,
                    attempts, last_error, created_at, updated_at
             FROM hedera_events
             WHERE status IN ('PENDING', 'FAILED')
             ORDER BY event_id LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], hedera_event_from_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Record the outcome of an HCS publish attempt.
    pub fn mark_hedera_event_submitted(
        &self,
        dedupe_key: &str,
        topic_id: &str,
        sequence_number: &str,
        consensus_timestamp: &str,
        transaction_id: &str,
    ) -> Result<(), StorageError> {
        let connection = self.connect()?;
        connection.execute(
            "UPDATE hedera_events SET
                status = 'CONFIRMED', topic_id = ?2, sequence_number = ?3,
                consensus_timestamp = ?4, transaction_id = ?5,
                attempts = attempts + 1, last_error = NULL, updated_at = ?6
             WHERE dedupe_key = ?1",
            params![
                dedupe_key,
                topic_id,
                sequence_number,
                consensus_timestamp,
                transaction_id,
                now()
            ],
        )?;
        Ok(())
    }

    /// Record a failed attempt; status stays retryable (FAILED).
    pub fn mark_hedera_event_failed(
        &self,
        dedupe_key: &str,
        error: &str,
    ) -> Result<(), StorageError> {
        let connection = self.connect()?;
        connection.execute(
            "UPDATE hedera_events SET
                status = 'FAILED', attempts = attempts + 1, last_error = ?2, updated_at = ?3
             WHERE dedupe_key = ?1",
            params![dedupe_key, error, now()],
        )?;
        Ok(())
    }

    /// Reserve an NFT receipt slot for a commitment. Idempotent: returns
    /// (created, serial_status). UNIQUE(commitment_hex) prevents double mint.
    pub fn reserve_hedera_receipt(
        &self,
        evidence_id: &str,
        commitment: &str,
        commitment_hex: &str,
        token_id: &str,
    ) -> Result<bool, StorageError> {
        validate_evidence_id(evidence_id)?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now();
        let inserted = transaction.execute(
            "INSERT INTO hedera_receipts (
                evidence_id, commitment, commitment_hex, token_id, status, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, 'PENDING', ?5, ?5)
            ON CONFLICT(commitment_hex) DO NOTHING",
            params![evidence_id, commitment, commitment_hex, token_id, now],
        )?;
        transaction.commit()?;
        Ok(inserted > 0)
    }

    /// Mark an NFT receipt as minted with real transaction references.
    pub fn mark_hedera_receipt_minted(
        &self,
        evidence_id: &str,
        serial_number: &str,
        mint_transaction_id: &str,
        mint_consensus_timestamp: &str,
    ) -> Result<(), StorageError> {
        let connection = self.connect()?;
        connection.execute(
            "UPDATE hedera_receipts SET
                status = 'MINTED', serial_number = ?2, mint_transaction_id = ?3,
                mint_consensus_timestamp = ?4, last_error = NULL, updated_at = ?5
             WHERE evidence_id = ?1",
            params![evidence_id, serial_number, mint_transaction_id, mint_consensus_timestamp, now()],
        )?;
        Ok(())
    }

    /// Mark an NFT receipt attempt as failed (retryable).
    pub fn mark_hedera_receipt_failed(
        &self,
        evidence_id: &str,
        error: &str,
    ) -> Result<(), StorageError> {
        let connection = self.connect()?;
        connection.execute(
            "UPDATE hedera_receipts SET status = 'FAILED', last_error = ?2, updated_at = ?3
             WHERE evidence_id = ?1",
            params![evidence_id, error, now()],
        )?;
        Ok(())
    }

    /// Fetch the NFT receipt for an evidence record, if any.
    pub fn hedera_receipt_for(
        &self,
        evidence_id: &str,
    ) -> Result<Option<HederaReceiptRow>, StorageError> {
        validate_evidence_id(evidence_id)?;
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT evidence_id, commitment, commitment_hex, token_id, serial_number,
                        mint_transaction_id, mint_consensus_timestamp, status, last_error,
                        created_at, updated_at
                 FROM hedera_receipts WHERE evidence_id = ?1",
                [evidence_id],
                hedera_receipt_from_row,
            )
            .optional()
            .map_err(StorageError::Database)
    }

    /// Fetch a receipt by commitment hex (used for dedupe across evidence IDs).
    pub fn hedera_receipt_by_commitment(
        &self,
        commitment_hex: &str,
    ) -> Result<Option<HederaReceiptRow>, StorageError> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT evidence_id, commitment, commitment_hex, token_id, serial_number,
                        mint_transaction_id, mint_consensus_timestamp, status, last_error,
                        created_at, updated_at
                 FROM hedera_receipts WHERE commitment_hex = ?1",
                [commitment_hex],
                hedera_receipt_from_row,
            )
            .optional()
            .map_err(StorageError::Database)
    }

    /// Receipts still needing a mint attempt (PENDING or FAILED).
    pub fn pending_hedera_receipts(&self) -> Result<Vec<HederaReceiptRow>, StorageError> {
        let connection = self.connect()?;
        let mut stmt = connection.prepare(
            "SELECT evidence_id, commitment, commitment_hex, token_id, serial_number,
                    mint_transaction_id, mint_consensus_timestamp, status, last_error,
                    created_at, updated_at
             FROM hedera_receipts WHERE status IN ('PENDING', 'FAILED')
             ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], hedera_receipt_from_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    fn initialize_database(&self) -> Result<(), StorageError> {
        let mut connection = self.connect()?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > DATABASE_VERSION {
            return Err(StorageError::UnsupportedSchemaVersion);
        }
        if version == 0 {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let locked_version: i64 =
                transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
            if locked_version == 0 {
                transaction.execute_batch(
                    "CREATE TABLE evidence_records (
                    evidence_id TEXT PRIMARY KEY NOT NULL,
                    commitment TEXT NOT NULL UNIQUE,
                    schema_version TEXT NOT NULL,
                    verification_status TEXT NOT NULL CHECK (verification_status = 'VERIFIED'),
                    verifier_version TEXT NOT NULL,
                    trust_policy_id TEXT NOT NULL,
                    tlsnotary_version TEXT NOT NULL,
                    proof_format TEXT NOT NULL,
                    attestation_hash TEXT NOT NULL,
                    presentation_hash TEXT NOT NULL,
                    manifest_hash TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state = 'READY')
                );
                CREATE TABLE evidence_artifacts (
                    artifact_id INTEGER PRIMARY KEY,
                    evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id) ON DELETE CASCADE,
                    artifact_type TEXT NOT NULL CHECK (
                        artifact_type IN ('attestation', 'presentation', 'request_manifest')
                    ),
                    storage_key TEXT NOT NULL UNIQUE,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
                    UNIQUE (evidence_id, artifact_type)
                );
                CREATE INDEX evidence_records_trust_policy
                    ON evidence_records(trust_policy_id);
                    CREATE TABLE verification_records (
                        verification_id INTEGER PRIMARY KEY,
                        evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id),
                        record_kind TEXT NOT NULL CHECK (
                            record_kind IN ('ORIGINAL', 'REVERIFICATION')
                        ),
                        verification_status TEXT NOT NULL,
                        verifier_version TEXT NOT NULL,
                        trust_policy_id TEXT NOT NULL,
                        verified_at TEXT NOT NULL,
                        report_json TEXT NOT NULL
                    );
                    CREATE UNIQUE INDEX verification_records_one_original
                        ON verification_records(evidence_id) WHERE record_kind = 'ORIGINAL';
                    CREATE TRIGGER verification_records_no_update
                        BEFORE UPDATE ON verification_records
                        BEGIN SELECT RAISE(ABORT, 'verification records are immutable'); END;
                    CREATE TRIGGER verification_records_no_delete
                        BEFORE DELETE ON verification_records
                        BEGIN SELECT RAISE(ABORT, 'verification records are immutable'); END;
                    PRAGMA user_version = 1;",
                )?;
            } else if locked_version != DATABASE_VERSION {
                return Err(StorageError::UnsupportedSchemaVersion);
            }
            transaction.commit()?;
        }
        // Migrate v1 -> v2: Hedera outbox + receipt tables.
        let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if current == 1 {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let locked: i64 =
                transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
            if locked == 1 {
                transaction.execute_batch(HEDERA_V2_SCHEMA)?;
            } else if locked != DATABASE_VERSION {
                return Err(StorageError::UnsupportedSchemaVersion);
            }
            transaction.commit()?;
        }
        set_file_permissions(&self.database_path)?;
        Ok(())
    }

    fn reconcile(&self) -> Result<(), StorageError> {
        ensure_existing_directory(&self.artifacts_root, &self.artifacts_root)?;
        ensure_existing_directory(&self.staging_root, &self.root)?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut known_ids = HashSet::new();
        {
            let mut statement = transaction
                .prepare("SELECT evidence_id FROM evidence_records WHERE state = 'READY'")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            for row in rows {
                known_ids.insert(row?);
            }
        }

        for entry in fs::read_dir(&self.staging_root)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(StorageError::UnsafePath);
            }
            if metadata.is_dir() {
                fs::remove_dir_all(entry.path())?;
            } else if metadata.is_file() {
                fs::remove_file(entry.path())?;
            }
        }
        for entry in fs::read_dir(&self.artifacts_root)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(StorageError::UnsafePath);
            }
            if metadata.is_dir() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if is_evidence_id(name) && !known_ids.contains(name) {
                    fs::remove_dir_all(entry.path())?;
                }
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn read_and_validate_artifacts(
        &self,
        record: &EvidenceRecord,
        rows: Vec<ArtifactRow>,
    ) -> Result<StoredArtifacts, StorageError> {
        if rows.len() != ARTIFACT_TYPES.len() {
            return Err(StorageError::Corrupt);
        }
        let mut by_type = HashMap::new();
        for row in rows {
            if by_type.insert(row.artifact_type.clone(), row).is_some() {
                return Err(StorageError::Corrupt);
            }
        }

        let mut read = HashMap::new();
        for (artifact_type, filename) in ARTIFACT_TYPES {
            let row = by_type.get(artifact_type).ok_or(StorageError::Corrupt)?;
            let expected_key = format!("{}/{}", record.evidence_id(), filename);
            if row.storage_key != expected_key
                || row.size_bytes < 0
                || row.size_bytes as u64 > MAX_ARTIFACT_SIZES[artifact_index(artifact_type)?]
            {
                return Err(StorageError::Corrupt);
            }
            let directory = self.artifacts_root.join(record.evidence_id());
            ensure_existing_directory(&directory, &self.artifacts_root)?;
            let path = directory.join(filename);
            let file_size = ensure_existing_file(&path, &self.artifacts_root)?;
            if file_size > MAX_ARTIFACT_SIZES[artifact_index(artifact_type)?] {
                return Err(StorageError::Corrupt);
            }
            let bytes = fs::read(&path)?;
            if i64::try_from(bytes.len()).ok() != Some(row.size_bytes)
                || sha256_hex(&bytes) != row.sha256
            {
                return Err(StorageError::Corrupt);
            }
            read.insert(artifact_type, bytes);
        }

        let attestation = read.remove("attestation").ok_or(StorageError::Corrupt)?;
        let presentation = read.remove("presentation").ok_or(StorageError::Corrupt)?;
        let request_manifest = read
            .remove("request_manifest")
            .ok_or(StorageError::Corrupt)?;
        let hashes = ArtifactHashes::from_bytes(&attestation, &presentation, &request_manifest);
        let payload = record.payload();
        if hashes.attestation_sha256 != payload.proof.attestation_sha256
            || hashes.presentation_sha256 != payload.proof.presentation_sha256
            || hashes.request_manifest_sha256 != payload.proof.request_manifest_sha256
        {
            return Err(StorageError::Corrupt);
        }
        record.validate().map_err(|_| StorageError::Corrupt)?;
        Ok(StoredArtifacts {
            attestation,
            presentation,
            request_manifest,
        })
    }
}

struct ArtifactRow {
    artifact_type: String,
    storage_key: String,
    sha256: String,
    size_bytes: i64,
}

fn artifact_index(artifact_type: &str) -> Result<usize, StorageError> {
    ARTIFACT_TYPES
        .iter()
        .position(|(name, _)| *name == artifact_type)
        .ok_or(StorageError::Corrupt)
}

fn insert_record(
    transaction: &Transaction<'_>,
    record: &EvidenceRecord,
    record_json: &str,
    stored_at: &str,
) -> Result<(), StorageError> {
    let payload = record.payload();
    transaction.execute(
        "INSERT INTO evidence_records (
            evidence_id, commitment, schema_version, verification_status, verifier_version,
            trust_policy_id, tlsnotary_version, proof_format, attestation_hash,
            presentation_hash, manifest_hash, record_json, stored_at, state
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'READY')",
        params![
            record.evidence_id(),
            record.commitment(),
            payload.schema_version,
            payload.verification.result,
            payload.verification.verifier_version,
            payload.trust_policy_id,
            payload.proof.tlsnotary_version,
            payload.proof.format,
            payload.proof.attestation_sha256,
            payload.proof.presentation_sha256,
            payload.proof.request_manifest_sha256,
            record_json,
            stored_at
        ],
    )?;
    Ok(())
}

fn insert_artifact_rows(
    transaction: &Transaction<'_>,
    record: &EvidenceRecord,
    hashes: &ArtifactHashes,
    sizes: [i64; 3],
) -> Result<(), StorageError> {
    let artifact_hashes = [
        hashes.attestation_sha256.as_str(),
        hashes.presentation_sha256.as_str(),
        hashes.request_manifest_sha256.as_str(),
    ];
    for (index, (artifact_type, filename)) in ARTIFACT_TYPES.iter().enumerate() {
        let storage_key = format!("{}/{}", record.evidence_id(), filename);
        transaction.execute(
            "INSERT INTO evidence_artifacts (
                evidence_id, artifact_type, storage_key, sha256, size_bytes
            ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                record.evidence_id(),
                artifact_type,
                storage_key,
                artifact_hashes[index],
                sizes[index]
            ],
        )?;
    }
    Ok(())
}

fn hedera_event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<HederaEventRow> {
    Ok(HederaEventRow {
        event_id: row.get(0)?,
        evidence_id: row.get(1)?,
        event_type: row.get(2)?,
        dedupe_key: row.get(3)?,
        payload_json: row.get(4)?,
        status: row.get(5)?,
        topic_id: row.get(6)?,
        sequence_number: row.get(7)?,
        consensus_timestamp: row.get(8)?,
        transaction_id: row.get(9)?,
        attempts: row.get(10)?,
        last_error: row.get(11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
    })
}

fn hedera_receipt_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<HederaReceiptRow> {
    Ok(HederaReceiptRow {
        evidence_id: row.get(0)?,
        commitment: row.get(1)?,
        commitment_hex: row.get(2)?,
        token_id: row.get(3)?,
        serial_number: row.get(4)?,
        mint_transaction_id: row.get(5)?,
        mint_consensus_timestamp: row.get(6)?,
        status: row.get(7)?,
        last_error: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

fn load_metadata(
    connection: &Connection,
    evidence_id: &str,
) -> Result<StoredMetadata, StorageError> {
    let (
        commitment,
        schema_version,
        verification_status,
        verifier_version,
        trust_policy_id,
        tlsnotary_version,
        proof_format,
        attestation_hash,
        presentation_hash,
        manifest_hash,
        record_json,
        stored_at,
        state,
    ) = connection
        .query_row(
            "SELECT commitment, schema_version, verification_status, verifier_version,
                    trust_policy_id, tlsnotary_version, proof_format, attestation_hash,
                    presentation_hash, manifest_hash, record_json, stored_at, state
             FROM evidence_records WHERE evidence_id = ?1",
            [evidence_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                ))
            },
        )
        .optional()?
        .ok_or(StorageError::NotFound)?;
    if state != "READY" || verification_status != "VERIFIED" {
        return Err(StorageError::Corrupt);
    }
    let record: EvidenceRecord =
        serde_json::from_str(&record_json).map_err(|_| StorageError::Corrupt)?;
    record.validate().map_err(|_| StorageError::Corrupt)?;
    let (original_verification, reverifications) =
        load_verification_records(connection, evidence_id, &record)?;
    let payload = record.payload();
    if record.evidence_id() != evidence_id
        || record.commitment() != commitment
        || payload.schema_version != schema_version
        || payload.verification.result != verification_status
        || payload.verification.verifier_version != verifier_version
        || payload.trust_policy_id != trust_policy_id
        || payload.proof.tlsnotary_version != tlsnotary_version
        || payload.proof.format != proof_format
        || payload.proof.attestation_sha256 != attestation_hash
        || payload.proof.presentation_sha256 != presentation_hash
        || payload.proof.request_manifest_sha256 != manifest_hash
    {
        return Err(StorageError::Corrupt);
    }
    Ok(StoredMetadata {
        record,
        original_verification,
        reverifications,
        stored_at,
    })
}

fn insert_verification_entry(
    transaction: &Transaction<'_>,
    record: &EvidenceRecord,
    report: &EvidenceReport,
    record_kind: &str,
) -> Result<(), StorageError> {
    validate_verification_report(report, record, record_kind == "ORIGINAL")?;
    let report_json = serde_json::to_string(report).map_err(|_| StorageError::Corrupt)?;
    transaction.execute(
        "INSERT INTO verification_records (
            evidence_id, record_kind, verification_status, verifier_version,
            trust_policy_id, verified_at, report_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            record.evidence_id(),
            record_kind,
            report.verification_status,
            report.verifier.version,
            report
                .trust_policy_id
                .as_deref()
                .ok_or(StorageError::Corrupt)?,
            report.verified_at,
            report_json
        ],
    )?;
    Ok(())
}

fn load_verification_records(
    connection: &Connection,
    evidence_id: &str,
    record: &EvidenceRecord,
) -> Result<(EvidenceReport, Vec<EvidenceReport>), StorageError> {
    let mut statement = connection.prepare(
        "SELECT record_kind, verification_status, verifier_version, trust_policy_id,
                verified_at, report_json
         FROM verification_records WHERE evidence_id = ?1 ORDER BY verification_id",
    )?;
    let rows = statement.query_map([evidence_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
        ))
    })?;
    let mut original = None;
    let mut reverifications = Vec::new();
    for row in rows {
        let (kind, status, verifier_version, trust_policy_id, verified_at, report_json) = row?;
        let report: EvidenceReport =
            serde_json::from_str(&report_json).map_err(|_| StorageError::Corrupt)?;
        if report.verification_status != status
            || report.verifier.version != verifier_version
            || report.trust_policy_id.as_deref() != Some(trust_policy_id.as_str())
            || report.verified_at != verified_at
        {
            return Err(StorageError::Corrupt);
        }
        match kind.as_str() {
            "ORIGINAL" => {
                if original.is_some() {
                    return Err(StorageError::Corrupt);
                }
                validate_verification_report(&report, record, true)?;
                original = Some(report);
            }
            "REVERIFICATION" => {
                validate_verification_report(&report, record, false)?;
                reverifications.push(report);
            }
            _ => return Err(StorageError::Corrupt),
        }
    }
    Ok((original.ok_or(StorageError::Corrupt)?, reverifications))
}

fn validate_trusted_evidence(verified: &VerifiedEvidence<'_>) -> Result<(), StorageError> {
    let record = verified.record();
    record.validate().map_err(|_| StorageError::Corrupt)?;
    validate_verification_report(verified.original_verification(), record, true)?;
    let (attestation, presentation, request_manifest) = verified.artifacts();
    let hashes = ArtifactHashes::from_bytes(attestation, presentation, request_manifest);
    if attestation.is_empty()
        || presentation.is_empty()
        || request_manifest.is_empty()
        || attestation.len() as u64 > MAX_ARTIFACT_SIZES[0]
        || presentation.len() as u64 > MAX_ARTIFACT_SIZES[1]
        || request_manifest.len() as u64 > MAX_ARTIFACT_SIZES[2]
        || record.payload().proof.attestation_sha256 != hashes.attestation_sha256
        || record.payload().proof.presentation_sha256 != hashes.presentation_sha256
        || record.payload().proof.request_manifest_sha256 != hashes.request_manifest_sha256
    {
        return Err(StorageError::Corrupt);
    }
    Ok(())
}

fn validate_verification_report(
    report: &EvidenceReport,
    record: &EvidenceRecord,
    original: bool,
) -> Result<(), StorageError> {
    let payload = record.payload();
    let disclosures_match = payload.disclosed_fields.iter().all(|(name, value)| {
        serde_json::to_value(value)
            .is_ok_and(|value| report.disclosed_evidence.get(name) == Some(&value))
    });
    if report.schema_version != payload.schema_version
        || report.verification_status != "VERIFIED"
        || report.verifier.exit_code != Some(0)
        || !report.errors.is_empty()
        || report.verifier.version.is_empty()
        || report.trust_policy_id.as_deref().is_none_or(str::is_empty)
        || (original
            && (report.verifier.version != payload.verification.verifier_version
                || report.trust_policy_id.as_deref() != Some(payload.trust_policy_id.as_str())))
        || report.proof_format.as_deref() != Some(payload.proof.format.as_str())
        || report.tlsnotary_version.as_deref() != Some(payload.proof.tlsnotary_version.as_str())
        || report.http_status != Some(payload.disclosed_http_status)
        || report.verified_request.as_ref() != Some(&payload.verified_request)
        || report.disclosed_evidence.len() != payload.disclosed_fields.len()
        || !disclosures_match
        || report.attestation.sha256.as_deref() != Some(payload.proof.attestation_sha256.as_str())
        || report.attestation.identifier.as_deref()
            != Some(payload.proof.attestation_sha256.as_str())
        || report.presentation.sha256.as_deref() != Some(payload.proof.presentation_sha256.as_str())
        || report.presentation.identifier.as_deref()
            != Some(payload.proof.presentation_sha256.as_str())
        || chrono::DateTime::parse_from_rfc3339(&report.verified_at).is_err()
    {
        return Err(StorageError::Corrupt);
    }
    Ok(())
}

fn load_artifact_rows(
    connection: &Connection,
    evidence_id: &str,
) -> Result<Vec<ArtifactRow>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT artifact_type, storage_key, sha256, size_bytes
         FROM evidence_artifacts WHERE evidence_id = ?1",
    )?;
    let rows = statement.query_map([evidence_id], |row| {
        Ok(ArtifactRow {
            artifact_type: row.get(0)?,
            storage_key: row.get(1)?,
            sha256: row.get(2)?,
            size_bytes: row.get(3)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StorageError::from)
}

fn validate_evidence_id(evidence_id: &str) -> Result<(), StorageError> {
    if is_evidence_id(evidence_id) {
        Ok(())
    } else {
        Err(StorageError::InvalidEvidenceId)
    }
}

fn is_evidence_id(value: &str) -> bool {
    value.len() == 68
        && value.starts_with("ts1_")
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn ensure_directory(path: &Path) -> Result<(), StorageError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StorageError::UnsafePath);
    }
    set_directory_permissions(path)?;
    Ok(())
}

fn ensure_existing_directory(path: &Path, root: &Path) -> Result<(), StorageError> {
    let metadata = fs::symlink_metadata(path).map_err(map_missing_artifact)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StorageError::UnsafePath);
    }
    let canonical = path.canonicalize()?;
    if !canonical.starts_with(root) {
        return Err(StorageError::UnsafePath);
    }
    Ok(())
}

fn ensure_existing_file(path: &Path, root: &Path) -> Result<u64, StorageError> {
    let metadata = fs::symlink_metadata(path).map_err(map_missing_artifact)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StorageError::UnsafePath);
    }
    let canonical = path.canonicalize()?;
    if !canonical.starts_with(root) {
        return Err(StorageError::UnsafePath);
    }
    Ok(metadata.len())
}

fn map_missing_artifact(error: std::io::Error) -> StorageError {
    if error.kind() == std::io::ErrorKind::NotFound {
        StorageError::Corrupt
    } else {
        StorageError::Io(error)
    }
}

fn reject_symlink_if_present(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(StorageError::UnsafePath),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(StorageError::Io(error)),
    }
}

fn write_new(path: PathBuf, bytes: &[u8]) -> Result<(), StorageError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_private_file_mode(&mut options);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn set_directory_permissions(path: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn set_file_permissions(path: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn set_private_file_mode(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = options;
}

fn sync_directory(path: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    std::fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        engine::tests::{test_verified_evidence, test_verified_evidence_with_report},
        evidence::ArtifactHashes,
    };
    use tempfile::tempdir;

    #[test]
    fn initializes_reopens_and_persists_metadata_and_exact_artifacts() {
        let directory = tempdir().unwrap();
        let verified = test_verified_evidence();
        let store = EvidenceStore::open(directory.path()).unwrap();
        let connection = store.connect().unwrap();
        let database_version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(database_version, DATABASE_VERSION);
        drop(connection);
        let receipt = store.store(&verified).unwrap();
        assert_eq!(receipt.disposition, StoreDisposition::Stored);
        assert_eq!(receipt.evidence_id, verified.record().evidence_id());
        assert_eq!(receipt.commitment, verified.record().commitment());

        let reopened = EvidenceStore::open(directory.path()).unwrap();
        let metadata = reopened.get_metadata(&receipt.evidence_id).unwrap();
        assert_eq!(metadata.record, *verified.record());
        let stored = reopened.get(&receipt.evidence_id).unwrap();
        let (attestation, presentation, request_manifest) = verified.artifacts();
        assert_eq!(stored.artifacts.attestation, attestation);
        assert_eq!(stored.artifacts.presentation, presentation);
        assert_eq!(stored.artifacts.request_manifest, request_manifest);
        assert_eq!(
            ArtifactHashes::from_bytes(
                &stored.artifacts.attestation,
                &stored.artifacts.presentation,
                &stored.artifacts.request_manifest,
            ),
            ArtifactHashes::from_bytes(attestation, presentation, request_manifest)
        );
    }

    #[test]
    fn identical_submission_is_idempotent_without_overwrite() {
        let directory = tempdir().unwrap();
        let verified = test_verified_evidence();
        let store = EvidenceStore::open(directory.path()).unwrap();
        let first = store.store(&verified).unwrap();
        let original = store.get(&first.evidence_id).unwrap();
        let duplicate = store.store(&verified).unwrap();

        assert_eq!(duplicate.disposition, StoreDisposition::AlreadyPresent);
        assert_eq!(store.get(&first.evidence_id).unwrap(), original);
    }

    #[test]
    fn duplicate_verification_reports_are_rejected_and_original_is_immutable() {
        let directory = tempdir().unwrap();
        let original = test_verified_evidence();
        let store = EvidenceStore::open(directory.path()).unwrap();
        let receipt = store.store(&original).unwrap();
        let reverified = test_verified_evidence();
        assert!(matches!(
            store.record_reverification(reverified),
            Err(StorageError::Conflict)
        ));

        let metadata = store.get_metadata(&receipt.evidence_id).unwrap();
        assert_eq!(
            metadata.original_verification.verified_at,
            "2026-11-06T01:57:09.859Z"
        );
        assert!(metadata.reverifications.is_empty());
        let connection = store.connect().unwrap();
        assert!(connection
            .execute(
                "UPDATE verification_records SET verified_at = 'changed'
                 WHERE evidence_id = ?1 AND record_kind = 'ORIGINAL'",
                [&receipt.evidence_id],
            )
            .is_err());
        assert!(connection
            .execute(
                "DELETE FROM verification_records
                 WHERE evidence_id = ?1 AND record_kind = 'ORIGINAL'",
                [&receipt.evidence_id],
            )
            .is_err());
    }

    #[test]
    fn metadata_and_artifact_corruption_are_rejected() {
        let directory = tempdir().unwrap();
        let verified = test_verified_evidence();
        let store = EvidenceStore::open(directory.path()).unwrap();
        let receipt = store.store(&verified).unwrap();
        let artifact = store
            .artifacts_root
            .join(&receipt.evidence_id)
            .join("presentation.tlsn");
        fs::write(&artifact, b"tampered").unwrap();
        assert!(matches!(
            store.get(&receipt.evidence_id),
            Err(StorageError::Corrupt)
        ));

        let connection = store.connect().unwrap();
        connection
            .execute(
                "UPDATE evidence_records SET trust_policy_id = 'forged' WHERE evidence_id = ?1",
                [&receipt.evidence_id],
            )
            .unwrap();
        assert!(matches!(
            store.get_metadata(&receipt.evidence_id),
            Err(StorageError::Corrupt)
        ));
    }

    #[test]
    fn missing_artifacts_and_untrusted_paths_fail_closed() {
        let directory = tempdir().unwrap();
        let verified = test_verified_evidence();
        let store = EvidenceStore::open(directory.path()).unwrap();
        let receipt = store.store(&verified).unwrap();
        fs::remove_file(
            store
                .artifacts_root
                .join(&receipt.evidence_id)
                .join("request.json"),
        )
        .unwrap();
        assert!(store.get(&receipt.evidence_id).is_err());
        assert!(matches!(
            store.get("../outside"),
            Err(StorageError::InvalidEvidenceId)
        ));
        assert!(matches!(
            store.get("ts1_0000000000000000000000000000000000000000000000000000000000000000"),
            Err(StorageError::NotFound)
        ));
    }

    #[test]
    fn database_storage_keys_cannot_redirect_artifact_reads() {
        let directory = tempdir().unwrap();
        let verified = test_verified_evidence();
        let store = EvidenceStore::open(directory.path()).unwrap();
        let receipt = store.store(&verified).unwrap();
        let connection = store.connect().unwrap();
        connection
            .execute(
                "UPDATE evidence_artifacts SET storage_key = '../../outside'
                 WHERE evidence_id = ?1 AND artifact_type = 'attestation'",
                [&receipt.evidence_id],
            )
            .unwrap();
        assert!(matches!(
            store.get(&receipt.evidence_id),
            Err(StorageError::Corrupt)
        ));
    }

    #[test]
    fn foreign_keys_are_enforced_and_orphans_are_reconciled_safely() {
        let directory = tempdir().unwrap();
        let store = EvidenceStore::open(directory.path()).unwrap();
        let connection = store.connect().unwrap();
        let insertion = connection.execute(
            "INSERT INTO evidence_artifacts
                (evidence_id, artifact_type, storage_key, sha256, size_bytes)
             VALUES ('ts1_0000000000000000000000000000000000000000000000000000000000000000',
                     'attestation', 'orphan/attestation.tlsn', '00', 0)",
            [],
        );
        assert!(insertion.is_err());
        drop(connection);

        let verified = test_verified_evidence();
        let receipt = store.store(&verified).unwrap();
        let orphan_id = "ts1_0000000000000000000000000000000000000000000000000000000000000000";
        fs::create_dir(store.artifacts_root.join(orphan_id)).unwrap();
        fs::create_dir(store.staging_root.join("ingest-interrupted")).unwrap();
        fs::write(
            store
                .staging_root
                .join("ingest-interrupted")
                .join("partial"),
            b"partial",
        )
        .unwrap();

        let reopened = EvidenceStore::open(directory.path()).unwrap();
        assert!(!reopened.artifacts_root.join(orphan_id).exists());
        assert!(!reopened.staging_root.join("ingest-interrupted").exists());
        assert!(reopened.get(&receipt.evidence_id).is_ok());
    }

    #[test]
    fn conflicting_existing_identity_is_never_overwritten() {
        let directory = tempdir().unwrap();
        let verified = test_verified_evidence();
        let store = EvidenceStore::open(directory.path()).unwrap();
        let receipt = store.store(&verified).unwrap();
        let connection = store.connect().unwrap();
        connection
            .execute(
                "UPDATE evidence_records SET commitment = 'sha256:conflict' WHERE evidence_id = ?1",
                [&receipt.evidence_id],
            )
            .unwrap();
        assert!(matches!(
            store.store(&verified),
            Err(StorageError::Conflict)
        ));
    }

    #[test]
    fn symlinked_artifacts_are_rejected_where_supported() {
        let directory = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let verified = test_verified_evidence();
        let store = EvidenceStore::open(directory.path()).unwrap();
        let receipt = store.store(&verified).unwrap();
        let artifact_dir = store.artifacts_root.join(&receipt.evidence_id);
        let artifact = artifact_dir.join("attestation.tlsn");
        let original = fs::read(&artifact).unwrap();
        fs::remove_file(&artifact).unwrap();
        let external_file = outside.path().join("outside.bin");
        fs::write(&external_file, original).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&external_file, &artifact).unwrap();
        #[cfg(windows)]
        if std::os::windows::fs::symlink_file(&external_file, &artifact).is_err() {
            return;
        }
        assert!(matches!(
            store.get(&receipt.evidence_id),
            Err(StorageError::UnsafePath)
        ));
    }

    #[test]
    fn concurrent_duplicate_stores_do_not_overwrite_artifacts() {
        let directory = tempdir().unwrap();
        let store = EvidenceStore::open(directory.path()).unwrap();
        let verified = test_verified_evidence();
        let first_store = store.clone();
        let second_store = store.clone();
        let first = std::thread::spawn(move || first_store.store(&verified).unwrap());
        let second = std::thread::spawn(move || {
            let verified = test_verified_evidence();
            second_store.store(&verified).unwrap()
        });
        let results = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(
            results
                .iter()
                .filter(|result| result.disposition == StoreDisposition::Stored)
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| result.disposition == StoreDisposition::AlreadyPresent)
                .count(),
            1
        );
        assert!(store.get(&results[0].evidence_id).is_ok());
    }

    #[test]
    fn startup_recovery_waits_for_active_store_and_preserves_its_evidence() {
        let directory = tempdir().unwrap();
        let root = directory.path().to_path_buf();
        let store = EvidenceStore::open(&root).unwrap();
        let verified = test_verified_evidence();
        let (staged_tx, staged_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            store
                .store_with_stage_hook(&verified, || {
                    staged_tx.send(()).unwrap();
                    resume_rx.recv().unwrap();
                })
                .unwrap()
        });
        staged_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("writer should stage bytes while holding the SQLite write lock");
        let staging_entries = fs::read_dir(root.join(".staging"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(staging_entries.len(), 1);
        assert!(staging_entries[0].is_dir());

        let (opened_tx, opened_rx) = std::sync::mpsc::channel();
        let recovery_root = root.clone();
        let recovery = std::thread::spawn(move || {
            opened_tx.send(EvidenceStore::open(recovery_root)).unwrap();
        });
        std::thread::sleep(Duration::from_millis(100));
        assert!(matches!(
            opened_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert!(staging_entries[0].exists());

        resume_tx.send(()).unwrap();
        let receipt = writer.join().unwrap();
        let recovered = opened_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("recovery should continue after the store commits")
            .unwrap();
        recovery.join().unwrap();
        assert!(recovered.get(&receipt.evidence_id).is_ok());
        assert!(fs::read_dir(root.join(".staging"))
            .unwrap()
            .next()
            .is_none());
    }

    #[test]
    fn rejected_and_nonzero_exit_reports_cannot_be_recorded_and_preserve_history() {
        let directory = tempdir().unwrap();
        let store = EvidenceStore::open(directory.path()).unwrap();
        let valid = test_verified_evidence();
        let receipt = store.store(&valid).unwrap();

        // 1. A REJECTED verification report cannot be stored initially
        let rejected_initial = test_verified_evidence_with_report(|r| {
            r.verification_status = "REJECTED".into();
        });
        assert!(matches!(
            store.store(&rejected_initial),
            Err(StorageError::Corrupt)
        ));

        // 2. A verification report with a non-zero exit code cannot be stored initially
        let nonzero_initial = test_verified_evidence_with_report(|r| {
            r.verifier.exit_code = Some(1);
        });
        assert!(matches!(
            store.store(&nonzero_initial),
            Err(StorageError::Corrupt)
        ));

        // 3. A REJECTED verification report cannot be recorded as a re-verification
        let rejected_reverify = test_verified_evidence_with_report(|r| {
            r.verification_status = "REJECTED".into();
            r.verified_at = "2026-11-06T02:00:00.000Z".into();
        });
        assert!(matches!(
            store.record_reverification(rejected_reverify),
            Err(StorageError::Corrupt)
        ));

        // 4. A verification report with a non-zero exit code cannot be recorded as a re-verification
        let nonzero_reverify = test_verified_evidence_with_report(|r| {
            r.verifier.exit_code = Some(1);
            r.verified_at = "2026-11-06T02:01:00.000Z".into();
        });
        assert!(matches!(
            store.record_reverification(nonzero_reverify),
            Err(StorageError::Corrupt)
        ));

        // 5. A verification report with errors cannot be recorded as a re-verification
        let with_errors = test_verified_evidence_with_report(|r| {
            r.errors = vec!["verifier reported an error".into()];
            r.verified_at = "2026-11-06T02:02:00.000Z".into();
        });
        assert!(matches!(
            store.record_reverification(with_errors),
            Err(StorageError::Corrupt)
        ));

        // 6. Failed re-verification does not modify existing verification history
        let metadata = store.get_metadata(&receipt.evidence_id).unwrap();
        assert_eq!(
            metadata.original_verification.verified_at,
            "2026-11-06T01:57:09.859Z"
        );
        assert_eq!(
            metadata.original_verification.verification_status,
            "VERIFIED"
        );
        assert_eq!(metadata.original_verification.verifier.exit_code, Some(0));
        assert!(metadata.reverifications.is_empty());

        let connection = store.connect().unwrap();
        let total_verifications: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM verification_records WHERE evidence_id = ?1",
                [&receipt.evidence_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(total_verifications, 1);
    }
}
