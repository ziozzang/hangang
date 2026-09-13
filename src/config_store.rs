//! Durable whole-configuration storage with optimistic revision arbitration.
//!
//! Stores assign revisions. Callers validate and prepare runtime resources
//! before CAS, then publish only the exact `Config` returned by `Applied`.
//!
//! Every durable document belongs to an *authority epoch*: a random
//! identifier created exactly once, by the bootstrap that inserts the first
//! document, and never changed by CAS. A store that is wiped and bootstrapped
//! again receives a new epoch, so instances holding the old history detect the
//! replacement instead of comparing revisions across unrelated histories.
//! A backup restored under the same bootstrap keeps its epoch, so within an
//! epoch the revision moves forward only between restores: an earlier
//! revision can come back. Legacy documents without an epoch are upgraded in
//! place exactly once when they are first read; concurrent upgraders converge
//! on one winner.
//!
//! The CAS is idempotent: a repeated identical write whose acknowledgement was
//! lost is reported as `Applied`, not as a conflict. When a store had to retry
//! an unacknowledged write, only its own document at the assigned revision
//! proves the outcome; every other durable state (the expected revision
//! itself included, since a restore can bring it back) is reported as
//! `StoreError::Indeterminate` instead of guessed. A bootstrap that retried
//! an unacknowledged insert likewise trusts only the document its follow-up
//! read finds; an empty or unreadable store afterwards is `Indeterminate`.
use crate::{
    config::{Config, Snapshot},
    store,
};
use anyhow::{Context, Result, anyhow, ensure};
use async_trait::async_trait;
use rusqlite::OptionalExtension;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub(crate) const MAX_CONFIG_BYTES: usize = store::MAX_CONFIG_BYTES;
/// Length of an authority epoch: 128 random bits as lowercase hex.
pub const EPOCH_LEN: usize = 32;
/// Retained SQL receipts are bounded; a full history refuses new operation CAS.
pub const COMMIT_RECEIPT_CAPACITY: u64 = 100_000;
pub const COMMIT_AUTHORITY_CAPACITY: u64 = 4_096;
pub const MAX_ACCEPTANCE_SEQUENCE: u64 = 9_007_199_254_740_991;
/// ACME HTTP-01 token limits shared by every store.
pub const MAX_CHALLENGE_TOKEN_LEN: usize = 128;
pub const MAX_KEY_AUTHORIZATION_LEN: usize = 512;
pub const MIN_CHALLENGE_TTL: Duration = Duration::from_secs(1);
pub const MAX_CHALLENGE_TTL: Duration = Duration::from_secs(60 * 60);

/// One durable snapshot: the authority incarnation it belongs to plus the
/// document.
#[derive(Debug, Clone, PartialEq)]
pub struct Stored {
    pub epoch: String,
    pub config: Config,
}

/// Opaque identity accepted by the local account authority for one candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationStamp {
    pub authority_id: String,
    pub operation_id: String,
    pub candidate_sha256: String,
}

/// Identity present on the current authoritative configuration document only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationProof {
    pub epoch: String,
    pub revision: u64,
    pub stamp: OperationStamp,
}

/// Evidence that one operation committed at a revision. It does not imply
/// that the candidate is still the current document or active on this node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommitReceipt {
    pub epoch: String,
    pub revision: u64,
    pub stamp: OperationStamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommitReceiptObservation {
    pub receipt: Option<CommitReceipt>,
    pub stored_records: u64,
    pub capacity: u64,
    pub writes_available: bool,
}

/// A locally accepted operation, bound to its never-reused local sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SequencedOperationStamp {
    pub authority_id: String,
    pub acceptance_seq: u64,
    pub operation_id: String,
    pub candidate_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SequencedCommitReceipt {
    pub epoch: String,
    pub revision: u64,
    pub stamp: SequencedOperationStamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SequencedReceiptObservation {
    pub receipt: Option<SequencedCommitReceipt>,
    pub high_water: u64,
    pub stored_records: u64,
    pub capacity: u64,
    pub registered_authorities: u64,
    pub authority_capacity: u64,
    pub writes_available: bool,
}

/// A stable prefix of one authority's sequenced receipts. New receipts may
/// advance the live high-water mark without changing this export boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SequencedReceiptSnapshot {
    pub high_water: u64,
    /// Changes on future explicit retention, never on ordinary append.
    pub retention_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SequencedReceiptPage {
    pub receipts: Vec<SequencedCommitReceipt>,
    pub snapshot: SequencedReceiptSnapshot,
    pub next_after: u64,
    pub has_more: bool,
}

/// A valid export cursor became stale because retained history changed or
/// the authority high-water mark moved backwards (for example, a restore).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SequencedReceiptPageResult {
    Page(SequencedReceiptPage),
    SnapshotChanged,
}

/// Why a store operation failed. Callers use the distinction for readiness
/// policy: a transport failure leaves the local snapshot valid, invalid
/// content does not, and an indeterminate mutation must be re-read.
#[derive(Debug)]
pub enum StoreError {
    /// Store unreachable / timed out before the request was durably
    /// processed. Nothing changed.
    Unavailable(anyhow::Error),
    /// Durable content is unreadable or violates limits (schema, JSON, size,
    /// negative revision).
    Invalid(anyhow::Error),
    /// A mutation was sent but its outcome is unknown: the acknowledgement
    /// was lost and the retry failed too, or the durable state seen afterwards
    /// no longer proves whether the write was applied.
    Indeterminate(anyhow::Error),
}

impl StoreError {
    /// `true` when the store, not its content, failed.
    pub fn is_transport(&self) -> bool {
        matches!(self, Self::Unavailable(_) | Self::Indeterminate(_))
    }

    pub fn inner(&self) -> &anyhow::Error {
        match self {
            Self::Unavailable(error) | Self::Invalid(error) | Self::Indeterminate(error) => error,
        }
    }

    pub fn into_inner(self) -> anyhow::Error {
        match self {
            Self::Unavailable(error) | Self::Invalid(error) | Self::Indeterminate(error) => error,
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(error) => write!(f, "store unavailable: {error:#}"),
            Self::Invalid(error) => write!(f, "store content invalid: {error:#}"),
            Self::Indeterminate(error) => write!(f, "store mutation indeterminate: {error:#}"),
        }
    }
}

impl std::error::Error for StoreError {}

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Debug, Clone, PartialEq)]
pub enum CasResult {
    Applied(Stored),
    Conflict { current: Stored },
}

/// The access kind of a failed request decides how a transport failure is
/// typed: a read that failed changed nothing, a mutation whose reply never
/// arrived may have been applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    Read,
    Mutation,
}

impl Access {
    pub(crate) fn transport(self, error: anyhow::Error) -> StoreError {
        match self {
            Self::Read => StoreError::Unavailable(error),
            Self::Mutation => StoreError::Indeterminate(error),
        }
    }
}

#[async_trait]
pub trait ConfigStore: Send + Sync {
    async fn load_latest(&self) -> StoreResult<Option<Stored>>;
    /// Insert `initial` only when the store is empty and return the winning
    /// snapshot; the insert creates the authority epoch. Repeated and
    /// concurrent calls are idempotent. A store that retried an
    /// unacknowledged insert returns the document its follow-up read finds
    /// and `StoreError::Indeterminate` when that read fails or finds the
    /// store empty: the seed may have been the shared authority before the
    /// store was wiped, so neither outcome proves "nothing changed".
    async fn bootstrap(&self, initial: Config) -> StoreResult<Stored>;
    /// Assign `expected + 1` and replace the whole snapshot only when the
    /// durable state is (`epoch`, `expected`). When the durable state is
    /// already (`epoch`, `expected + 1`) with exactly this document, the write
    /// is our own whose acknowledgement was lost and `Applied` is returned
    /// again. Anything else is a `Conflict` carrying the durable state, so an
    /// epoch mismatch is visible as `current.epoch != epoch`. A store that
    /// retried an unacknowledged write reports `Applied` only for (`epoch`,
    /// `expected + 1`, this document) and `StoreError::Indeterminate` for
    /// every other durable state — (`epoch`, `expected`) and another document
    /// at `expected + 1` included, because a backup restored under the same
    /// epoch can bring them back after the write committed — and for a
    /// failed re-read.
    async fn compare_and_swap(
        &self,
        epoch: &str,
        expected: u64,
        next: Config,
    ) -> StoreResult<CasResult>;
    fn supports_operation_cas(&self) -> bool {
        false
    }
    async fn compare_and_swap_operation(
        &self,
        _epoch: &str,
        _expected: u64,
        _next: Config,
        _stamp: OperationStamp,
    ) -> StoreResult<CasResult> {
        Err(StoreError::Invalid(anyhow!(
            "operation-specific CAS is unsupported by this store"
        )))
    }
    async fn load_current_operation_proof(&self) -> StoreResult<Option<OperationProof>> {
        Err(StoreError::Invalid(anyhow!(
            "operation-specific proof is unsupported by this store"
        )))
    }
    fn supports_commit_receipts(&self) -> bool {
        false
    }
    async fn lookup_commit_receipt(
        &self,
        _authority_id: &str,
        _operation_id: &str,
    ) -> StoreResult<CommitReceiptObservation> {
        Err(StoreError::Invalid(anyhow!(
            "retained commit receipts are unsupported by this store"
        )))
    }
    fn supports_sequenced_operation_cas(&self) -> bool {
        false
    }
    async fn compare_and_swap_operation_v2(
        &self,
        _epoch: &str,
        _expected: u64,
        _next: Config,
        _stamp: SequencedOperationStamp,
    ) -> StoreResult<CasResult> {
        Err(StoreError::Invalid(anyhow!(
            "sequenced operation CAS is unsupported by this store"
        )))
    }
    async fn lookup_commit_receipt_v2(
        &self,
        _authority_id: &str,
        _acceptance_seq: u64,
    ) -> StoreResult<SequencedReceiptObservation> {
        Err(StoreError::Invalid(anyhow!(
            "sequenced commit receipts are unsupported by this store"
        )))
    }
    async fn list_commit_receipts_v2(
        &self,
        _authority_id: &str,
        _after_seq: u64,
        _snapshot: Option<SequencedReceiptSnapshot>,
        _limit: usize,
    ) -> StoreResult<SequencedReceiptPageResult> {
        Err(StoreError::Invalid(anyhow!(
            "sequenced receipt export is unsupported by this store"
        )))
    }
    /// ACME HTTP-01 sharing: every instance behind a load balancer can answer
    /// the CA's validation request. `token`: 1..=128 chars of `[A-Za-z0-9_-]`;
    /// `key_authorization`: 1..=512 printable ASCII; `ttl`: 1 s..=1 h.
    /// Violations return `StoreError::Invalid` without touching the store.
    async fn publish_challenge(
        &self,
        token: &str,
        key_authorization: &str,
        ttl: Duration,
    ) -> StoreResult<()>;
    /// `None` when the token is absent or expired.
    async fn lookup_challenge(&self, token: &str) -> StoreResult<Option<String>>;
    async fn withdraw_challenge(&self, token: &str) -> StoreResult<()>;
}

/// The snapshot startup publishes plus the authority epoch it belongs to.
pub struct PreparedBootstrap {
    pub snapshot: Snapshot,
    pub epoch: String,
}

/// Bootstrap `seed` only after its runtime resources (certificate material,
/// upstream TLS, host patterns) have been prepared, so a seed that this
/// instance cannot serve never becomes the shared authority for every
/// instance. When another instance won the bootstrap, its committed snapshot
/// is prepared instead. The returned snapshot is the one startup should
/// publish; callers validate Lua separately before calling this.
pub async fn bootstrap_prepared(
    store: &dyn ConfigStore,
    seed: Config,
) -> StoreResult<PreparedBootstrap> {
    let prepared = prepare_snapshot(seed, "prepare seed configuration before bootstrap").await?;
    let committed = store.bootstrap(prepared.config.clone()).await?;
    if committed.config == prepared.config {
        return Ok(PreparedBootstrap {
            snapshot: prepared,
            epoch: committed.epoch,
        });
    }
    let Stored { epoch, config } = committed;
    let snapshot = prepare_snapshot(
        config,
        "prepare shared configuration bootstrapped by another instance",
    )
    .await?;
    Ok(PreparedBootstrap { snapshot, epoch })
}

async fn prepare_snapshot(config: Config, context: &'static str) -> StoreResult<Snapshot> {
    ensure_reader_compatibility(&config)?;
    match tokio::task::spawn_blocking(move || Snapshot::new(config)).await {
        Ok(Ok(snapshot)) => Ok(snapshot),
        Ok(Err(error)) => Err(StoreError::Invalid(error.context(context))),
        Err(error) => Err(StoreError::Invalid(anyhow!(error).context(context))),
    }
}

/// A fresh authority epoch from the process CSPRNG.
pub(crate) fn new_epoch() -> StoreResult<String> {
    let mut bytes = [0u8; EPOCH_LEN / 2];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| StoreError::Unavailable(anyhow!("generate authority epoch: no entropy")))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Accept only the canonical form so a corrupted column is never mistaken for
/// a legitimate authority.
pub(crate) fn check_epoch(epoch: &str) -> StoreResult<()> {
    let canonical = epoch.len() == EPOCH_LEN
        && epoch
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if canonical {
        Ok(())
    } else {
        Err(StoreError::Invalid(anyhow!(
            "stored authority epoch is not {EPOCH_LEN} lowercase hex characters"
        )))
    }
}

/// The idempotency rule shared by every store, applied to the durable state
/// after a guarded update changed nothing. `next` already carries
/// `expected + 1`, so an equal document implies the expected revision.
pub(crate) fn resolve_cas(current: Stored, epoch: &str, next: &Config) -> CasResult {
    if current.epoch == epoch && current.config == *next {
        CasResult::Applied(current)
    } else {
        CasResult::Conflict { current }
    }
}

#[derive(Debug, Clone)]
struct OperationMetadata {
    revision: u64,
    stamp: OperationStamp,
    version: u8,
    sequence: Option<u64>,
}

fn valid_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Opaque correlation ID with an injective sequence prefix. The suffix is a
/// checksum, not an authentication code or a credential.
pub fn canonical_operation_id(authority_id: &str, seq: u64) -> StoreResult<String> {
    if !valid_hex(authority_id, 32) || !(1..=MAX_ACCEPTANCE_SEQUENCE).contains(&seq) {
        return Err(StoreError::Invalid(anyhow!(
            "invalid sequenced operation identity"
        )));
    }
    let mut authority = [0u8; 16];
    for (index, byte) in authority.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&authority_id[index * 2..index * 2 + 2], 16)
            .map_err(|_| StoreError::Invalid(anyhow!("invalid sequenced operation identity")))?;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"hangang-op-v2");
    hasher.update(authority);
    hasher.update(seq.to_be_bytes());
    let digest = hasher.finalize();
    let mut id = format!("{seq:016x}");
    for byte in &digest[..8] {
        use std::fmt::Write;
        write!(&mut id, "{byte:02x}").expect("String write is infallible");
    }
    Ok(id)
}

fn validate_sequenced_stamp(stamp: &SequencedOperationStamp, encoded: &str) -> StoreResult<()> {
    if stamp.operation_id != canonical_operation_id(&stamp.authority_id, stamp.acceptance_seq)?
        || !valid_hex(&stamp.candidate_sha256, 64)
        || stamp.candidate_sha256 != sha256_hex(encoded.as_bytes())
    {
        return Err(StoreError::Invalid(anyhow!(
            "invalid sequenced operation stamp"
        )));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_operation_stamp(stamp: &OperationStamp, encoded: &str) -> StoreResult<()> {
    if !valid_hex(&stamp.authority_id, 32)
        || !valid_hex(&stamp.operation_id, 32)
        || !valid_hex(&stamp.candidate_sha256, 64)
        || stamp.candidate_sha256 != sha256_hex(encoded.as_bytes())
    {
        return Err(StoreError::Invalid(anyhow!(
            "invalid operation stamp or candidate fingerprint"
        )));
    }
    Ok(())
}

fn validate_receipt_ids(authority_id: &str, operation_id: &str) -> StoreResult<()> {
    if valid_hex(authority_id, 32) && valid_hex(operation_id, 32) {
        Ok(())
    } else {
        Err(StoreError::Invalid(anyhow!(
            "invalid commit receipt identity"
        )))
    }
}

fn commit_receipt(
    authority_id: String,
    operation_id: String,
    epoch: String,
    revision: i64,
    candidate_sha256: String,
) -> StoreResult<CommitReceipt> {
    validate_receipt_ids(&authority_id, &operation_id)?;
    check_epoch(&epoch)?;
    let revision = i64_to_revision(revision)?;
    if revision == 0 || !valid_hex(&candidate_sha256, 64) {
        return Err(StoreError::Invalid(anyhow!(
            "invalid stored commit receipt"
        )));
    }
    Ok(CommitReceipt {
        epoch,
        revision,
        stamp: OperationStamp {
            authority_id,
            operation_id,
            candidate_sha256,
        },
    })
}

fn receipt_observation(
    receipt: Option<CommitReceipt>,
    stored_records: i64,
) -> StoreResult<CommitReceiptObservation> {
    let stored_records = u64::try_from(stored_records)
        .map_err(|_| StoreError::Invalid(anyhow!("invalid commit receipt count")))?;
    if stored_records > COMMIT_RECEIPT_CAPACITY || (receipt.is_some() && stored_records == 0) {
        return Err(StoreError::Invalid(anyhow!("invalid commit receipt count")));
    }
    Ok(CommitReceiptObservation {
        receipt,
        stored_records,
        capacity: COMMIT_RECEIPT_CAPACITY,
        writes_available: stored_records < COMMIT_RECEIPT_CAPACITY,
    })
}

fn sequenced_receipt(
    authority_id: String,
    acceptance_seq: i64,
    operation_id: String,
    epoch: String,
    revision: i64,
    candidate_sha256: String,
) -> StoreResult<SequencedCommitReceipt> {
    let seq = u64::try_from(acceptance_seq)
        .map_err(|_| StoreError::Invalid(anyhow!("invalid sequenced receipt")))?;
    if operation_id != canonical_operation_id(&authority_id, seq)?
        || !valid_hex(&candidate_sha256, 64)
    {
        return Err(StoreError::Invalid(anyhow!("invalid sequenced receipt")));
    }
    check_epoch(&epoch)?;
    let revision = i64_to_revision(revision)?;
    if revision == 0 {
        return Err(StoreError::Invalid(anyhow!("invalid sequenced receipt")));
    }
    Ok(SequencedCommitReceipt {
        epoch,
        revision,
        stamp: SequencedOperationStamp {
            authority_id,
            acceptance_seq: seq,
            operation_id,
            candidate_sha256,
        },
    })
}

fn sequenced_observation(
    receipt: Option<SequencedCommitReceipt>,
    high_water: Option<i64>,
    stored_records: i64,
    registered_authorities: i64,
) -> StoreResult<SequencedReceiptObservation> {
    let count = u64::try_from(stored_records)
        .map_err(|_| StoreError::Invalid(anyhow!("invalid receipt count")))?;
    let authorities = u64::try_from(registered_authorities)
        .map_err(|_| StoreError::Invalid(anyhow!("invalid authority count")))?;
    let high_water = u64::try_from(high_water.unwrap_or(0))
        .map_err(|_| StoreError::Invalid(anyhow!("invalid authority high water")))?;
    if count > COMMIT_RECEIPT_CAPACITY
        || authorities > COMMIT_AUTHORITY_CAPACITY
        || high_water > MAX_ACCEPTANCE_SEQUENCE
        || (receipt.is_some() && count == 0)
        || (high_water > 0 && authorities == 0)
        || receipt
            .as_ref()
            .is_some_and(|entry| entry.stamp.acceptance_seq > high_water)
    {
        return Err(StoreError::Invalid(anyhow!(
            "invalid sequenced receipt metadata"
        )));
    }
    Ok(SequencedReceiptObservation {
        receipt,
        high_water,
        stored_records: count,
        capacity: COMMIT_RECEIPT_CAPACITY,
        registered_authorities: authorities,
        authority_capacity: COMMIT_AUTHORITY_CAPACITY,
        writes_available: count < COMMIT_RECEIPT_CAPACITY
            && (high_water > 0 || authorities < COMMIT_AUTHORITY_CAPACITY),
    })
}

fn decode_operation_metadata(
    authority_id: Option<String>,
    operation_id: Option<String>,
    revision: Option<i64>,
    candidate_sha256: Option<String>,
    version: Option<i64>,
    sequence: Option<i64>,
) -> StoreResult<Option<OperationMetadata>> {
    if authority_id.is_none()
        && operation_id.is_none()
        && revision.is_none()
        && candidate_sha256.is_none()
    {
        return if version.is_none() && sequence.is_none() {
            Ok(None)
        } else {
            Err(StoreError::Invalid(anyhow!(
                "invalid stored operation stamp"
            )))
        };
    }
    let (Some(authority_id), Some(operation_id), Some(revision), Some(candidate_sha256)) =
        (authority_id, operation_id, revision, candidate_sha256)
    else {
        return Err(StoreError::Invalid(anyhow!(
            "invalid stored operation stamp"
        )));
    };
    let revision = i64_to_revision(revision)?;
    let stamp = OperationStamp {
        authority_id,
        operation_id,
        candidate_sha256,
    };
    if !valid_hex(&stamp.authority_id, 32)
        || !valid_hex(&stamp.operation_id, 32)
        || !valid_hex(&stamp.candidate_sha256, 64)
    {
        return Err(StoreError::Invalid(anyhow!(
            "invalid stored operation stamp"
        )));
    }
    let (version, sequence) = match (version, sequence) {
        (None, None) | (Some(1), None) => (1, None),
        (Some(2), Some(seq)) if (1..=MAX_ACCEPTANCE_SEQUENCE as i64).contains(&seq) => {
            let seq = u64::try_from(seq)
                .map_err(|_| StoreError::Invalid(anyhow!("invalid stored operation stamp")))?;
            if stamp.operation_id != canonical_operation_id(&stamp.authority_id, seq)? {
                return Err(StoreError::Invalid(anyhow!(
                    "invalid stored sequenced identity"
                )));
            }
            (2, Some(seq))
        }
        _ => {
            return Err(StoreError::Invalid(anyhow!(
                "invalid stored operation version"
            )));
        }
    };
    Ok(Some(OperationMetadata {
        revision,
        stamp,
        version,
        sequence,
    }))
}

fn current_operation_proof(
    stored: &Stored,
    encoded: &str,
    metadata: &Option<OperationMetadata>,
) -> Option<OperationProof> {
    let metadata = metadata.as_ref()?;
    (metadata.revision == stored.config.revision
        && metadata.stamp.candidate_sha256 == sha256_hex(encoded.as_bytes()))
    .then(|| OperationProof {
        epoch: stored.epoch.clone(),
        revision: metadata.revision,
        stamp: metadata.stamp.clone(),
    })
}

fn current_v1_operation_proof(
    stored: &Stored,
    encoded: &str,
    metadata: &Option<OperationMetadata>,
) -> Option<OperationProof> {
    if !metadata
        .as_ref()
        .is_some_and(|meta| meta.version == 1 && meta.sequence.is_none())
    {
        return None;
    }
    current_operation_proof(stored, encoded, metadata)
}

fn current_sequenced_proof(
    stored: &Stored,
    encoded: &str,
    metadata: &Option<OperationMetadata>,
    stamp: &SequencedOperationStamp,
) -> bool {
    metadata.as_ref().is_some_and(|meta| {
        meta.version == 2
            && meta.sequence == Some(stamp.acceptance_seq)
            && meta.revision == stored.config.revision
            && meta.stamp.authority_id == stamp.authority_id
            && meta.stamp.operation_id == stamp.operation_id
            && meta.stamp.candidate_sha256 == stamp.candidate_sha256
            && stamp.candidate_sha256 == sha256_hex(encoded.as_bytes())
    })
}

fn resolve_operation_cas(
    current: StoreResult<Option<(Stored, String, Option<OperationMetadata>)>>,
    epoch: &str,
    next: &Config,
    stamp: &OperationStamp,
    uncertain: bool,
) -> StoreResult<CasResult> {
    let (stored, encoded, metadata) = match current {
        Ok(Some(value)) => value,
        Ok(None) if uncertain => {
            return Err(StoreError::Indeterminate(anyhow!(
                "operation CAS outcome is not provable from an empty store"
            )));
        }
        Ok(None) => {
            return Err(StoreError::Invalid(anyhow!(
                "configuration store is not initialized"
            )));
        }
        Err(error) if uncertain => {
            return Err(StoreError::Indeterminate(
                error
                    .into_inner()
                    .context("operation CAS recovery read failed"),
            ));
        }
        Err(error) => return Err(error),
    };
    let proof = current_v1_operation_proof(&stored, &encoded, &metadata);
    if metadata
        .as_ref()
        .is_some_and(|current| current.stamp.operation_id == stamp.operation_id)
    {
        if stored.epoch == epoch
            && stored.config == *next
            && proof.as_ref().is_some_and(|proof| proof.stamp == *stamp)
        {
            return Ok(CasResult::Applied(stored));
        }
        if uncertain {
            return Err(StoreError::Indeterminate(anyhow!(
                "operation CAS acknowledgement was lost and the current document cannot prove the same operation"
            )));
        }
        return Err(StoreError::Invalid(anyhow!(
            "operation identifier reused with another candidate or precondition"
        )));
    }
    if uncertain {
        return Err(StoreError::Indeterminate(anyhow!(
            "operation CAS acknowledgement was lost and the current document has no matching operation identity"
        )));
    }
    Ok(CasResult::Conflict { current: stored })
}

fn receipt_recovery_read<T>(read: StoreResult<T>, uncertain: bool) -> StoreResult<T> {
    match read {
        Err(error) if uncertain => Err(StoreError::Indeterminate(
            error
                .into_inner()
                .context("operation CAS recovery current read failed"),
        )),
        result => result,
    }
}

pub(crate) fn check_challenge_token(token: &str) -> StoreResult<()> {
    let valid = !token.is_empty()
        && token.len() <= MAX_CHALLENGE_TOKEN_LEN
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(StoreError::Invalid(anyhow!(
            "ACME challenge token must be 1..={MAX_CHALLENGE_TOKEN_LEN} characters of [A-Za-z0-9_-]"
        )))
    }
}

pub(crate) fn check_challenge(
    token: &str,
    key_authorization: &str,
    ttl: Duration,
) -> StoreResult<()> {
    check_challenge_token(token)?;
    let printable = !key_authorization.is_empty()
        && key_authorization.len() <= MAX_KEY_AUTHORIZATION_LEN
        && key_authorization
            .bytes()
            .all(|byte| (0x20..=0x7e).contains(&byte));
    if !printable {
        return Err(StoreError::Invalid(anyhow!(
            "ACME key authorization must be 1..={MAX_KEY_AUTHORIZATION_LEN} printable ASCII characters"
        )));
    }
    if ttl < MIN_CHALLENGE_TTL || ttl > MAX_CHALLENGE_TTL {
        return Err(StoreError::Invalid(anyhow!(
            "ACME challenge ttl must be between 1 second and 1 hour"
        )));
    }
    Ok(())
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Expiry rounded up to whole seconds so a short ttl never expires early.
pub(crate) fn challenge_expiry(ttl: Duration) -> i64 {
    let seconds = i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX);
    unix_now().saturating_add(seconds).saturating_add(1)
}

/// Test helper store on one JSON file. The authority epoch lives in a
/// `<path>.epoch` sidecar and challenges in `<path>.challenges`, so a file
/// written by `store::save` (without an epoch) is treated as legacy data.
pub struct FileConfigStore {
    path: PathBuf,
    writes: tokio::sync::Mutex<()>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct FileChallenge {
    key_authorization: String,
    expires_unix: i64,
}

impl FileConfigStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            writes: tokio::sync::Mutex::new(()),
        }
    }

    fn sidecar(&self, suffix: &str) -> PathBuf {
        let mut path = self.path.clone().into_os_string();
        path.push(suffix);
        PathBuf::from(path)
    }

    fn epoch_path(&self) -> PathBuf {
        self.sidecar(".epoch")
    }

    fn challenges_path(&self) -> PathBuf {
        self.sidecar(".challenges")
    }

    async fn read_challenges(&self) -> StoreResult<BTreeMap<String, FileChallenge>> {
        let path = self.challenges_path();
        blocking(Access::Read, move || match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| StoreError::Invalid(anyhow!(error).context("decode challenges"))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(error) => Err(StoreError::Unavailable(
                anyhow!(error).context("read challenges"),
            )),
        })
        .await
    }

    async fn write_challenges(
        &self,
        challenges: BTreeMap<String, FileChallenge>,
    ) -> StoreResult<()> {
        let path = self.challenges_path();
        blocking(Access::Mutation, move || {
            let bytes = serde_json::to_vec(&challenges).map_err(|error| {
                StoreError::Invalid(anyhow!(error).context("encode challenges"))
            })?;
            write_atomically(&path, &bytes)
                .map_err(|error| StoreError::Unavailable(error.context("write challenges")))
        })
        .await
    }
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    Ok(())
}

/// Read the sidecar epoch, creating it exactly once for a legacy file. The
/// candidate is complete and synced before an atomic hard link makes it
/// visible; a competing reader can never observe a newly-created empty file.
fn file_epoch(path: &Path) -> StoreResult<String> {
    loop {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        match options.open(path) {
            Ok(mut file) => {
                if !file
                    .metadata()
                    .map_err(|error| {
                        StoreError::Unavailable(anyhow!(error).context("inspect authority epoch"))
                    })?
                    .is_file()
                {
                    return Err(StoreError::Invalid(anyhow!(
                        "authority epoch path is not a regular file"
                    )));
                }
                let mut bytes = Vec::new();
                Read::by_ref(&mut file)
                    .take(EPOCH_LEN as u64 + 3)
                    .read_to_end(&mut bytes)
                    .map_err(|error| {
                        StoreError::Unavailable(anyhow!(error).context("read authority epoch"))
                    })?;
                if bytes.len() > EPOCH_LEN + 2 {
                    return Err(StoreError::Invalid(anyhow!(
                        "authority epoch sidecar exceeds {} bytes",
                        EPOCH_LEN + 2
                    )));
                }
                let existing = std::str::from_utf8(&bytes).map_err(|error| {
                    StoreError::Invalid(anyhow!(error).context("authority epoch is not UTF-8"))
                })?;
                let epoch = existing.trim();
                check_epoch(epoch)?;
                return Ok(epoch.to_owned());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(StoreError::Unavailable(
                    anyhow!(error).context("read authority epoch"),
                ));
            }
        }
        let epoch = new_epoch()?;
        if publish_epoch_if_absent(path, &epoch, || {})? {
            return Ok(epoch);
        }
    }
}

/// Publish a fully-written sidecar without replacing a winning concurrent
/// writer. The callback is only a test synchronization point immediately
/// before publication; production callers pass a no-op.
fn publish_epoch_if_absent(
    path: &Path,
    epoch: &str,
    before_publish: impl FnOnce(),
) -> StoreResult<bool> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        StoreError::Unavailable(anyhow!(error).context("create authority epoch temporary file"))
    })?;
    temporary
        .write_all(epoch.as_bytes())
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|error| {
            StoreError::Unavailable(anyhow!(error).context("write authority epoch temporary file"))
        })?;
    before_publish();
    match std::fs::hard_link(temporary.path(), path) {
        Ok(()) => {
            // The link is the commit point. Report a subsequent directory
            // sync failure without claiming the epoch was not published.
            if let Err(error) =
                std::fs::File::open(parent).and_then(|directory| directory.sync_all())
            {
                tracing::warn!(%error, "authority epoch linked but directory sync failed");
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(StoreError::Unavailable(
            anyhow!(error).context("publish authority epoch"),
        )),
    }
}

async fn blocking<T, F>(access: Access, operation: F) -> StoreResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> StoreResult<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(operation).await {
        Ok(result) => result,
        Err(error) => Err(access.transport(anyhow!(error).context("store worker failed"))),
    }
}

/// File errors from `store::load`/`store::save`: I/O is a transport failure,
/// everything else is content that cannot be used.
fn file_error(error: anyhow::Error, access: Access) -> StoreError {
    if error.chain().any(|cause| cause.is::<std::io::Error>()) {
        access.transport(error)
    } else {
        StoreError::Invalid(error)
    }
}

#[async_trait]
impl ConfigStore for FileConfigStore {
    async fn load_latest(&self) -> StoreResult<Option<Stored>> {
        let path = self.path.clone();
        let epoch_path = self.epoch_path();
        blocking(Access::Read, move || {
            let Some(config) = load_optional(&path)? else {
                return Ok(None);
            };
            ensure_reader_compatibility(&config)?;
            let epoch = file_epoch(&epoch_path)?;
            Ok(Some(Stored { epoch, config }))
        })
        .await
    }

    async fn bootstrap(&self, initial: Config) -> StoreResult<Stored> {
        let _guard = self.writes.lock().await;
        if let Some(current) = self.load_latest().await? {
            return Ok(current);
        }
        encode(&initial)?;
        let epoch = new_epoch()?;
        let epoch_path = self.epoch_path();
        let written = epoch.clone();
        blocking(Access::Mutation, move || {
            write_atomically(&epoch_path, written.as_bytes())
                .map_err(|error| StoreError::Unavailable(error.context("write authority epoch")))
        })
        .await?;
        store::save(self.path.clone(), initial.clone())
            .await
            .map_err(|error| file_error(error, Access::Mutation))?;
        Ok(Stored {
            epoch,
            config: initial,
        })
    }

    async fn compare_and_swap(
        &self,
        epoch: &str,
        expected: u64,
        mut next: Config,
    ) -> StoreResult<CasResult> {
        let _guard = self.writes.lock().await;
        next.revision = next_revision(expected)?;
        let current = self.load_latest().await?.ok_or_else(|| {
            StoreError::Invalid(anyhow!("configuration store is not initialized"))
        })?;
        if current.epoch != epoch || current.config.revision != expected {
            return Ok(resolve_cas(current, epoch, &next));
        }
        encode(&next)?;
        store::save(self.path.clone(), next.clone())
            .await
            .map_err(|error| file_error(error, Access::Mutation))?;
        Ok(CasResult::Applied(Stored {
            epoch: epoch.to_owned(),
            config: next,
        }))
    }

    async fn publish_challenge(
        &self,
        token: &str,
        key_authorization: &str,
        ttl: Duration,
    ) -> StoreResult<()> {
        check_challenge(token, key_authorization, ttl)?;
        let _guard = self.writes.lock().await;
        let mut challenges = self.read_challenges().await?;
        let now = unix_now();
        challenges.retain(|_, challenge| challenge.expires_unix > now);
        challenges.insert(
            token.to_owned(),
            FileChallenge {
                key_authorization: key_authorization.to_owned(),
                expires_unix: challenge_expiry(ttl),
            },
        );
        self.write_challenges(challenges).await
    }

    async fn lookup_challenge(&self, token: &str) -> StoreResult<Option<String>> {
        check_challenge_token(token)?;
        let challenges = self.read_challenges().await?;
        let now = unix_now();
        Ok(challenges
            .get(token)
            .filter(|challenge| challenge.expires_unix > now)
            .map(|challenge| challenge.key_authorization.clone()))
    }

    async fn withdraw_challenge(&self, token: &str) -> StoreResult<()> {
        check_challenge_token(token)?;
        let _guard = self.writes.lock().await;
        let mut challenges = self.read_challenges().await?;
        if challenges.remove(token).is_none() {
            return Ok(());
        }
        self.write_challenges(challenges).await
    }
}

#[derive(Clone)]
pub struct SqliteConfigStore {
    path: PathBuf,
}

impl SqliteConfigStore {
    pub async fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let store = Self { path: path.into() };
        store
            .with_connection(Access::Read, |_| Ok(()))
            .await
            .map_err(StoreError::into_inner)?;
        Ok(store)
    }

    async fn with_connection<T, F>(&self, access: Access, operation: F) -> StoreResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut rusqlite::Connection) -> StoreResult<T> + Send + 'static,
    {
        let path = self.path.clone();
        blocking(access, move || {
            let mut connection = rusqlite::Connection::open(&path).map_err(|error| {
                StoreError::Unavailable(anyhow!(error).context(format!(
                    "open SQLite configuration store {}",
                    path.display()
                )))
            })?;
            connection
                .busy_timeout(Duration::from_secs(5))
                .map_err(sqlite_error)?;
            enable_wal(&connection)?;
            initialize_sqlite(&connection)?;
            operation(&mut connection)
        })
        .await
    }
}

/// Corrupt or mistyped database content is `Invalid`; everything else
/// (locked, cannot open, I/O, disk full) is a transport failure. SQLite
/// reports a failed statement before it commits, so a failed mutation
/// changed nothing.
fn sqlite_error(error: rusqlite::Error) -> StoreError {
    use rusqlite::{Error, ffi::ErrorCode};
    let invalid = match &error {
        Error::SqliteFailure(failure, _) => matches!(
            failure.code,
            ErrorCode::DatabaseCorrupt
                | ErrorCode::NotADatabase
                | ErrorCode::TypeMismatch
                | ErrorCode::ConstraintViolation
                | ErrorCode::TooBig
        ),
        Error::FromSqlConversionFailure(..)
        | Error::IntegralValueOutOfRange(..)
        | Error::InvalidColumnType(..)
        | Error::InvalidColumnIndex(_)
        | Error::InvalidColumnName(_)
        | Error::QueryReturnedNoRows
        | Error::QueryReturnedMoreThanOneRow => true,
        _ => false,
    };
    let error = anyhow!(error).context("SQLite configuration store operation failed");
    if invalid {
        StoreError::Invalid(error)
    } else {
        StoreError::Unavailable(error)
    }
}

#[async_trait]
impl ConfigStore for SqliteConfigStore {
    async fn load_latest(&self) -> StoreResult<Option<Stored>> {
        self.with_connection(Access::Read, |connection| sqlite_load(connection))
            .await
    }

    async fn bootstrap(&self, initial: Config) -> StoreResult<Stored> {
        let encoded = encode(&initial)?;
        let revision = revision_to_i64(initial.revision)?;
        let epoch = new_epoch()?;
        self.with_connection(Access::Mutation, move |connection| {
            connection
                .execute(
                    "INSERT OR IGNORE INTO hangang_config(singleton, revision, config_json, epoch) VALUES (1, ?1, ?2, ?3)",
                    rusqlite::params![revision, encoded, epoch],
                )
                .map_err(sqlite_error)?;
            sqlite_load(connection)?.ok_or_else(|| {
                StoreError::Invalid(anyhow!("SQLite bootstrap did not produce a snapshot"))
            })
        })
        .await
    }

    async fn compare_and_swap(
        &self,
        epoch: &str,
        expected: u64,
        mut next: Config,
    ) -> StoreResult<CasResult> {
        next.revision = next_revision(expected)?;
        let encoded = encode(&next)?;
        let next_revision = revision_to_i64(next.revision)?;
        let expected_revision = revision_to_i64(expected)?;
        let epoch = epoch.to_owned();
        self.with_connection(Access::Mutation, move |connection| {
            let transaction = connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(sqlite_error)?;
            let changed = transaction
                .execute(
                    "UPDATE hangang_config SET revision = ?1, config_json = ?2, operation_authority_id=NULL, operation_id=NULL, operation_revision=NULL, operation_sha256=NULL, operation_version=NULL, operation_sequence=NULL, write_generation=write_generation+1 WHERE singleton = 1 AND revision = ?3 AND epoch = ?4 AND write_generation<9223372036854775807",
                    rusqlite::params![next_revision, encoded, expected_revision, epoch],
                )
                .map_err(sqlite_error)?;
            let result = if changed == 1 {
                CasResult::Applied(Stored {
                    epoch: epoch.clone(),
                    config: next,
                })
            } else {
                let current = sqlite_load(&transaction)?.ok_or_else(|| {
                    StoreError::Invalid(anyhow!("SQLite configuration store is not initialized"))
                })?;
                resolve_cas(current, &epoch, &next)
            };
            transaction
                .commit()
                .map_err(sqlite_error)?;
            Ok(result)
        })
        .await
    }

    fn supports_operation_cas(&self) -> bool {
        true
    }

    fn supports_commit_receipts(&self) -> bool {
        true
    }

    fn supports_sequenced_operation_cas(&self) -> bool {
        true
    }

    async fn lookup_commit_receipt_v2(
        &self,
        authority_id: &str,
        acceptance_seq: u64,
    ) -> StoreResult<SequencedReceiptObservation> {
        canonical_operation_id(authority_id, acceptance_seq)?;
        let authority_id = authority_id.to_owned();
        self.with_connection(Access::Read, move |connection| {
            let tx = connection.transaction().map_err(sqlite_error)?;
            let observation = sqlite_sequenced_observation(&tx, &authority_id, acceptance_seq)?;
            tx.commit().map_err(sqlite_error)?;
            Ok(observation)
        })
        .await
    }

    async fn compare_and_swap_operation_v2(
        &self,
        epoch: &str,
        expected: u64,
        mut next: Config,
        stamp: SequencedOperationStamp,
    ) -> StoreResult<CasResult> {
        check_epoch(epoch)?;
        next.revision = next_revision(expected)?;
        let encoded = encode(&next)?;
        validate_sequenced_stamp(&stamp, &encoded)?;
        let revision = revision_to_i64(next.revision)?;
        let expected = revision_to_i64(expected)?;
        let seq = i64::try_from(stamp.acceptance_seq)
            .map_err(|_| StoreError::Invalid(anyhow!("invalid acceptance sequence")))?;
        let epoch = epoch.to_owned();
        self.with_connection(Access::Mutation,move|connection|{
            let tx=connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(sqlite_error)?;
            let current=sqlite_load_operation(&tx)?.ok_or_else(||StoreError::Invalid(anyhow!("SQLite configuration store is not initialized")))?;
            let observation=sqlite_sequenced_observation(&tx,&stamp.authority_id,stamp.acceptance_seq)?;
            if let Some(receipt)=observation.receipt {
                if receipt.epoch!=epoch || receipt.revision!=next.revision || receipt.stamp!=stamp {
                    return Err(StoreError::Invalid(anyhow!("sequenced operation identity reused")));
                }
                return Ok(if current.0.epoch==epoch && current.0.config==next && current_sequenced_proof(&current.0,&current.1,&current.2,&stamp){
                    CasResult::Applied(current.0)
                }else{CasResult::Conflict{current:current.0}});
            }
            if stamp.acceptance_seq<=observation.high_water {
                return Ok(CasResult::Conflict{current:current.0});
            }
            if !observation.writes_available {
                return Err(StoreError::Unavailable(anyhow!("sequenced receipt or authority capacity exhausted")));
            }
            let changed=tx.execute(
                "UPDATE hangang_config SET revision=?1,config_json=?2,operation_authority_id=?3,operation_id=?4,operation_revision=?1,operation_sha256=?5,operation_version=2,operation_sequence=?6,write_generation=write_generation+1 WHERE singleton=1 AND revision=?7 AND epoch=?8 AND write_generation<9223372036854775807",
                rusqlite::params![revision,encoded,stamp.authority_id,stamp.operation_id,stamp.candidate_sha256,seq,expected,epoch]
            ).map_err(sqlite_error)?;
            if changed!=1 {return Ok(CasResult::Conflict{current:current.0});}
            tx.execute("INSERT INTO hangang_sequenced_receipts(authority_id,acceptance_seq,operation_id,epoch,revision,candidate_sha256) VALUES(?1,?2,?3,?4,?5,?6)",rusqlite::params![stamp.authority_id,seq,stamp.operation_id,epoch,revision,stamp.candidate_sha256]).map_err(sqlite_error)?;
            let hwm=tx.execute("INSERT INTO hangang_sequenced_authorities(authority_id,high_water) VALUES(?1,?2) ON CONFLICT(authority_id) DO UPDATE SET high_water=excluded.high_water WHERE high_water<excluded.high_water",rusqlite::params![stamp.authority_id,seq]).map_err(sqlite_error)?;
            let counted=tx.execute("UPDATE hangang_commit_receipt_meta SET stored_records=stored_records+1 WHERE singleton=1 AND stored_records<100000",[]).map_err(sqlite_error)?;
            if hwm!=1 || counted!=1 {return Err(StoreError::Unavailable(anyhow!("sequenced receipt capacity exhausted")));}
            tx.commit().map_err(sqlite_error)?;
            Ok(CasResult::Applied(Stored{epoch,config:next}))
        }).await
    }

    async fn lookup_commit_receipt(
        &self,
        authority_id: &str,
        operation_id: &str,
    ) -> StoreResult<CommitReceiptObservation> {
        validate_receipt_ids(authority_id, operation_id)?;
        let authority_id = authority_id.to_owned();
        let operation_id = operation_id.to_owned();
        self.with_connection(Access::Read, move |connection| {
            let transaction = connection.transaction().map_err(sqlite_error)?;
            let observation =
                sqlite_receipt_observation(&transaction, &authority_id, &operation_id)?;
            transaction.commit().map_err(sqlite_error)?;
            Ok(observation)
        })
        .await
    }

    async fn load_current_operation_proof(&self) -> StoreResult<Option<OperationProof>> {
        self.with_connection(Access::Read, move |connection| {
            let transaction = connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(sqlite_error)?;
            let result =
                sqlite_load_operation(&transaction)?.and_then(|(stored, encoded, metadata)| {
                    current_operation_proof(&stored, &encoded, &metadata)
                });
            transaction.commit().map_err(sqlite_error)?;
            Ok(result)
        })
        .await
    }

    async fn compare_and_swap_operation(
        &self,
        epoch: &str,
        expected: u64,
        mut next: Config,
        stamp: OperationStamp,
    ) -> StoreResult<CasResult> {
        check_epoch(epoch)?;
        next.revision = next_revision(expected)?;
        let encoded = encode(&next)?;
        validate_operation_stamp(&stamp, &encoded)?;
        let next_revision = revision_to_i64(next.revision)?;
        let expected_revision = revision_to_i64(expected)?;
        let epoch = epoch.to_owned();
        self.with_connection(Access::Mutation,move |connection|{
            let transaction=connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(sqlite_error)?;
            let current=sqlite_load_operation(&transaction)?.ok_or_else(||StoreError::Invalid(anyhow!("SQLite configuration store is not initialized")))?;
            let history=sqlite_receipt_observation(&transaction,&stamp.authority_id,&stamp.operation_id)?;
            if let Some(receipt)=history.receipt {
                if receipt.epoch!=epoch || receipt.revision!=next.revision || receipt.stamp!=stamp {
                    return Err(StoreError::Invalid(anyhow!("operation identifier reused with another candidate or precondition")));
                }
                let result=if current.0.epoch==epoch && current.0.config==next &&
                    current_v1_operation_proof(&current.0,&current.1,&current.2).is_some_and(|proof| proof.stamp==stamp) {
                    CasResult::Applied(current.0)
                } else {CasResult::Conflict{current:current.0}};
                return Ok(result);
            }
            if !history.writes_available {
                return Err(StoreError::Unavailable(anyhow!("retained commit receipt capacity exhausted")));
            }
            if current.2.as_ref().is_some_and(|metadata|metadata.stamp.operation_id==stamp.operation_id) {
                return resolve_operation_cas(Ok(Some(current)),&epoch,&next,&stamp,false);
            }
            let changed=transaction.execute(
                "UPDATE hangang_config SET revision=?1,config_json=?2,operation_authority_id=?3,operation_id=?4,operation_revision=?1,operation_sha256=?5,operation_version=1,operation_sequence=NULL,write_generation=write_generation+1 WHERE singleton=1 AND revision=?6 AND epoch=?7 AND write_generation<9223372036854775807 AND (operation_id IS NULL OR operation_id!=?4)",
                rusqlite::params![next_revision,encoded,stamp.authority_id,stamp.operation_id,stamp.candidate_sha256,expected_revision,epoch]
            ).map_err(sqlite_error)?;
            let result=if changed==1 {
                transaction.execute("INSERT INTO hangang_commit_receipts(authority_id,operation_id,epoch,revision,candidate_sha256) VALUES(?1,?2,?3,?4,?5)",rusqlite::params![stamp.authority_id,stamp.operation_id,epoch,next_revision,stamp.candidate_sha256]).map_err(sqlite_error)?;
                let counted=transaction.execute("UPDATE hangang_commit_receipt_meta SET stored_records=stored_records+1 WHERE singleton=1 AND stored_records<100000",[]).map_err(sqlite_error)?;
                if counted!=1 {return Err(StoreError::Unavailable(anyhow!("retained commit receipt capacity exhausted")));}
                CasResult::Applied(Stored{epoch,config:next})
            }
                else {resolve_operation_cas(Ok(Some(current)),&epoch,&next,&stamp,false)?};
            transaction.commit().map_err(sqlite_error)?;
            Ok(result)
        }).await
    }

    async fn publish_challenge(
        &self,
        token: &str,
        key_authorization: &str,
        ttl: Duration,
    ) -> StoreResult<()> {
        check_challenge(token, key_authorization, ttl)?;
        let token = token.to_owned();
        let key_authorization = key_authorization.to_owned();
        let expires = challenge_expiry(ttl);
        self.with_connection(Access::Mutation, move |connection| {
            connection
                .execute(
                    "DELETE FROM hangang_acme_challenges WHERE expires_unix <= ?1",
                    rusqlite::params![unix_now()],
                )
                .map_err(sqlite_error)?;
            connection
                .execute(
                    "INSERT INTO hangang_acme_challenges(token, key_authorization, expires_unix) VALUES (?1, ?2, ?3)
                     ON CONFLICT(token) DO UPDATE SET key_authorization = excluded.key_authorization, expires_unix = excluded.expires_unix",
                    rusqlite::params![token, key_authorization, expires],
                )
                .map_err(sqlite_error)?;
            Ok(())
        })
        .await
    }

    async fn lookup_challenge(&self, token: &str) -> StoreResult<Option<String>> {
        check_challenge_token(token)?;
        let token = token.to_owned();
        self.with_connection(Access::Read, move |connection| {
            connection
                .query_row(
                    "SELECT key_authorization FROM hangang_acme_challenges WHERE token = ?1 AND expires_unix > ?2",
                    rusqlite::params![token, unix_now()],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(sqlite_error)
        })
        .await
    }

    async fn withdraw_challenge(&self, token: &str) -> StoreResult<()> {
        check_challenge_token(token)?;
        let token = token.to_owned();
        self.with_connection(Access::Mutation, move |connection| {
            connection
                .execute(
                    "DELETE FROM hangang_acme_challenges WHERE token = ?1",
                    rusqlite::params![token],
                )
                .map_err(sqlite_error)?;
            Ok(())
        })
        .await
    }
}

/// Switch a rollback-journal file to WAL once. Two openers racing on that
/// switch can receive `SQLITE_BUSY` without the busy handler running (SQLite
/// avoids a lock-upgrade deadlock that way), so the loser retries briefly
/// and then finds the file already in WAL mode.
fn enable_wal(connection: &rusqlite::Connection) -> StoreResult<()> {
    use rusqlite::{Error, ffi::ErrorCode};
    let mut attempts = 0;
    loop {
        let mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(sqlite_error)?;
        if mode.eq_ignore_ascii_case("wal") {
            return Ok(());
        }
        match connection.pragma_update(None, "journal_mode", "WAL") {
            Ok(()) => return Ok(()),
            Err(Error::SqliteFailure(failure, _))
                if matches!(
                    failure.code,
                    ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
                ) && attempts < 100 =>
            {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(sqlite_error(error)),
        }
    }
}

fn initialize_sqlite(connection: &rusqlite::Connection) -> StoreResult<()> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS hangang_config (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                revision INTEGER NOT NULL CHECK (revision >= 0),
                config_json TEXT NOT NULL,
                epoch TEXT NOT NULL DEFAULT '',
                operation_authority_id TEXT,
                operation_id TEXT,
                operation_revision INTEGER,
                operation_sha256 TEXT,
                operation_version INTEGER,
                operation_sequence INTEGER,
                write_generation INTEGER NOT NULL DEFAULT 0
            ) STRICT;
            CREATE TABLE IF NOT EXISTS hangang_acme_challenges (
                token TEXT PRIMARY KEY,
                key_authorization TEXT NOT NULL,
                expires_unix INTEGER NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS hangang_commit_receipts (
                authority_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                epoch TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision > 0),
                candidate_sha256 TEXT NOT NULL,
                PRIMARY KEY(authority_id, operation_id)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS hangang_commit_receipt_meta (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                stored_records INTEGER NOT NULL CHECK(stored_records >= 0 AND stored_records <= 100000)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS hangang_sequenced_receipts (
                authority_id TEXT NOT NULL,
                acceptance_seq INTEGER NOT NULL CHECK(acceptance_seq > 0 AND acceptance_seq <= 9007199254740991),
                operation_id TEXT NOT NULL,
                epoch TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision > 0),
                candidate_sha256 TEXT NOT NULL,
                PRIMARY KEY(authority_id, acceptance_seq),
                UNIQUE(authority_id, operation_id)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS hangang_sequenced_authorities (
                authority_id TEXT PRIMARY KEY,
                high_water INTEGER NOT NULL CHECK(high_water > 0 AND high_water <= 9007199254740991)
            ) STRICT;",
        )
        .map_err(sqlite_error)?;
    // Legacy files predate the epoch column. A concurrent upgrader may add
    // it first; that is success, not failure.
    if !sqlite_has_column(connection, "epoch")?
        && let Err(error) = connection
            .execute_batch("ALTER TABLE hangang_config ADD COLUMN epoch TEXT NOT NULL DEFAULT ''")
        && !sqlite_has_column(connection, "epoch")?
    {
        return Err(sqlite_error(error));
    }
    for (name, ddl) in [
        (
            "operation_authority_id",
            "ALTER TABLE hangang_config ADD COLUMN operation_authority_id TEXT",
        ),
        (
            "operation_id",
            "ALTER TABLE hangang_config ADD COLUMN operation_id TEXT",
        ),
        (
            "operation_revision",
            "ALTER TABLE hangang_config ADD COLUMN operation_revision INTEGER",
        ),
        (
            "operation_sha256",
            "ALTER TABLE hangang_config ADD COLUMN operation_sha256 TEXT",
        ),
        (
            "operation_version",
            "ALTER TABLE hangang_config ADD COLUMN operation_version INTEGER",
        ),
        (
            "operation_sequence",
            "ALTER TABLE hangang_config ADD COLUMN operation_sequence INTEGER",
        ),
        (
            "write_generation",
            "ALTER TABLE hangang_config ADD COLUMN write_generation INTEGER NOT NULL DEFAULT 0",
        ),
    ] {
        if !sqlite_has_column(connection, name)?
            && let Err(error) = connection.execute_batch(ddl)
            && !sqlite_has_column(connection, name)?
        {
            return Err(sqlite_error(error));
        }
    }
    connection.execute(
        "INSERT OR IGNORE INTO hangang_commit_receipt_meta(singleton, stored_records) VALUES(1, 0)",
        [],
    ).map_err(sqlite_error)?;
    connection
        .execute_batch(
            "CREATE TRIGGER IF NOT EXISTS hangang_stamped_write_generation_v2
         BEFORE UPDATE ON hangang_config
         WHEN (OLD.operation_id IS NOT NULL OR NEW.operation_id IS NOT NULL)
          AND NEW.write_generation <= OLD.write_generation
          AND (NEW.revision IS NOT OLD.revision OR NEW.config_json IS NOT OLD.config_json
               OR NEW.operation_authority_id IS NOT OLD.operation_authority_id
               OR NEW.operation_id IS NOT OLD.operation_id
               OR NEW.operation_revision IS NOT OLD.operation_revision
               OR NEW.operation_sha256 IS NOT OLD.operation_sha256)
         BEGIN SELECT RAISE(ABORT, 'stamped writer requires a new write generation'); END;",
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn sqlite_has_column(connection: &rusqlite::Connection, wanted: &str) -> StoreResult<bool> {
    let mut statement = connection
        .prepare("PRAGMA table_info(hangang_config)")
        .map_err(sqlite_error)?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sqlite_error)?;
    for name in names {
        if name.map_err(sqlite_error)? == wanted {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Read the document, upgrading a legacy row (empty epoch) exactly once. The
/// guarded `UPDATE` admits one winner; the loser re-reads the winner's row.
fn sqlite_load(connection: &rusqlite::Connection) -> StoreResult<Option<Stored>> {
    sqlite_load_interleaved(connection, || {})
}

/// `sqlite_load` with a hook in the window between the legacy read and the
/// guarded upgrade, where another connection can replace the row. Production
/// passes a no-op; the regression test replaces the row there.
fn sqlite_load_interleaved(
    connection: &rusqlite::Connection,
    before_upgrade: impl FnOnce(),
) -> StoreResult<Option<Stored>> {
    let Some((revision, json, epoch)) = sqlite_row(connection)? else {
        return Ok(None);
    };
    let (revision, json, epoch) = if epoch.is_empty() {
        before_upgrade();
        // Legacy row: assign an epoch once (one winner among racing
        // upgraders), then re-read the WHOLE row. Taking only the epoch from
        // the re-read could pair another incarnation's epoch with the
        // document read before it (a wipe-and-reseed in between).
        let candidate = new_epoch()?;
        connection
            .execute(
                "UPDATE hangang_config SET epoch = ?1 WHERE singleton = 1 AND epoch = ''",
                rusqlite::params![candidate],
            )
            .map_err(sqlite_error)?;
        sqlite_row(connection)?.ok_or_else(|| {
            StoreError::Invalid(anyhow!("SQLite document vanished during epoch upgrade"))
        })?
    } else {
        (revision, json, epoch)
    };
    check_epoch(&epoch)?;
    let config = decode(i64_to_revision(revision)?, &json)?;
    Ok(Some(Stored { epoch, config }))
}

fn sqlite_row(connection: &rusqlite::Connection) -> StoreResult<Option<(i64, String, String)>> {
    let row = connection
        .query_row(
            "SELECT revision,
                    CASE WHEN octet_length(config_json) <= ?1 THEN config_json END,
                    CASE WHEN octet_length(epoch) <= ?2 THEN epoch END
             FROM hangang_config WHERE singleton = 1",
            rusqlite::params![MAX_CONFIG_BYTES as i64, EPOCH_LEN as i64],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    row.map(|(revision, json, epoch)| {
        let json = json.ok_or_else(|| {
            StoreError::Invalid(anyhow!("stored SQLite configuration exceeds 1 MiB"))
        })?;
        let epoch = epoch.ok_or_else(|| {
            StoreError::Invalid(anyhow!(
                "stored SQLite authority epoch exceeds {EPOCH_LEN} bytes"
            ))
        })?;
        Ok((revision, json, epoch))
    })
    .transpose()
}

/// Call under one SQLite transaction so document and optional identity are a
/// single consistent row observation, including legacy epoch upgrades.
fn sqlite_load_operation(
    connection: &rusqlite::Connection,
) -> StoreResult<Option<(Stored, String, Option<OperationMetadata>)>> {
    let Some(stored) = sqlite_load(connection)? else {
        return Ok(None);
    };
    let (revision, encoded, epoch) = sqlite_row(connection)?
        .ok_or_else(|| StoreError::Invalid(anyhow!("SQLite configuration row vanished")))?;
    if i64_to_revision(revision)? != stored.config.revision || epoch != stored.epoch {
        return Err(StoreError::Invalid(anyhow!(
            "SQLite configuration row changed during proof read"
        )));
    }
    let (present,authority_id,operation_id,operation_revision,candidate_sha256,version,sequence)=connection.query_row(
        "SELECT (operation_authority_id IS NOT NULL OR operation_id IS NOT NULL OR operation_revision IS NOT NULL OR operation_sha256 IS NOT NULL OR operation_version IS NOT NULL OR operation_sequence IS NOT NULL),
                CASE WHEN octet_length(operation_authority_id)<=32 THEN operation_authority_id END,
                CASE WHEN octet_length(operation_id)<=32 THEN operation_id END,
                operation_revision,
                CASE WHEN octet_length(operation_sha256)<=64 THEN operation_sha256 END,
                operation_version,operation_sequence
         FROM hangang_config WHERE singleton=1",[],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,Option<String>>(1)?,row.get::<_,Option<String>>(2)?,row.get::<_,Option<i64>>(3)?,row.get::<_,Option<String>>(4)?,row.get::<_,Option<i64>>(5)?,row.get::<_,Option<i64>>(6)?))).map_err(sqlite_error)?;
    let metadata = if present == 0 {
        None
    } else {
        decode_operation_metadata(
            authority_id,
            operation_id,
            operation_revision,
            candidate_sha256,
            version,
            sequence,
        )?
    };
    if present != 0 && metadata.is_none() {
        return Err(StoreError::Invalid(anyhow!(
            "invalid stored operation stamp"
        )));
    }
    Ok(Some((stored, encoded, metadata)))
}

fn sqlite_receipt_observation(
    connection: &rusqlite::Connection,
    authority_id: &str,
    operation_id: &str,
) -> StoreResult<CommitReceiptObservation> {
    type ReceiptRow = (
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
        Option<String>,
    );
    let count: i64 = connection
        .query_row(
            "SELECT stored_records FROM hangang_commit_receipt_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let row: Option<ReceiptRow> = connection
        .query_row(
            "SELECT CASE WHEN octet_length(authority_id)<=32 THEN authority_id END,
                CASE WHEN octet_length(operation_id)<=32 THEN operation_id END,
                CASE WHEN octet_length(epoch)<=32 THEN epoch END,
                revision,
                CASE WHEN octet_length(candidate_sha256)<=64 THEN candidate_sha256 END
         FROM hangang_commit_receipts WHERE authority_id=?1 AND operation_id=?2",
            rusqlite::params![authority_id, operation_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let receipt = row
        .map(|(a, o, e, r, h)| {
            let (Some(a), Some(o), Some(e), Some(h)) = (a, o, e, h) else {
                return Err(StoreError::Invalid(anyhow!(
                    "invalid stored commit receipt"
                )));
            };
            commit_receipt(a, o, e, r, h)
        })
        .transpose()?;
    receipt_observation(receipt, count)
}

fn sqlite_sequenced_observation(
    connection: &rusqlite::Connection,
    authority_id: &str,
    seq: u64,
) -> StoreResult<SequencedReceiptObservation> {
    let count: i64 = connection
        .query_row(
            "SELECT stored_records FROM hangang_commit_receipt_meta WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(sqlite_error)?;
    let authorities: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM (SELECT 1 FROM hangang_sequenced_authorities LIMIT 4097)",
            [],
            |r| r.get(0),
        )
        .map_err(sqlite_error)?;
    let high_water: Option<i64> = connection
        .query_row(
            "SELECT high_water FROM hangang_sequenced_authorities WHERE authority_id=?1",
            [authority_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    type Row = (
        Option<String>,
        i64,
        Option<String>,
        Option<String>,
        i64,
        Option<String>,
    );
    let row: Option<Row> = connection
        .query_row(
            "SELECT CASE WHEN octet_length(authority_id)<=32 THEN authority_id END,
                acceptance_seq,
                CASE WHEN octet_length(operation_id)<=32 THEN operation_id END,
                CASE WHEN octet_length(epoch)<=32 THEN epoch END,
                revision,
                CASE WHEN octet_length(candidate_sha256)<=64 THEN candidate_sha256 END
         FROM hangang_sequenced_receipts WHERE authority_id=?1 AND acceptance_seq=?2",
            rusqlite::params![
                authority_id,
                i64::try_from(seq)
                    .map_err(|_| StoreError::Invalid(anyhow!("invalid acceptance sequence")))?
            ],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let receipt = row
        .map(|(a, s, o, e, r, h)| {
            let (Some(a), Some(o), Some(e), Some(h)) = (a, o, e, h) else {
                return Err(StoreError::Invalid(anyhow!("invalid sequenced receipt")));
            };
            sequenced_receipt(a, s, o, e, r, h)
        })
        .transpose()?;
    sequenced_observation(receipt, high_water, count, authorities)
}

#[derive(Clone)]
pub struct PostgresConfigStore {
    inner: Arc<PostgresInner>,
}

struct PostgresInner {
    config: tokio_postgres::Config,
    transport: PostgresTransport,
    client: tokio::sync::Mutex<Option<Arc<tokio_postgres::Client>>>,
}

enum PostgresTransport {
    Unencrypted,
    Rustls(Arc<rustls::ClientConfig>),
}

/// A PostgreSQL failure with whether the server answered: an answered
/// statement was rejected and changed nothing, an unanswered one may have
/// committed.
struct PostgresFailure {
    error: anyhow::Error,
    answered: bool,
}

/// A statement result plus whether an earlier attempt of the same statement
/// was sent and never answered. When `uncertain`, `value` describes the retry
/// only: a mutation's first attempt may have committed, so a retry that
/// changed nothing proves nothing on its own.
#[derive(Debug)]
struct Attempted<T> {
    value: T,
    uncertain: bool,
}

/// The retry of a statement whose first attempt failed.
enum Retry<T> {
    Sent(std::result::Result<T, PostgresFailure>),
    /// Reconnecting failed; nothing was sent again.
    Unsent(anyhow::Error),
}

/// Classify two attempts of one statement. A mutation whose first attempt
/// was sent and never answered may have committed: its retried value is
/// `uncertain`, and a failed or unsent retry is `Indeterminate`. A retry that
/// was itself unanswered is `Indeterminate` too. Reads change nothing, so
/// their failures are `Unavailable`.
fn settle<T>(access: Access, first: PostgresFailure, retry: Retry<T>) -> StoreResult<Attempted<T>> {
    let uncertain = access == Access::Mutation && !first.answered;
    let (error, unanswered_retry) = match retry {
        Retry::Sent(Ok(value)) => return Ok(Attempted { value, uncertain }),
        Retry::Sent(Err(second)) => (second.error, access == Access::Mutation && !second.answered),
        Retry::Unsent(error) => (error, false),
    };
    let error = error.context(first.error.to_string());
    if uncertain || unanswered_retry {
        Err(StoreError::Indeterminate(error))
    } else {
        Err(StoreError::Unavailable(error))
    }
}

/// Resolve a guarded CAS update that changed no row, from the recovery read
/// of the durable state. With `uncertain` (an earlier attempt of the same
/// update may have committed) only (`epoch`, `next.revision`, `next`) proves
/// an outcome: our write is durable (`Applied`). Nothing else does, so every
/// other state is `Indeterminate`, never a conflict or "nothing changed". In
/// particular (`epoch`, `expected`) does not prove that the write never
/// committed, and neither does another document at `next.revision`: a backup
/// taken before the write and restored under the same epoch between the
/// retry and this read brings the expected revision back (and lets another
/// writer take `next.revision` again) after our write committed and was
/// visible. A later revision, another epoch, an empty store and a failed
/// read prove nothing either. Without uncertainty the plain idempotency rule
/// applies: the answered update changed nothing, so the state is a conflict.
fn resolve_unchanged_cas(
    current: StoreResult<Option<Stored>>,
    epoch: &str,
    next: &Config,
    uncertain: bool,
) -> StoreResult<CasResult> {
    let current = match current {
        Ok(Some(current)) => current,
        Ok(None) if uncertain => {
            return Err(StoreError::Indeterminate(anyhow!(
                "the write was not acknowledged and the store is empty now"
            )));
        }
        Ok(None) => {
            return Err(StoreError::Invalid(anyhow!(
                "PostgreSQL configuration store is not initialized"
            )));
        }
        Err(error) if uncertain => {
            return Err(StoreError::Indeterminate(error.into_inner().context(
                "the write was not acknowledged and re-reading the store failed",
            )));
        }
        Err(error) => return Err(error),
    };
    match resolve_cas(current, epoch, next) {
        CasResult::Conflict { current } if uncertain => Err(StoreError::Indeterminate(anyhow!(
            "the write of revision {} was not acknowledged and the durable state (epoch {}, revision {}) cannot prove its outcome",
            next.revision,
            current.epoch,
            current.config.revision
        ))),
        resolved => Ok(resolved),
    }
}

/// Resolve a bootstrap from the read that follows its idempotent insert.
/// The answered insert (ours, or a no-op because a row already existed) left
/// a row behind, so an empty store afterwards is unreadable content. With
/// `uncertain` (an earlier attempt of the insert was never answered) the
/// seed may have been the shared authority the moment it committed, and
/// only a document found by this read settles what the authority is: an
/// empty store (the row can have been wiped after the insert committed,
/// before this read) and a failed read are both `Indeterminate`, because
/// "invalid, nothing changed" and "unavailable, nothing changed" would lie.
fn resolve_bootstrap_read(
    current: StoreResult<Option<Stored>>,
    uncertain: bool,
) -> StoreResult<Stored> {
    match current {
        Ok(Some(stored)) => Ok(stored),
        Ok(None) if uncertain => Err(StoreError::Indeterminate(anyhow!(
            "the bootstrap insert was not acknowledged and the store is empty now"
        ))),
        Ok(None) => Err(StoreError::Invalid(anyhow!(
            "PostgreSQL bootstrap did not produce a snapshot"
        ))),
        Err(error) if uncertain => {
            Err(StoreError::Indeterminate(error.into_inner().context(
                "the bootstrap insert was not acknowledged and re-reading the store failed",
            )))
        }
        Err(error) => Err(error),
    }
}

impl PostgresConfigStore {
    async fn receipt_observation(
        &self,
        authority_id: &str,
        operation_id: &str,
    ) -> StoreResult<CommitReceiptObservation> {
        validate_receipt_ids(authority_id, operation_id)?;
        let row = self
            .query_opt(
                Access::Read,
                "SELECT m.stored_records,
                CASE WHEN octet_length(r.authority_id)<=32 THEN r.authority_id END,
                CASE WHEN octet_length(r.operation_id)<=32 THEN r.operation_id END,
                CASE WHEN octet_length(r.epoch)<=32 THEN r.epoch END,
                r.revision,
                CASE WHEN octet_length(r.candidate_sha256)<=64 THEN r.candidate_sha256 END
             FROM hangang_commit_receipt_meta m
             LEFT JOIN hangang_commit_receipts r ON r.authority_id=$1 AND r.operation_id=$2
             WHERE m.singleton=1",
                &[&authority_id, &operation_id],
            )
            .await?
            .ok_or_else(|| StoreError::Invalid(anyhow!("commit receipt metadata is missing")))?;
        let count: i64 = postgres_column(&row, 0)?;
        let authority: Option<String> = postgres_column(&row, 1)?;
        let operation: Option<String> = postgres_column(&row, 2)?;
        let epoch: Option<String> = postgres_column(&row, 3)?;
        let revision: Option<i64> = postgres_column(&row, 4)?;
        let digest: Option<String> = postgres_column(&row, 5)?;
        let receipt = match (authority, operation, epoch, revision, digest) {
            (None, None, None, None, None) => None,
            (Some(a), Some(o), Some(e), Some(r), Some(h)) => Some(commit_receipt(a, o, e, r, h)?),
            _ => {
                return Err(StoreError::Invalid(anyhow!(
                    "invalid stored commit receipt"
                )));
            }
        };
        receipt_observation(receipt, count)
    }
    async fn sequenced_observation(
        &self,
        authority_id: &str,
        seq: u64,
    ) -> StoreResult<SequencedReceiptObservation> {
        let seq = i64::try_from(seq)
            .map_err(|_| StoreError::Invalid(anyhow!("invalid acceptance sequence")))?;
        let row = self
            .query_opt(
                Access::Read,
                "SELECT m.stored_records,
                (SELECT COUNT(*) FROM (SELECT 1 FROM hangang_sequenced_authorities LIMIT 4097)),
                (SELECT high_water FROM hangang_sequenced_authorities WHERE authority_id=$1),
                CASE WHEN octet_length(r.authority_id)<=32 THEN r.authority_id END,
                r.acceptance_seq,
                CASE WHEN octet_length(r.operation_id)<=32 THEN r.operation_id END,
                CASE WHEN octet_length(r.epoch)<=32 THEN r.epoch END,
                r.revision,
                CASE WHEN octet_length(r.candidate_sha256)<=64 THEN r.candidate_sha256 END
             FROM hangang_commit_receipt_meta m
             LEFT JOIN hangang_sequenced_receipts r ON r.authority_id=$1 AND r.acceptance_seq=$2
             WHERE m.singleton=1",
                &[&authority_id, &seq],
            )
            .await?
            .ok_or_else(|| StoreError::Invalid(anyhow!("sequenced receipt metadata is missing")))?;
        let count: i64 = postgres_column(&row, 0)?;
        let authorities: i64 = postgres_column(&row, 1)?;
        let high_water: Option<i64> = postgres_column(&row, 2)?;
        let authority: Option<String> = postgres_column(&row, 3)?;
        let receipt_seq: Option<i64> = postgres_column(&row, 4)?;
        let operation: Option<String> = postgres_column(&row, 5)?;
        let epoch: Option<String> = postgres_column(&row, 6)?;
        let revision: Option<i64> = postgres_column(&row, 7)?;
        let digest: Option<String> = postgres_column(&row, 8)?;
        let receipt = match (authority, receipt_seq, operation, epoch, revision, digest) {
            (None, None, None, None, None, None) => None,
            (Some(a), Some(s), Some(o), Some(e), Some(r), Some(h)) => {
                Some(sequenced_receipt(a, s, o, e, r, h)?)
            }
            _ => return Err(StoreError::Invalid(anyhow!("invalid sequenced receipt"))),
        };
        sequenced_observation(receipt, high_water, count, authorities)
    }
    /// Connect without transport encryption. This intentionally rejects
    /// non-loopback TCP hosts and `sslmode=require`; production remote
    /// PostgreSQL integration must use a separately verified TLS constructor.
    pub async fn connect_unencrypted(connection_string: &str) -> Result<Self> {
        let config = tokio_postgres::Config::from_str(connection_string)
            .context("parse PostgreSQL configuration store URL")?;
        ensure!(
            config.get_ssl_mode() != tokio_postgres::config::SslMode::Require,
            "sslmode=require cannot use an unencrypted PostgreSQL connection"
        );
        ensure!(
            config.get_hostaddrs().iter().all(IpAddr::is_loopback),
            "unencrypted PostgreSQL is limited to loopback host addresses"
        );
        for host in config.get_hosts() {
            match host {
                tokio_postgres::config::Host::Tcp(host) => {
                    let loopback = host == "localhost"
                        || host
                            .parse::<IpAddr>()
                            .is_ok_and(|address| address.is_loopback());
                    ensure!(
                        loopback,
                        "unencrypted PostgreSQL is limited to loopback hosts"
                    );
                }
                #[cfg(unix)]
                tokio_postgres::config::Host::Unix(_) => {}
            }
        }
        let store = Self {
            inner: Arc::new(PostgresInner {
                config,
                transport: PostgresTransport::Unencrypted,
                client: tokio::sync::Mutex::new(None),
            }),
        };
        store.client().await.map_err(StoreError::into_inner)?;
        Ok(store)
    }

    /// Connect with certificate and hostname verification. TLS is forced even
    /// when the connection string does not specify `sslmode=require`.
    pub async fn connect(connection_string: &str, tls: rustls::ClientConfig) -> Result<Self> {
        let mut config = tokio_postgres::Config::from_str(connection_string)
            .context("parse PostgreSQL configuration store URL")?;
        config.ssl_mode(tokio_postgres::config::SslMode::Require);
        let store = Self {
            inner: Arc::new(PostgresInner {
                config,
                transport: PostgresTransport::Rustls(Arc::new(tls)),
                client: tokio::sync::Mutex::new(None),
            }),
        };
        store.client().await.map_err(StoreError::into_inner)?;
        Ok(store)
    }

    async fn client(&self) -> StoreResult<Arc<tokio_postgres::Client>> {
        let mut cached = self.inner.client.lock().await;
        if let Some(client) = cached.as_ref().filter(|client| !client.is_closed()) {
            return Ok(client.clone());
        }
        let client = match &self.inner.transport {
            PostgresTransport::Unencrypted => {
                let (client, connection) =
                    postgres_timeout(self.inner.config.connect(tokio_postgres::NoTls))
                        .await
                        .map_err(|failure| {
                            StoreError::Unavailable(
                                failure
                                    .error
                                    .context("connect unencrypted PostgreSQL configuration store"),
                            )
                        })?;
                tokio::spawn(async move {
                    if let Err(error) = connection.await {
                        tracing::warn!(%error, "PostgreSQL configuration store connection ended");
                    }
                });
                client
            }
            PostgresTransport::Rustls(config) => {
                let connector = tokio_postgres_rustls::MakeRustlsConnect::new((**config).clone());
                let (client, connection) = postgres_timeout(self.inner.config.connect(connector))
                    .await
                    .map_err(|failure| {
                        StoreError::Unavailable(
                            failure
                                .error
                                .context("connect TLS PostgreSQL configuration store"),
                        )
                    })?;
                tokio::spawn(async move {
                    if let Err(error) = connection.await {
                        tracing::warn!(%error, "PostgreSQL configuration store connection ended");
                    }
                });
                client
            }
        };
        // `ADD COLUMN IF NOT EXISTS` upgrades a legacy table in place; the
        // fresh definition already carries the column.
        postgres_timeout(client.batch_execute(
            "CREATE TABLE IF NOT EXISTS hangang_config (
                singleton SMALLINT PRIMARY KEY CHECK (singleton = 1),
                revision BIGINT NOT NULL CHECK (revision >= 0),
                config_json TEXT NOT NULL,
                epoch TEXT NOT NULL DEFAULT '',
                operation_authority_id TEXT,
                operation_id TEXT,
                operation_revision BIGINT,
                operation_sha256 TEXT,
                operation_version SMALLINT,
                operation_sequence BIGINT,
                write_generation BIGINT NOT NULL DEFAULT 0
            );
            ALTER TABLE hangang_config ADD COLUMN IF NOT EXISTS epoch TEXT NOT NULL DEFAULT '';
            ALTER TABLE hangang_config ADD COLUMN IF NOT EXISTS operation_authority_id TEXT;
            ALTER TABLE hangang_config ADD COLUMN IF NOT EXISTS operation_id TEXT;
            ALTER TABLE hangang_config ADD COLUMN IF NOT EXISTS operation_revision BIGINT;
            ALTER TABLE hangang_config ADD COLUMN IF NOT EXISTS operation_sha256 TEXT;
            ALTER TABLE hangang_config ADD COLUMN IF NOT EXISTS operation_version SMALLINT;
            ALTER TABLE hangang_config ADD COLUMN IF NOT EXISTS operation_sequence BIGINT;
            ALTER TABLE hangang_config ADD COLUMN IF NOT EXISTS write_generation BIGINT NOT NULL DEFAULT 0;
            CREATE TABLE IF NOT EXISTS hangang_acme_challenges (
                token TEXT PRIMARY KEY,
                key_authorization TEXT NOT NULL,
                expires_unix BIGINT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS hangang_commit_receipts (
                authority_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                epoch TEXT NOT NULL,
                revision BIGINT NOT NULL CHECK(revision > 0),
                candidate_sha256 TEXT NOT NULL,
                PRIMARY KEY(authority_id, operation_id)
            );
            CREATE TABLE IF NOT EXISTS hangang_commit_receipt_meta (
                singleton SMALLINT PRIMARY KEY CHECK(singleton = 1),
                stored_records BIGINT NOT NULL CHECK(stored_records >= 0 AND stored_records <= 100000)
            );
            CREATE TABLE IF NOT EXISTS hangang_sequenced_receipts (
                authority_id TEXT NOT NULL,
                acceptance_seq BIGINT NOT NULL CHECK(acceptance_seq > 0 AND acceptance_seq <= 9007199254740991),
                operation_id TEXT NOT NULL,
                epoch TEXT NOT NULL,
                revision BIGINT NOT NULL CHECK(revision > 0),
                candidate_sha256 TEXT NOT NULL,
                PRIMARY KEY(authority_id, acceptance_seq),
                UNIQUE(authority_id, operation_id)
            );
            CREATE TABLE IF NOT EXISTS hangang_sequenced_authorities (
                authority_id TEXT PRIMARY KEY,
                high_water BIGINT NOT NULL CHECK(high_water > 0 AND high_water <= 9007199254740991)
            );
            INSERT INTO hangang_commit_receipt_meta(singleton,stored_records)
            VALUES(1,0) ON CONFLICT(singleton) DO NOTHING;
            CREATE OR REPLACE FUNCTION hangang_stamped_generation_guard() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN
                IF (OLD.operation_id IS NOT NULL OR NEW.operation_id IS NOT NULL)
                   AND NEW.write_generation <= OLD.write_generation
                   AND (NEW.revision IS DISTINCT FROM OLD.revision
                     OR NEW.config_json IS DISTINCT FROM OLD.config_json
                     OR NEW.operation_authority_id IS DISTINCT FROM OLD.operation_authority_id
                     OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
                     OR NEW.operation_revision IS DISTINCT FROM OLD.operation_revision
                     OR NEW.operation_sha256 IS DISTINCT FROM OLD.operation_sha256)
                THEN RAISE EXCEPTION 'stamped writer requires a new write generation' USING ERRCODE='23514';
                END IF;
                RETURN NEW;
            END $$;
            CREATE OR REPLACE TRIGGER hangang_stamped_write_generation
            BEFORE UPDATE ON hangang_config FOR EACH ROW
            EXECUTE FUNCTION hangang_stamped_generation_guard();
            CREATE OR REPLACE FUNCTION hangang_cas_v2(
                p_revision BIGINT,p_encoded TEXT,p_authority TEXT,p_operation TEXT,
                p_digest TEXT,p_sequence BIGINT,p_expected BIGINT,p_epoch TEXT
            ) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY INVOKER SET search_path FROM CURRENT AS $v2$
            DECLARE changed BIGINT;
            BEGIN
                IF p_sequence<=0 OR p_sequence>9007199254740991 THEN
                    RAISE EXCEPTION 'invalid sequenced operation' USING ERRCODE='23514';
                END IF;
                UPDATE hangang_config SET
                    revision=p_revision,config_json=p_encoded,operation_authority_id=p_authority,
                    operation_id=p_operation,operation_revision=p_revision,operation_sha256=p_digest,
                    operation_version=2,operation_sequence=p_sequence,write_generation=write_generation+1
                WHERE singleton=1 AND revision=p_expected AND epoch=p_epoch
                  AND write_generation<9223372036854775807
                  AND NOT EXISTS (SELECT 1 FROM hangang_sequenced_receipts WHERE authority_id=p_authority AND acceptance_seq=p_sequence)
                  AND COALESCE((SELECT high_water FROM hangang_sequenced_authorities WHERE authority_id=p_authority),0)<p_sequence
                  AND EXISTS (SELECT 1 FROM hangang_commit_receipt_meta WHERE singleton=1 AND stored_records<100000);
                GET DIAGNOSTICS changed=ROW_COUNT;
                IF changed=0 THEN RETURN FALSE; END IF;
                IF NOT EXISTS (SELECT 1 FROM hangang_sequenced_authorities WHERE authority_id=p_authority)
                   AND (SELECT COUNT(*) FROM (SELECT 1 FROM hangang_sequenced_authorities LIMIT 4096))>=4096 THEN
                    RAISE EXCEPTION 'sequenced authority capacity exhausted' USING ERRCODE='23514';
                END IF;
                INSERT INTO hangang_sequenced_receipts(authority_id,acceptance_seq,operation_id,epoch,revision,candidate_sha256)
                VALUES(p_authority,p_sequence,p_operation,p_epoch,p_revision,p_digest);
                INSERT INTO hangang_sequenced_authorities(authority_id,high_water)
                VALUES(p_authority,p_sequence)
                ON CONFLICT(authority_id) DO UPDATE SET high_water=EXCLUDED.high_water
                WHERE hangang_sequenced_authorities.high_water<EXCLUDED.high_water;
                GET DIAGNOSTICS changed=ROW_COUNT;
                IF changed<>1 THEN RAISE EXCEPTION 'sequenced authority fence changed' USING ERRCODE='23514'; END IF;
                UPDATE hangang_commit_receipt_meta SET stored_records=stored_records+1
                WHERE singleton=1 AND stored_records<100000;
                GET DIAGNOSTICS changed=ROW_COUNT;
                IF changed<>1 THEN RAISE EXCEPTION 'sequenced receipt capacity exhausted' USING ERRCODE='23514'; END IF;
                RETURN TRUE;
            END $v2$",
        ))
        .await
        .map_err(|failure| {
            StoreError::Unavailable(
                failure
                    .error
                    .context("initialize PostgreSQL configuration schema"),
            )
        })?;
        let client = Arc::new(client);
        *cached = Some(client.clone());
        Ok(client)
    }

    async fn invalidate(&self, failed: &Arc<tokio_postgres::Client>) {
        let mut cached = self.inner.client.lock().await;
        if cached
            .as_ref()
            .is_some_and(|client| Arc::ptr_eq(client, failed))
        {
            *cached = None;
        }
    }

    /// Run a statement, retrying once on a fresh connection. A mutation is
    /// safe to retry because CAS and bootstrap are idempotent; the result
    /// records whether the first attempt was sent and never answered, so a
    /// caller whose retry changed nothing can tell "never applied" from
    /// "unknown" (see `settle`).
    async fn run<T, F, Fut>(&self, access: Access, statement: F) -> StoreResult<Attempted<T>>
    where
        F: Fn(Arc<tokio_postgres::Client>) -> Fut,
        Fut: Future<Output = std::result::Result<T, tokio_postgres::Error>>,
    {
        let client = self.client().await?;
        let first = match postgres_timeout(statement(client.clone())).await {
            Ok(value) => {
                return Ok(Attempted {
                    value,
                    uncertain: false,
                });
            }
            Err(failure) => failure,
        };
        self.invalidate(&client).await;
        let retry = match self.client().await {
            Ok(retry) => Retry::Sent(postgres_timeout(statement(retry)).await),
            Err(error) => Retry::Unsent(error.into_inner()),
        };
        settle(access, first, retry)
    }

    async fn query_opt(
        &self,
        access: Access,
        query: &str,
        parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> StoreResult<Option<tokio_postgres::Row>> {
        let attempted = self
            .run(access, |client| async move {
                client.query_opt(query, parameters).await
            })
            .await?;
        Ok(attempted.value)
    }

    async fn execute(
        &self,
        access: Access,
        query: &str,
        parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> StoreResult<u64> {
        let attempted = self
            .run(access, |client| async move {
                client.execute(query, parameters).await
            })
            .await?;
        Ok(attempted.value)
    }

    /// Read the document, upgrading a legacy row (empty epoch) exactly once
    /// with one winner among concurrent upgraders.
    async fn load_stored(&self) -> StoreResult<Option<Stored>> {
        // PostgreSQL's `octet_length(text)` returns INT4, so its comparison
        // parameters must use the inferred INT4 wire type as well.
        let max_config_bytes = i32::try_from(MAX_CONFIG_BYTES).expect("1 MiB fits i32");
        let max_epoch_bytes = i32::try_from(EPOCH_LEN).expect("epoch length fits i32");
        let Some(row) = self
            .query_opt(
                Access::Read,
                "SELECT revision,
                        CASE WHEN octet_length(config_json) <= $1 THEN config_json END,
                        CASE WHEN octet_length(epoch) <= $2 THEN epoch END
                 FROM hangang_config WHERE singleton = 1",
                &[&max_config_bytes, &max_epoch_bytes],
            )
            .await?
        else {
            return Ok(None);
        };
        let mut revision: i64 = postgres_column(&row, 0)?;
        let mut json: String = postgres_column::<Option<String>>(&row, 1)?.ok_or_else(|| {
            StoreError::Invalid(anyhow!("stored PostgreSQL configuration exceeds 1 MiB"))
        })?;
        let mut epoch: String = postgres_column::<Option<String>>(&row, 2)?.ok_or_else(|| {
            StoreError::Invalid(anyhow!(
                "stored PostgreSQL authority epoch exceeds {EPOCH_LEN} bytes"
            ))
        })?;
        if epoch.is_empty() {
            // Legacy row: assign an epoch once, then re-read the WHOLE row so
            // the epoch is never paired with a document that another
            // incarnation replaced in between.
            let candidate = new_epoch()?;
            self.execute(
                Access::Mutation,
                "UPDATE hangang_config SET epoch = $1 WHERE singleton = 1 AND epoch = ''",
                &[&candidate],
            )
            .await?;
            let row = self
                .query_opt(
                    Access::Read,
                    "SELECT revision,
                            CASE WHEN octet_length(config_json) <= $1 THEN config_json END,
                            CASE WHEN octet_length(epoch) <= $2 THEN epoch END
                     FROM hangang_config WHERE singleton = 1",
                    &[&max_config_bytes, &max_epoch_bytes],
                )
                .await?
                .ok_or_else(|| {
                    StoreError::Invalid(anyhow!(
                        "PostgreSQL document vanished during epoch upgrade"
                    ))
                })?;
            revision = postgres_column(&row, 0)?;
            json = postgres_column::<Option<String>>(&row, 1)?.ok_or_else(|| {
                StoreError::Invalid(anyhow!("stored PostgreSQL configuration exceeds 1 MiB"))
            })?;
            epoch = postgres_column::<Option<String>>(&row, 2)?.ok_or_else(|| {
                StoreError::Invalid(anyhow!(
                    "stored PostgreSQL authority epoch exceeds {EPOCH_LEN} bytes"
                ))
            })?;
        }
        check_epoch(&epoch)?;
        let config = decode(i64_to_revision(revision)?, &json)?;
        Ok(Some(Stored { epoch, config }))
    }

    /// One row read supplies both the document and its optional stamp. The
    /// initial load also performs the existing one-time legacy epoch upgrade.
    async fn load_stored_with_proof(
        &self,
    ) -> StoreResult<Option<(Stored, String, Option<OperationMetadata>)>> {
        self.load_stored().await?;
        let max_config_bytes = i32::try_from(MAX_CONFIG_BYTES).expect("1 MiB fits i32");
        let max_epoch_bytes = i32::try_from(EPOCH_LEN).expect("epoch length fits i32");
        let Some(row)=self.query_opt(Access::Read,
            "SELECT revision,
                CASE WHEN octet_length(config_json)<=$1 THEN config_json END,
                CASE WHEN octet_length(epoch)<=$2 THEN epoch END,
                (operation_authority_id IS NOT NULL OR operation_id IS NOT NULL OR operation_revision IS NOT NULL OR operation_sha256 IS NOT NULL OR operation_version IS NOT NULL OR operation_sequence IS NOT NULL),
                CASE WHEN octet_length(operation_authority_id)<=32 THEN operation_authority_id END,
                CASE WHEN octet_length(operation_id)<=32 THEN operation_id END,
                operation_revision,
                CASE WHEN octet_length(operation_sha256)<=64 THEN operation_sha256 END,
                operation_version,operation_sequence
             FROM hangang_config WHERE singleton=1",
            &[&max_config_bytes,&max_epoch_bytes]).await? else {return Ok(None)};
        let revision: i64 = postgres_column(&row, 0)?;
        let encoded: String = postgres_column::<Option<String>>(&row, 1)?.ok_or_else(|| {
            StoreError::Invalid(anyhow!("stored PostgreSQL configuration exceeds 1 MiB"))
        })?;
        let epoch: String = postgres_column::<Option<String>>(&row, 2)?.ok_or_else(|| {
            StoreError::Invalid(anyhow!(
                "stored PostgreSQL authority epoch exceeds {EPOCH_LEN} bytes"
            ))
        })?;
        check_epoch(&epoch)?;
        let present: bool = postgres_column(&row, 3)?;
        let authority_id: Option<String> = postgres_column(&row, 4)?;
        let operation_id: Option<String> = postgres_column(&row, 5)?;
        let operation_revision: Option<i64> = postgres_column(&row, 6)?;
        let candidate_sha256: Option<String> = postgres_column(&row, 7)?;
        let version: Option<i64> = postgres_column::<Option<i16>>(&row, 8)?.map(i64::from);
        let sequence: Option<i64> = postgres_column(&row, 9)?;
        let metadata = if present {
            decode_operation_metadata(
                authority_id,
                operation_id,
                operation_revision,
                candidate_sha256,
                version,
                sequence,
            )?
        } else {
            None
        };
        if present && metadata.is_none() {
            return Err(StoreError::Invalid(anyhow!(
                "invalid stored operation stamp"
            )));
        }
        let config = decode(i64_to_revision(revision)?, &encoded)?;
        Ok(Some((Stored { epoch, config }, encoded, metadata)))
    }
}

fn postgres_column<'a, T>(row: &'a tokio_postgres::Row, index: usize) -> StoreResult<T>
where
    T: tokio_postgres::types::FromSql<'a>,
{
    row.try_get(index).map_err(|error| {
        StoreError::Invalid(anyhow!(error).context("decode PostgreSQL configuration row"))
    })
}

#[async_trait]
impl ConfigStore for PostgresConfigStore {
    async fn load_latest(&self) -> StoreResult<Option<Stored>> {
        self.load_stored().await
    }

    async fn bootstrap(&self, initial: Config) -> StoreResult<Stored> {
        let encoded = encode(&initial)?;
        let revision = revision_to_i64(initial.revision)?;
        let epoch = new_epoch()?;
        let parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)] =
            &[&revision, &encoded, &epoch];
        let Attempted { uncertain, .. } = self
            .run(Access::Mutation, |client| async move {
                client
                    .execute(
                        "INSERT INTO hangang_config(singleton, revision, config_json, epoch) VALUES (1, $1, $2, $3) ON CONFLICT (singleton) DO NOTHING",
                        parameters,
                    )
                    .await
            })
            .await?;
        // An unanswered insert may have seeded the shared authority; a read
        // that fails or finds the store empty afterwards must not be
        // reported as "nothing changed".
        resolve_bootstrap_read(self.load_stored().await, uncertain)
    }

    async fn compare_and_swap(
        &self,
        epoch: &str,
        expected: u64,
        mut next: Config,
    ) -> StoreResult<CasResult> {
        next.revision = next_revision(expected)?;
        let encoded = encode(&next)?;
        let next_revision = revision_to_i64(next.revision)?;
        let expected_revision = revision_to_i64(expected)?;
        let parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)] =
            &[&next_revision, &encoded, &expected_revision, &epoch];
        let Attempted {
            value: row,
            uncertain,
        } = self
            .run(Access::Mutation, |client| async move {
                client
                    .query_opt(
                        "UPDATE hangang_config SET revision = $1, config_json = $2, operation_authority_id=NULL, operation_id=NULL, operation_revision=NULL, operation_sha256=NULL, operation_version=NULL, operation_sequence=NULL, write_generation=write_generation+1 WHERE singleton = 1 AND revision = $3 AND epoch = $4 AND write_generation<9223372036854775807 RETURNING revision",
                        parameters,
                    )
                    .await
            })
            .await?;
        if row.is_some() {
            // This attempt updated the row, so our document is durable at
            // (`epoch`, `expected + 1`) whatever became of an earlier
            // unanswered attempt (a same-epoch restore may even have undone
            // it in between).
            return Ok(CasResult::Applied(Stored {
                epoch: epoch.to_owned(),
                config: next,
            }));
        }
        // A lost acknowledgement makes the recovery read the only evidence,
        // and only our own document at `expected + 1` is evidence: anything
        // else, the read's failure included, must not become a conflict or
        // "nothing changed".
        let current = self.load_stored().await;
        resolve_unchanged_cas(current, epoch, &next, uncertain)
    }

    fn supports_operation_cas(&self) -> bool {
        true
    }

    fn supports_commit_receipts(&self) -> bool {
        true
    }

    fn supports_sequenced_operation_cas(&self) -> bool {
        true
    }

    async fn lookup_commit_receipt_v2(
        &self,
        authority_id: &str,
        acceptance_seq: u64,
    ) -> StoreResult<SequencedReceiptObservation> {
        canonical_operation_id(authority_id, acceptance_seq)?;
        self.sequenced_observation(authority_id, acceptance_seq)
            .await
    }

    async fn compare_and_swap_operation_v2(
        &self,
        epoch: &str,
        expected: u64,
        mut next: Config,
        stamp: SequencedOperationStamp,
    ) -> StoreResult<CasResult> {
        check_epoch(epoch)?;
        next.revision = next_revision(expected)?;
        let encoded = encode(&next)?;
        validate_sequenced_stamp(&stamp, &encoded)?;
        let revision = revision_to_i64(next.revision)?;
        let expected_i64 = revision_to_i64(expected)?;
        let seq = i64::try_from(stamp.acceptance_seq)
            .map_err(|_| StoreError::Invalid(anyhow!("invalid acceptance sequence")))?;
        let parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
            &revision,
            &encoded,
            &stamp.authority_id,
            &stamp.operation_id,
            &stamp.candidate_sha256,
            &seq,
            &expected_i64,
            &epoch,
        ];
        let attempted = self
            .run(Access::Mutation, |client| async move {
                client
                    .query_one("SELECT hangang_cas_v2($1,$2,$3,$4,$5,$6,$7,$8)", parameters)
                    .await
            })
            .await?;
        let changed: bool = postgres_column(&attempted.value, 0)?;
        if changed {
            return Ok(CasResult::Applied(Stored {
                epoch: epoch.to_owned(),
                config: next,
            }));
        }
        let observation = match self
            .sequenced_observation(&stamp.authority_id, stamp.acceptance_seq)
            .await
        {
            Ok(value) => value,
            Err(error) if attempted.uncertain => {
                return Err(StoreError::Indeterminate(
                    error
                        .into_inner()
                        .context("sequenced CAS receipt recovery failed"),
                ));
            }
            Err(error) => return Err(error),
        };
        if let Some(receipt) = observation.receipt {
            if receipt.epoch != epoch || receipt.revision != next.revision || receipt.stamp != stamp
            {
                return if attempted.uncertain {
                    Err(StoreError::Indeterminate(anyhow!(
                        "sequenced CAS unanswered and identity differs"
                    )))
                } else {
                    Err(StoreError::Invalid(anyhow!(
                        "sequenced operation identity reused"
                    )))
                };
            }
            let current =
                receipt_recovery_read(self.load_stored_with_proof().await, attempted.uncertain)?;
            return match current {
                Some((stored, encoded, metadata))
                    if stored.epoch == epoch
                        && stored.config == next
                        && current_sequenced_proof(&stored, &encoded, &metadata, &stamp) =>
                {
                    Ok(CasResult::Applied(stored))
                }
                Some((_stored, _, _)) if attempted.uncertain => Err(StoreError::Indeterminate(
                    anyhow!("sequenced CAS committed historically but current document changed"),
                )),
                Some((stored, _, _)) => Ok(CasResult::Conflict { current: stored }),
                None => Err(StoreError::Indeterminate(anyhow!(
                    "sequenced receipt exists but current configuration is absent"
                ))),
            };
        }
        let current =
            receipt_recovery_read(self.load_stored_with_proof().await, attempted.uncertain)?;
        let Some((stored, _, _)) = current else {
            return Err(StoreError::Indeterminate(anyhow!(
                "sequenced CAS current configuration is absent"
            )));
        };
        if attempted.uncertain {
            return Err(StoreError::Indeterminate(anyhow!(
                "sequenced CAS outcome is not provable"
            )));
        }
        if stored.epoch == epoch
            && stored.config.revision == expected
            && !observation.writes_available
        {
            return Err(StoreError::Unavailable(anyhow!(
                "sequenced receipt or authority capacity exhausted"
            )));
        }
        Ok(CasResult::Conflict { current: stored })
    }

    async fn lookup_commit_receipt(
        &self,
        authority_id: &str,
        operation_id: &str,
    ) -> StoreResult<CommitReceiptObservation> {
        self.receipt_observation(authority_id, operation_id).await
    }

    async fn load_current_operation_proof(&self) -> StoreResult<Option<OperationProof>> {
        Ok(self
            .load_stored_with_proof()
            .await?
            .and_then(|(stored, encoded, metadata)| {
                current_operation_proof(&stored, &encoded, &metadata)
            }))
    }

    async fn compare_and_swap_operation(
        &self,
        epoch: &str,
        expected: u64,
        mut next: Config,
        stamp: OperationStamp,
    ) -> StoreResult<CasResult> {
        check_epoch(epoch)?;
        next.revision = next_revision(expected)?;
        let encoded = encode(&next)?;
        validate_operation_stamp(&stamp, &encoded)?;
        let next_revision = revision_to_i64(next.revision)?;
        let expected_revision = revision_to_i64(expected)?;
        let parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
            &next_revision,
            &encoded,
            &stamp.authority_id,
            &stamp.operation_id,
            &stamp.candidate_sha256,
            &expected_revision,
            &epoch,
        ];
        let Attempted{value:row,uncertain}=self.run(Access::Mutation,|client|async move{
            client.query_opt(
                "WITH updated AS (
                    UPDATE hangang_config
                    SET revision=$1,config_json=$2,operation_authority_id=$3,operation_id=$4,operation_revision=$1,operation_sha256=$5,operation_version=1,operation_sequence=NULL,write_generation=write_generation+1
                    WHERE singleton=1 AND revision=$6 AND epoch=$7
                      AND write_generation<9223372036854775807
                      AND (operation_id IS NULL OR operation_id<>$4)
                      AND NOT EXISTS (SELECT 1 FROM hangang_commit_receipts WHERE authority_id=$3 AND operation_id=$4)
                      AND EXISTS (SELECT 1 FROM hangang_commit_receipt_meta WHERE singleton=1 AND stored_records<100000)
                    RETURNING revision
                ), inserted AS (
                    INSERT INTO hangang_commit_receipts(authority_id,operation_id,epoch,revision,candidate_sha256)
                    SELECT $3,$4,$7,revision,$5 FROM updated RETURNING revision
                ), counted AS (
                    UPDATE hangang_commit_receipt_meta SET stored_records=stored_records+1
                    WHERE singleton=1 AND EXISTS (SELECT 1 FROM inserted)
                    RETURNING stored_records
                ) SELECT inserted.revision FROM inserted JOIN counted ON true",
                parameters).await
        }).await?;
        if row.is_some() {
            return Ok(CasResult::Applied(Stored {
                epoch: epoch.to_owned(),
                config: next,
            }));
        }
        let history = match self
            .receipt_observation(&stamp.authority_id, &stamp.operation_id)
            .await
        {
            Ok(value) => value,
            Err(error) if uncertain => {
                return Err(StoreError::Indeterminate(
                    error
                        .into_inner()
                        .context("operation CAS recovery receipt read failed"),
                ));
            }
            Err(error) => return Err(error),
        };
        if let Some(receipt) = history.receipt {
            if receipt.epoch != epoch || receipt.revision != next.revision || receipt.stamp != stamp
            {
                if uncertain {
                    return Err(StoreError::Indeterminate(anyhow!(
                        "operation CAS outcome is not provable after an unanswered attempt"
                    )));
                }
                return Err(StoreError::Invalid(anyhow!(
                    "operation identifier reused with another candidate or precondition"
                )));
            }
            let current = receipt_recovery_read(self.load_stored_with_proof().await, uncertain)?;
            if let Some((stored, encoded, metadata)) = current {
                if stored.epoch == epoch
                    && stored.config == next
                    && current_v1_operation_proof(&stored, &encoded, &metadata)
                        .is_some_and(|proof| proof.stamp == stamp)
                {
                    return Ok(CasResult::Applied(stored));
                }
                if uncertain {
                    return Err(StoreError::Indeterminate(anyhow!(
                        "operation CAS committed historically but current document changed"
                    )));
                }
                return Ok(CasResult::Conflict { current: stored });
            }
            return Err(StoreError::Indeterminate(anyhow!(
                "operation CAS receipt exists but current configuration is absent"
            )));
        }
        if !history.writes_available && !uncertain {
            let current = self.load_stored_with_proof().await?;
            if current.as_ref().is_some_and(|(stored, _, _)| {
                stored.epoch == epoch && stored.config.revision == expected
            }) {
                return Err(StoreError::Unavailable(anyhow!(
                    "retained commit receipt capacity exhausted"
                )));
            }
        }
        resolve_operation_cas(
            self.load_stored_with_proof().await,
            epoch,
            &next,
            &stamp,
            uncertain,
        )
    }

    async fn publish_challenge(
        &self,
        token: &str,
        key_authorization: &str,
        ttl: Duration,
    ) -> StoreResult<()> {
        check_challenge(token, key_authorization, ttl)?;
        let expires = challenge_expiry(ttl);
        self.execute(
            Access::Mutation,
            "DELETE FROM hangang_acme_challenges WHERE expires_unix <= $1",
            &[&unix_now()],
        )
        .await?;
        self.execute(
            Access::Mutation,
            "INSERT INTO hangang_acme_challenges(token, key_authorization, expires_unix) VALUES ($1, $2, $3)
             ON CONFLICT (token) DO UPDATE SET key_authorization = EXCLUDED.key_authorization, expires_unix = EXCLUDED.expires_unix",
            &[&token, &key_authorization, &expires],
        )
        .await?;
        Ok(())
    }

    async fn lookup_challenge(&self, token: &str) -> StoreResult<Option<String>> {
        check_challenge_token(token)?;
        let row = self
            .query_opt(
                Access::Read,
                "SELECT key_authorization FROM hangang_acme_challenges WHERE token = $1 AND expires_unix > $2",
                &[&token, &unix_now()],
            )
            .await?;
        row.map(|row| postgres_column(&row, 0)).transpose()
    }

    async fn withdraw_challenge(&self, token: &str) -> StoreResult<()> {
        check_challenge_token(token)?;
        self.execute(
            Access::Mutation,
            "DELETE FROM hangang_acme_challenges WHERE token = $1",
            &[&token],
        )
        .await?;
        Ok(())
    }
}

async fn postgres_timeout<T>(
    operation: impl Future<Output = std::result::Result<T, tokio_postgres::Error>>,
) -> std::result::Result<T, PostgresFailure> {
    match tokio::time::timeout(Duration::from_secs(5), operation).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(PostgresFailure {
            answered: error.as_db_error().is_some(),
            error: anyhow!(error).context("PostgreSQL configuration store operation failed"),
        }),
        Err(_) => Err(PostgresFailure {
            answered: false,
            error: anyhow!("PostgreSQL configuration store operation timed out"),
        }),
    }
}

fn load_optional(path: &Path) -> StoreResult<Option<Config>> {
    match store::load(path) {
        Ok(config) => Ok(Some(config)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(file_error(error, Access::Read)),
    }
}

pub(crate) fn ensure_reader_compatibility(config: &Config) -> StoreResult<()> {
    if config.has_named_members() {
        return Err(StoreError::Invalid(anyhow!(
            "named pool members require fleet reader capability coordination; use local file authority until it is available"
        )));
    }
    Ok(())
}

pub(crate) fn encode(config: &Config) -> StoreResult<String> {
    config.validate().map_err(StoreError::Invalid)?;
    ensure_reader_compatibility(config)?;
    let json = serde_json::to_string(config)
        .map_err(|error| StoreError::Invalid(anyhow!(error).context("encode configuration")))?;
    if json.len() > MAX_CONFIG_BYTES {
        return Err(StoreError::Invalid(anyhow!("configuration exceeds 1 MiB")));
    }
    Ok(json)
}

pub(crate) fn decode(revision: u64, json: &str) -> StoreResult<Config> {
    if json.len() > MAX_CONFIG_BYTES {
        return Err(StoreError::Invalid(anyhow!(
            "stored configuration exceeds 1 MiB"
        )));
    }
    let config: Config = serde_json::from_str(json).map_err(|error| {
        StoreError::Invalid(anyhow!(error).context("decode stored configuration"))
    })?;
    if config.revision != revision {
        return Err(StoreError::Invalid(anyhow!(
            "stored revision does not match configuration JSON"
        )));
    }
    config.validate().map_err(StoreError::Invalid)?;
    ensure_reader_compatibility(&config)?;
    Ok(config)
}

pub(crate) fn next_revision(expected: u64) -> StoreResult<u64> {
    expected
        .checked_add(1)
        .ok_or_else(|| StoreError::Invalid(anyhow!("revision exhausted")))
}

fn revision_to_i64(revision: u64) -> StoreResult<i64> {
    i64::try_from(revision).map_err(|_| StoreError::Invalid(anyhow!("revision exceeds SQL BIGINT")))
}

fn i64_to_revision(revision: i64) -> StoreResult<u64> {
    u64::try_from(revision).map_err(|_| StoreError::Invalid(anyhow!("stored revision is negative")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_epochs_are_canonical_and_distinct() {
        let first = new_epoch().unwrap();
        let second = new_epoch().unwrap();
        assert_ne!(first, second);
        check_epoch(&first).unwrap();
        assert!(check_epoch(&first.to_uppercase()).is_err());
        assert!(check_epoch(&first[..31]).is_err());
        assert!(check_epoch("").is_err());
    }

    #[test]
    fn file_epoch_sidecar_is_read_through_a_strict_bound() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.epoch");
        std::fs::write(&path, vec![b'a'; MAX_CONFIG_BYTES]).unwrap();
        let error = file_epoch(&path).unwrap_err();
        assert!(matches!(error, StoreError::Invalid(_)), "{error}");
        assert!(error.to_string().contains("exceeds"), "{error}");
    }

    #[test]
    fn legacy_epoch_is_never_visible_before_its_complete_contents() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.epoch");
        let candidate = new_epoch().unwrap();
        let (staged_tx, staged_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let writer_path = path.clone();
        let writer = std::thread::spawn(move || {
            publish_epoch_if_absent(&writer_path, &candidate, || {
                staged_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
            .unwrap()
        });
        staged_rx.recv().unwrap();
        assert!(!path.exists(), "unfinished sidecar became visible");
        let winner = file_epoch(&path).unwrap();
        check_epoch(&winner).unwrap();
        release_tx.send(()).unwrap();
        assert!(
            !writer.join().unwrap(),
            "paused writer overwrote the winner"
        );
        assert_eq!(file_epoch(&path).unwrap(), winner);
    }

    #[test]
    fn sqlite_rejects_oversized_text_without_returning_it_from_sql() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        initialize_sqlite(&connection).unwrap();
        let epoch = new_epoch().unwrap();
        connection
            .execute(
                "INSERT INTO hangang_config(singleton, revision, config_json, epoch) VALUES(1, 0, ?1, ?2)",
                rusqlite::params!["x".repeat(MAX_CONFIG_BYTES + 1), epoch],
            )
            .unwrap();
        let error = sqlite_load(&connection).unwrap_err();
        assert!(error.to_string().contains("exceeds 1 MiB"), "{error}");

        connection
            .execute("DELETE FROM hangang_config", [])
            .unwrap();
        connection
            .execute(
                "INSERT INTO hangang_config(singleton, revision, config_json, epoch) VALUES(1, 0, ?1, ?2)",
                rusqlite::params![encode(&Config::default()).unwrap(), "a".repeat(EPOCH_LEN + 1)],
            )
            .unwrap();
        let error = sqlite_load(&connection).unwrap_err();
        assert!(error.to_string().contains("epoch exceeds"), "{error}");
    }

    #[test]
    fn store_challenge_validator_enforces_shared_limits() {
        let ttl = Duration::from_secs(30);
        check_challenge("abc-_09", "key.auth", ttl).unwrap();
        check_challenge(
            &"a".repeat(128),
            &"k".repeat(512),
            Duration::from_secs(3600),
        )
        .unwrap();
        for (token, key, ttl) in [
            ("", "k", ttl),
            ("bad token", "k", ttl),
            ("bad.token", "k", ttl),
            (&"a".repeat(129), "k", ttl),
            ("ok", "", ttl),
            ("ok", &"k".repeat(513), ttl),
            ("ok", "tab\there", ttl),
            ("ok", "naïve", ttl),
            ("ok", "k", Duration::from_millis(999)),
            ("ok", "k", Duration::from_secs(3601)),
        ] {
            assert!(
                matches!(
                    check_challenge(token, key, ttl),
                    Err(StoreError::Invalid(_))
                ),
                "{token:?} {key:?} {ttl:?}"
            );
        }
    }

    #[test]
    fn store_error_display_prefixes_and_transport_classification() {
        let unavailable = StoreError::Unavailable(anyhow!("down"));
        let invalid = StoreError::Invalid(anyhow!("bad"));
        let indeterminate = StoreError::Indeterminate(anyhow!("lost"));
        assert!(unavailable.is_transport());
        assert!(!invalid.is_transport());
        assert!(indeterminate.is_transport());
        assert_eq!(unavailable.to_string(), "store unavailable: down");
        assert_eq!(invalid.to_string(), "store content invalid: bad");
        assert_eq!(
            indeterminate.to_string(),
            "store mutation indeterminate: lost"
        );
        assert_eq!(
            Access::Read.transport(anyhow!("x")).to_string(),
            "store unavailable: x"
        );
        assert!(matches!(
            Access::Mutation.transport(anyhow!("x")),
            StoreError::Indeterminate(_)
        ));
    }

    #[test]
    fn store_cas_resolution_applies_only_the_identical_document() {
        let epoch = new_epoch().unwrap();
        let next = Config {
            revision: 6,
            ..Config::default()
        };
        let current = Stored {
            epoch: epoch.clone(),
            config: next.clone(),
        };
        assert!(matches!(
            resolve_cas(current.clone(), &epoch, &next),
            CasResult::Applied(_)
        ));
        let foreign = new_epoch().unwrap();
        assert!(matches!(
            resolve_cas(current.clone(), &foreign, &next),
            CasResult::Conflict { .. }
        ));
        let different = Config {
            revision: 6,
            certificates: vec![],
            http: vec![],
            tcp: vec![],
            workload_http: Vec::new(),
            cache: Some(Default::default()),
            settings: Default::default(),
            cache_generation_floor: 0,
        };
        assert!(matches!(
            resolve_cas(current, &epoch, &different),
            CasResult::Conflict { .. }
        ));
    }

    fn document(revision: u64, dot_segments: bool) -> Config {
        let mut config = Config {
            revision,
            ..Config::default()
        };
        config.settings.allow_dot_segments = Some(dot_segments);
        config
    }

    fn test_stamp(id: char, config: &Config) -> OperationStamp {
        OperationStamp {
            authority_id: "a".repeat(32),
            operation_id: id.to_string().repeat(32),
            candidate_sha256: sha256_hex(encode(config).unwrap().as_bytes()),
        }
    }

    fn sequenced_test_stamp(authority: &str, seq: u64, config: &Config) -> SequencedOperationStamp {
        SequencedOperationStamp {
            authority_id: authority.to_owned(),
            acceptance_seq: seq,
            operation_id: canonical_operation_id(authority, seq).unwrap(),
            candidate_sha256: sha256_hex(encode(config).unwrap().as_bytes()),
        }
    }

    #[tokio::test]
    async fn sqlite_sequenced_receipts_fence_replay_after_later_commit_and_reseed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sequenced.db");
        let store = SqliteConfigStore::open(&path).await.unwrap();
        assert!(store.supports_sequenced_operation_cas());
        let initial = store.bootstrap(document(0, false)).await.unwrap();
        let authority = "a".repeat(32);
        let first = sequenced_test_stamp(&authority, 7, &document(1, false));
        assert!(matches!(
            store
                .compare_and_swap_operation_v2(&initial.epoch, 0, document(0, false), first.clone())
                .await
                .unwrap(),
            CasResult::Applied(_)
        ));
        let observation = store.lookup_commit_receipt_v2(&authority, 7).await.unwrap();
        assert_eq!(observation.high_water, 7);
        assert_eq!(observation.registered_authorities, 1);
        assert_eq!(observation.stored_records, 1);
        assert_eq!(observation.receipt.unwrap().stamp, first);
        let second = sequenced_test_stamp(&authority, 9, &document(2, true));
        assert!(matches!(
            store
                .compare_and_swap_operation_v2(&initial.epoch, 1, document(0, true), second.clone())
                .await
                .unwrap(),
            CasResult::Applied(_)
        ));
        assert!(
            matches!(store.compare_and_swap_operation_v2(&initial.epoch,0,document(0,false),first.clone()).await.unwrap(),CasResult::Conflict{current} if current.config.revision==2)
        );
        let old = sequenced_test_stamp(&authority, 8, &document(3, false));
        assert!(
            matches!(store.compare_and_swap_operation_v2(&initial.epoch,2,document(0,false),old).await.unwrap(),CasResult::Conflict{current} if current.config.revision==2)
        );
        let mut reused = first.clone();
        reused.candidate_sha256 = sha256_hex(encode(&document(3, true)).unwrap().as_bytes());
        assert!(matches!(
            store
                .compare_and_swap_operation_v2(&initial.epoch, 2, document(0, true), reused)
                .await,
            Err(StoreError::Invalid(_))
        ));
        let old_writer = rusqlite::Connection::open(&path).unwrap();
        assert!(
            old_writer
                .execute(
                    "UPDATE hangang_config SET revision=3,config_json=?1 WHERE singleton=1",
                    [encode(&document(3, true)).unwrap()]
                )
                .is_err()
        );
        old_writer
            .execute("DELETE FROM hangang_config", [])
            .unwrap();
        let reseeded = store.bootstrap(document(0, false)).await.unwrap();
        assert_ne!(reseeded.epoch, initial.epoch);
        assert_eq!(
            store
                .lookup_commit_receipt_v2(&authority, 7)
                .await
                .unwrap()
                .high_water,
            9
        );
        assert!(matches!(
            store
                .compare_and_swap_operation_v2(&reseeded.epoch, 0, document(0, false), first)
                .await,
            Err(StoreError::Invalid(_))
        ));
        assert_eq!(
            store.load_latest().await.unwrap().unwrap().config.revision,
            0
        );
    }

    #[test]
    fn operation_resolver_requires_exact_stamp_even_for_identical_document() {
        let next = document(1, false);
        let encoded = encode(&next).unwrap();
        let epoch = new_epoch().unwrap();
        let first = test_stamp('b', &next);
        let second = test_stamp('c', &next);
        let current = || {
            Ok(Some((
                Stored {
                    epoch: epoch.clone(),
                    config: next.clone(),
                },
                encoded.clone(),
                Some(OperationMetadata {
                    revision: 1,
                    stamp: first.clone(),
                    version: 1,
                    sequence: None,
                }),
            )))
        };
        assert!(matches!(
            resolve_operation_cas(current(), &epoch, &next, &first, false).unwrap(),
            CasResult::Applied(_)
        ));
        assert!(matches!(
            resolve_operation_cas(current(), &epoch, &next, &second, false).unwrap(),
            CasResult::Conflict { .. }
        ));
        assert!(matches!(
            resolve_operation_cas(current(), &epoch, &next, &second, true).unwrap_err(),
            StoreError::Indeterminate(_)
        ));
        let different = document(2, true);
        assert!(matches!(
            resolve_operation_cas(current(), &epoch, &different, &first, false).unwrap_err(),
            StoreError::Invalid(_)
        ));
        assert!(matches!(
            resolve_operation_cas(current(), &epoch, &different, &first, true).unwrap_err(),
            StoreError::Indeterminate(_)
        ));
        // A committed, unanswered write followed by an older SQL writer can
        // leave this same ID on a newer, different document. It is not proof
        // of reuse by the caller, nor proof that the first write never landed.
        let old_writer_current = Ok(Some((
            Stored {
                epoch: epoch.clone(),
                config: different.clone(),
            },
            encode(&different).unwrap(),
            Some(OperationMetadata {
                revision: 1,
                stamp: first.clone(),
                version: 1,
                sequence: None,
            }),
        )));
        assert!(matches!(
            resolve_operation_cas(old_writer_current, &epoch, &next, &first, true).unwrap_err(),
            StoreError::Indeterminate(_)
        ));
        assert!(matches!(
            validate_operation_stamp(&first, &encode(&different).unwrap()),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn retained_receipt_recovery_read_keeps_unanswered_write_indeterminate() {
        let failure: StoreResult<()> = Err(StoreError::Unavailable(anyhow!("read failed")));
        assert!(matches!(
            receipt_recovery_read(failure, true),
            Err(StoreError::Indeterminate(_))
        ));
        let failure: StoreResult<()> = Err(StoreError::Unavailable(anyhow!("read failed")));
        assert!(matches!(
            receipt_recovery_read(failure, false),
            Err(StoreError::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn sqlite_current_operation_proof_is_atomic_and_old_writer_is_unproven() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.db");
        let store = SqliteConfigStore::open(&path).await.unwrap();
        assert!(store.supports_operation_cas());
        let initial = store.bootstrap(document(0, false)).await.unwrap();
        let next = document(1, false);
        let stamp = test_stamp('b', &next);
        let first = store
            .compare_and_swap_operation(&initial.epoch, 0, document(0, false), stamp.clone())
            .await
            .unwrap();
        assert!(matches!(first, CasResult::Applied(_)));
        assert_eq!(
            store.load_current_operation_proof().await.unwrap(),
            Some(OperationProof {
                epoch: initial.epoch.clone(),
                revision: 1,
                stamp: stamp.clone()
            })
        );
        assert!(matches!(
            store
                .compare_and_swap_operation(&initial.epoch, 0, document(0, false), stamp.clone())
                .await
                .unwrap(),
            CasResult::Applied(_)
        ));
        assert!(matches!(
            store
                .compare_and_swap_operation(
                    &initial.epoch,
                    0,
                    document(0, false),
                    test_stamp('c', &next)
                )
                .await
                .unwrap(),
            CasResult::Conflict { .. }
        ));
        assert!(matches!(
            store
                .compare_and_swap_operation(
                    &initial.epoch,
                    1,
                    document(0, true),
                    test_stamp('b', &document(2, true))
                )
                .await
                .unwrap_err(),
            StoreError::Invalid(_)
        ));
        // A pre-upgrade SQL writer leaves the stamp and generation unchanged;
        // the migration gate rejects that mutation rather than carrying stale
        // identity into a newer document.
        let old_writer = rusqlite::Connection::open(&path).unwrap();
        assert!(
            old_writer
                .execute(
                    "UPDATE hangang_config SET revision=2,config_json=?1 WHERE singleton=1",
                    rusqlite::params![encode(&document(2, true)).unwrap()],
                )
                .is_err()
        );
        assert_eq!(
            store
                .load_current_operation_proof()
                .await
                .unwrap()
                .unwrap()
                .revision,
            1
        );
        assert_eq!(
            store.load_latest().await.unwrap().unwrap().config,
            document(1, false)
        );
        assert!(matches!(
            store
                .compare_and_swap(&initial.epoch, 1, document(0, false))
                .await
                .unwrap(),
            CasResult::Applied(_)
        ));
        assert_eq!(store.load_current_operation_proof().await.unwrap(), None);
    }

    /// F5: a legacy reader that loses the race against a wipe-and-reseed
    /// must return the reseeded row, never the new epoch paired with the
    /// document it read before the replacement.
    #[test]
    fn store_sqlite_legacy_upgrade_returns_the_replaced_row_not_a_mixed_pair() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy.db");
        let reader = rusqlite::Connection::open(&path).unwrap();
        enable_wal(&reader).unwrap();
        initialize_sqlite(&reader).unwrap();
        let old = document(7, false);
        let new = document(7, true);
        assert_ne!(old, new);
        reader
            .execute(
                "INSERT INTO hangang_config(singleton, revision, config_json) VALUES (1, 7, ?1)",
                rusqlite::params![encode(&old).unwrap()],
            )
            .unwrap();
        let reseeded_epoch = new_epoch().unwrap();

        let replaced = {
            let path = path.clone();
            let reseeded_epoch = reseeded_epoch.clone();
            let new = new.clone();
            sqlite_load_interleaved(&reader, move || {
                // Another instance wipes and reseeds the store at the same
                // revision after the reader saw the legacy row and before
                // its guarded epoch update runs.
                let replacer = rusqlite::Connection::open(&path).unwrap();
                replacer
                    .execute_batch("BEGIN IMMEDIATE; DELETE FROM hangang_config; COMMIT;")
                    .unwrap();
                replacer
                    .execute(
                        "INSERT INTO hangang_config(singleton, revision, config_json, epoch) VALUES (1, 7, ?1, ?2)",
                        rusqlite::params![encode(&new).unwrap(), reseeded_epoch],
                    )
                    .unwrap();
            })
            .unwrap()
            .unwrap()
        };
        assert_eq!(replaced.epoch, reseeded_epoch);
        assert_eq!(
            replaced.config, new,
            "the reseeded epoch must carry the reseeded document"
        );
        assert_eq!(sqlite_load(&reader).unwrap().unwrap(), replaced);
        let durable: (String, String) = reader
            .query_row(
                "SELECT epoch, config_json FROM hangang_config WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            durable.0, reseeded_epoch,
            "the loser must not overwrite the epoch"
        );
        assert_eq!(durable.1, encode(&new).unwrap());
    }

    fn failure(answered: bool) -> PostgresFailure {
        PostgresFailure {
            error: anyhow!(if answered { "rejected" } else { "unanswered" }),
            answered,
        }
    }

    /// F6: the decision table of `PostgresConfigStore::run` for a statement
    /// whose first attempt failed.
    #[test]
    fn store_postgres_retry_settlement_carries_first_attempt_uncertainty() {
        for access in [Access::Read, Access::Mutation] {
            // A retry that succeeds after an unanswered mutation is uncertain;
            // after an answered (rejected) first attempt it is not.
            let settled = settle(access, failure(false), Retry::Sent(Ok(7))).unwrap();
            assert_eq!(settled.value, 7);
            assert_eq!(settled.uncertain, access == Access::Mutation);
            let settled = settle(access, failure(true), Retry::Sent(Ok(7))).unwrap();
            assert!(!settled.uncertain);

            // Failed or unsent retries.
            for (first_answered, retry, indeterminate_if_mutation) in [
                (false, Retry::Sent(Err(failure(true))), true),
                (false, Retry::Sent(Err(failure(false))), true),
                (
                    false,
                    Retry::<u8>::Unsent(anyhow!("reconnect refused")),
                    true,
                ),
                (true, Retry::Sent(Err(failure(false))), true),
                (true, Retry::Sent(Err(failure(true))), false),
                (true, Retry::Unsent(anyhow!("reconnect refused")), false),
            ] {
                let error = settle(access, failure(first_answered), retry).unwrap_err();
                let expect_indeterminate = access == Access::Mutation && indeterminate_if_mutation;
                assert_eq!(
                    matches!(error, StoreError::Indeterminate(_)),
                    expect_indeterminate,
                    "{access:?} first_answered={first_answered}: {error}"
                );
                if !expect_indeterminate {
                    assert!(matches!(error, StoreError::Unavailable(_)), "{error}");
                }
                assert!(
                    format!("{error}").contains(if first_answered {
                        "rejected"
                    } else {
                        "unanswered"
                    }),
                    "the first failure stays in the chain: {error}"
                );
            }
        }
    }

    /// F6: after a 0-row retry, only our own document at `expected + 1`
    /// proves the outcome of an unacknowledged write. Every other durable
    /// state is `Indeterminate` — (`epoch`, `expected`) and another document
    /// at `expected + 1` included, because a same-epoch backup restore
    /// between the retry and the recovery read produces them after our write
    /// committed (see `store_unchanged_cas_never_trusts_a_restored_history`).
    #[test]
    fn store_unchanged_cas_resolution_reports_unprovable_outcomes_as_indeterminate() {
        let epoch = new_epoch().unwrap();
        let foreign = new_epoch().unwrap();
        let next = document(8, true);
        let stored = |epoch: &str, config: Config| {
            Ok(Some(Stored {
                epoch: epoch.to_owned(),
                config,
            }))
        };
        let resolve = |current: StoreResult<Option<Stored>>, uncertain: bool| {
            resolve_unchanged_cas(current, &epoch, &next, uncertain)
        };

        for uncertain in [false, true] {
            // (epoch, expected + 1, next) is our write.
            assert!(matches!(
                resolve(stored(&epoch, next.clone()), uncertain).unwrap(),
                CasResult::Applied(ref applied) if applied.config == next
            ));
        }

        // Unprovable states: the expected revision itself and another
        // document at expected + 1 (what a restore of a backup taken before
        // our write leaves behind, the latter once another writer took the
        // slot again), an intervening commit, a revision from before ours,
        // another authority, an empty store, and a failed read.
        let unprovable = [
            stored(&epoch, document(7, false)),
            stored(&epoch, document(8, false)),
            stored(&epoch, document(9, false)),
            stored(&epoch, document(6, true)),
            stored(&foreign, next.clone()),
            Ok(None),
            Err(StoreError::Unavailable(anyhow!("connection reset"))),
            Err(StoreError::Invalid(anyhow!("not json"))),
        ];
        for current in unprovable {
            let description = format!("{current:?}");
            let durable_revision = match &current {
                Ok(Some(durable)) => Some(durable.config.revision),
                _ => None,
            };
            // Certain: the plain rules apply (conflict, not initialized, or
            // the read's own error).
            let certain = match &current {
                Ok(Some(durable)) => stored(durable.epoch.as_str(), durable.config.clone()),
                Ok(None) => Ok(None),
                Err(StoreError::Unavailable(error)) => {
                    Err(StoreError::Unavailable(anyhow!(error.to_string())))
                }
                Err(StoreError::Invalid(error)) => {
                    Err(StoreError::Invalid(anyhow!(error.to_string())))
                }
                Err(StoreError::Indeterminate(_)) => unreachable!(),
            };
            match resolve(certain, false) {
                Ok(CasResult::Conflict { .. }) => {
                    assert!(matches!(current, Ok(Some(_))), "{description}")
                }
                Ok(CasResult::Applied(_)) => panic!("{description}: applied"),
                Err(StoreError::Invalid(_)) => assert!(
                    matches!(current, Ok(None) | Err(StoreError::Invalid(_))),
                    "{description}"
                ),
                Err(StoreError::Unavailable(_)) => {
                    assert!(
                        matches!(current, Err(StoreError::Unavailable(_))),
                        "{description}"
                    )
                }
                Err(StoreError::Indeterminate(error)) => {
                    panic!("{description}: indeterminate without uncertainty: {error}")
                }
            }
            // Uncertain: never a conflict, never "nothing changed".
            let error = resolve(current, true).unwrap_err();
            assert!(
                matches!(error, StoreError::Indeterminate(_)),
                "{description}: {error}"
            );
            assert!(error.is_transport());
            assert!(
                error
                    .to_string()
                    .starts_with("store mutation indeterminate: "),
                "{error}"
            );
            if let Some(revision) = durable_revision {
                let text = error.to_string();
                assert!(
                    text.contains("revision 8 was not acknowledged")
                        && text.contains(&format!("revision {revision}) cannot prove")),
                    "the message names our revision and the durable one: {text}"
                );
            }
        }
        let error = resolve(
            Err(StoreError::Unavailable(anyhow!("connection reset"))),
            true,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("connection reset"),
            "the read failure stays in the chain: {error}"
        );
    }

    /// The durable history of one epoch is not monotonic across a backup
    /// restore: write 7 -> 8 commits but its acknowledgement is lost, another
    /// writer reaches 9, the retry changes nothing, and before the recovery
    /// read the operator restores the backup taken at 7 under the same
    /// bootstrap. The read then sees (epoch, 7) — or (epoch, 8, another
    /// document) once a third writer took the slot again — although our
    /// write committed and was visible. Neither state may be reported as a
    /// conflict.
    #[test]
    fn store_unchanged_cas_never_trusts_a_restored_history() {
        let epoch = new_epoch().unwrap();
        let ours = document(8, true);
        let restored = |config: Config| {
            Ok(Some(Stored {
                epoch: epoch.clone(),
                config,
            }))
        };
        for after_restore in [document(7, false), document(8, false)] {
            let description = format!("{after_restore:?}");
            let error = resolve_unchanged_cas(restored(after_restore.clone()), &epoch, &ours, true)
                .unwrap_err();
            assert!(
                matches!(error, StoreError::Indeterminate(_)),
                "{description}: {error}"
            );
            // The same state after an answered (never committed) attempt is
            // the ordinary conflict.
            assert!(matches!(
                resolve_unchanged_cas(restored(after_restore.clone()), &epoch, &ours, false)
                    .unwrap(),
                CasResult::Conflict { ref current } if current.config == after_restore
            ));
        }
        // A restore cannot fake our own document at 8: it is our write.
        assert!(matches!(
            resolve_unchanged_cas(restored(ours.clone()), &epoch, &ours, true).unwrap(),
            CasResult::Applied(ref applied) if applied.config == ours
        ));
    }

    /// The read after bootstrap's idempotent insert. An answered insert left
    /// a row behind, so an empty store afterwards is invalid content and a
    /// failed read keeps its own class. After an unanswered insert the seed
    /// may be the shared authority, and neither an empty store (the row can
    /// have been wiped after the insert committed) nor a failed read proves
    /// the outcome: both are `Indeterminate`, never "nothing changed".
    #[test]
    fn store_bootstrap_read_after_unanswered_insert_is_indeterminate() {
        let seeded = Stored {
            epoch: new_epoch().unwrap(),
            config: document(0, true),
        };
        for uncertain in [false, true] {
            assert_eq!(
                resolve_bootstrap_read(Ok(Some(seeded.clone())), uncertain).unwrap(),
                seeded
            );
        }
        let wiped = resolve_bootstrap_read(Ok(None), false).unwrap_err();
        assert!(
            matches!(wiped, StoreError::Invalid(_)),
            "an answered insert left a row, so an empty store is a wipe: {wiped}"
        );
        assert!(!wiped.is_transport());
        let unproven = resolve_bootstrap_read(Ok(None), true).unwrap_err();
        assert!(
            matches!(unproven, StoreError::Indeterminate(_)),
            "an empty store after an unanswered insert proves nothing: {unproven}"
        );
        assert!(unproven.is_transport());
        assert!(
            unproven
                .to_string()
                .contains("bootstrap insert was not acknowledged"),
            "{unproven}"
        );
        for (failed, text) in [
            (
                StoreError::Unavailable(anyhow!("connection reset")),
                "connection reset",
            ),
            (StoreError::Invalid(anyhow!("not json")), "not json"),
        ] {
            let unavailable = matches!(failed, StoreError::Unavailable(_));
            let certain = resolve_bootstrap_read(Err(failed), false).unwrap_err();
            assert_eq!(
                matches!(certain, StoreError::Unavailable(_)),
                unavailable,
                "an answered insert keeps the read's own error: {certain}"
            );
            assert!(!matches!(certain, StoreError::Indeterminate(_)));

            let failed = if unavailable {
                StoreError::Unavailable(anyhow!(text))
            } else {
                StoreError::Invalid(anyhow!(text))
            };
            let error = resolve_bootstrap_read(Err(failed), true).unwrap_err();
            assert!(
                matches!(error, StoreError::Indeterminate(_)),
                "{text}: {error}"
            );
            assert!(error.is_transport());
            assert!(
                error.to_string().contains(text)
                    && error
                        .to_string()
                        .contains("bootstrap insert was not acknowledged"),
                "the read failure stays in the chain: {error}"
            );
        }
    }
}
