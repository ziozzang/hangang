//! Instance-local, durable administrator accounts and revocable bearer sessions.
//! Password derivation and SQLite I/O run on bounded blocking workers, never
//! on the async administration reactor.

use anyhow::{Context, Result, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

const MAX_USERS: i64 = 256;
const MAX_SESSIONS: i64 = 4096;
const SESSION_SECONDS: i64 = 8 * 60 * 60;
const MAX_SAFE_ID: i64 = 9_007_199_254_740_991;
pub const AUDIT_CAPACITY: i64 = 100_000;
pub const CONFIG_OPERATION_CAPACITY: i64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Viewer,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Viewer => "viewer",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "admin" => Ok(Self::Admin),
            "viewer" => Ok(Self::Viewer),
            _ => anyhow::bail!("invalid stored administrator role"),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub role: Role,
    pub enabled: bool,
}

#[derive(Debug)]
pub struct Login {
    pub token: String,
    pub expires_in_seconds: i64,
    pub user: User,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    NotFound,
    Conflict,
    Applied,
}

/// The account used for a management mutation. `Session` contains an opaque
/// bearer secret, so this type deliberately has no Debug or Serialize impl.
pub enum MutationAuthority {
    System,
    Session(String),
}

#[derive(Debug)]
pub struct AuthorizationRevoked;

impl std::fmt::Display for AuthorizationRevoked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("administrator mutation authority is no longer valid")
    }
}

impl std::error::Error for AuthorizationRevoked {}

#[derive(Debug)]
pub struct AuditCapacity;
impl std::fmt::Display for AuditCapacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("administrator audit capacity exhausted")
    }
}
impl std::error::Error for AuditCapacity {}

#[derive(Debug)]
pub struct AuditConflict;
impl std::fmt::Display for AuditConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("administrator audit revision or prune range conflicted")
    }
}
impl std::error::Error for AuditConflict {}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Baseline,
    Bootstrap,
    Create,
    Update,
    Delete,
    Prune,
}
impl AuditAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Bootstrap => "bootstrap",
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Prune => "prune",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "baseline" => Ok(Self::Baseline),
            "bootstrap" => Ok(Self::Bootstrap),
            "create" => Ok(Self::Create),
            "update" => Ok(Self::Update),
            "delete" => Ok(Self::Delete),
            "prune" => Ok(Self::Prune),
            _ => anyhow::bail!("invalid stored audit action"),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditActorKind {
    System,
    Account,
}
impl AuditActorKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Account => "account",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "system" => Ok(Self::System),
            "account" => Ok(Self::Account),
            _ => anyhow::bail!("invalid stored audit actor"),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct AuditUserState {
    pub role: Role,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditRecord {
    pub id: i64,
    pub time_unix_ms: i64,
    pub action: AuditAction,
    pub actor_kind: AuditActorKind,
    pub actor_user_id: Option<i64>,
    pub target_user_id: Option<i64>,
    pub before: Option<AuditUserState>,
    pub after: Option<AuditUserState>,
    pub password_changed: bool,
    pub affected_count: u64,
    pub through_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct AuditPage {
    pub scope: &'static str,
    pub coverage: [&'static str; 5],
    pub started_at_unix_ms: i64,
    pub records: Vec<AuditRecord>,
    pub next_after: i64,
    pub oldest_id: Option<i64>,
    pub latest_id: i64,
    pub pruned_through: i64,
    pub truncated: bool,
    pub stored_records: i64,
    pub capacity: i64,
    pub writes_available: bool,
    pub server_time_unix_ms: i64,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
pub struct AuditPruneResult {
    pub pruned_records: u64,
    pub record: AuditRecord,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigStoreKind {
    LocalFile,
    SharedStore,
}
impl ConfigStoreKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::LocalFile => "local_file",
            Self::SharedStore => "shared_store",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "local_file" => Ok(Self::LocalFile),
            "shared_store" => Ok(Self::SharedStore),
            _ => anyhow::bail!("invalid stored config operation store kind"),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigOperationState {
    Accepted,
    CandidateActivated,
    Conflict,
    Failed,
    Indeterminate,
}
impl ConfigOperationState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::CandidateActivated => "candidate_activated",
            Self::Conflict => "conflict",
            Self::Failed => "failed",
            Self::Indeterminate => "indeterminate",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "accepted" => Ok(Self::Accepted),
            "candidate_activated" => Ok(Self::CandidateActivated),
            "conflict" => Ok(Self::Conflict),
            "failed" => Ok(Self::Failed),
            "indeterminate" => Ok(Self::Indeterminate),
            _ => anyhow::bail!("invalid stored config operation state"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConfigAcceptRequest {
    pub store_kind: ConfigStoreKind,
    pub authority_epoch: Option<String>,
    pub expected_revision: u64,
    pub candidate_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConfigOperation {
    pub id: i64,
    pub operation_id: String,
    pub authority_id: String,
    pub actor_kind: AuditActorKind,
    pub actor_user_id: Option<i64>,
    pub accepted_at_unix_ms: i64,
    pub expected_revision: u64,
    pub candidate_sha256: String,
    pub store_kind: ConfigStoreKind,
    pub authority_epoch: Option<String>,
    pub state: ConfigOperationState,
    pub finished_at_unix_ms: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ConfigOperationPage {
    pub scope: &'static str,
    pub coverage: [&'static str; 2],
    pub authority_id: String,
    pub started_at_unix_ms: i64,
    pub records: Vec<ConfigOperation>,
    pub next_after: i64,
    pub oldest_id: Option<i64>,
    pub latest_id: i64,
    pub stored_records: i64,
    pub capacity: i64,
    pub writes_available: bool,
    pub server_time_unix_ms: i64,
    pub has_more: bool,
}

#[derive(Debug)]
pub struct ConfigOperationCapacity;
impl std::fmt::Display for ConfigOperationCapacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("local config operation capacity exhausted")
    }
}
impl std::error::Error for ConfigOperationCapacity {}

#[derive(Debug)]
pub struct ConfigOperationConflict;
impl std::fmt::Display for ConfigOperationConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("local config operation state conflict")
    }
}
impl std::error::Error for ConfigOperationConflict {}

pub struct Store {
    path: PathBuf,
    password_workers: Arc<Semaphore>,
}

impl Store {
    pub fn open(path: PathBuf) -> Result<Self> {
        ensure!(
            path.is_absolute()
                && path.as_os_str().as_encoded_bytes().len() <= 4096
                && path
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
            "administrator user database needs a normalized absolute path"
        );
        let parent = path
            .parent()
            .context("administrator database parent missing")?;
        let parent_metadata = std::fs::symlink_metadata(parent)?;
        ensure!(
            parent_metadata.file_type().is_dir()
                && parent_metadata.permissions().mode() & 0o022 == 0,
            "administrator database parent must be a directory not writable by group or others"
        );
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        let file = options
            .open(&path)
            .context("open administrator user database")?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file(),
            "administrator user database is not a regular file"
        );
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "administrator user database must be private"
        );
        for suffix in ["-wal", "-shm"] {
            let mut name = path.as_os_str().to_os_string();
            name.push(suffix);
            let sibling = PathBuf::from(name);
            match std::fs::symlink_metadata(&sibling) {
                Ok(metadata) => ensure!(
                    metadata.file_type().is_file() && metadata.permissions().mode() & 0o077 == 0,
                    "administrator user database sidecar must be a private regular file"
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        drop(file);
        let mut connection = connection(&path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = transaction.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        ensure!(
            version <= 3,
            "administrator user database schema is newer than this binary"
        );
        if version < 2 {
            transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin','viewer')),
                enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
                password_epoch INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash BLOB PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
            CREATE TABLE admin_audit_meta (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                started_at_unix_ms INTEGER NOT NULL,
                pruned_through INTEGER NOT NULL DEFAULT 0,
                stored_records INTEGER NOT NULL DEFAULT 0,
                next_user_id INTEGER NOT NULL,
                next_audit_id INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE admin_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT CHECK(id BETWEEN 1 AND 9007199254740991),
                time_unix_ms INTEGER NOT NULL CHECK(time_unix_ms BETWEEN 0 AND 9007199254740991),
                action TEXT NOT NULL CHECK(action IN ('baseline','bootstrap','create','update','delete','prune')),
                actor_kind TEXT NOT NULL CHECK(actor_kind IN ('system','account')),
                actor_user_id INTEGER CHECK(actor_user_id BETWEEN 1 AND 9007199254740991),
                target_user_id INTEGER CHECK(target_user_id BETWEEN 1 AND 9007199254740991),
                before_role TEXT CHECK(before_role IN ('admin','viewer')),
                before_enabled INTEGER CHECK(before_enabled IN (0,1)),
                after_role TEXT CHECK(after_role IN ('admin','viewer')),
                after_enabled INTEGER CHECK(after_enabled IN (0,1)),
                password_changed INTEGER NOT NULL CHECK(password_changed IN (0,1)),
                affected_count INTEGER NOT NULL CHECK(affected_count BETWEEN 0 AND 9007199254740991),
                through_id INTEGER CHECK(through_id BETWEEN 1 AND 9007199254740991),
                CHECK((actor_kind='system' AND actor_user_id IS NULL) OR (actor_kind='account' AND actor_user_id IS NOT NULL)),
                CHECK((before_role IS NULL AND before_enabled IS NULL) OR (before_role IS NOT NULL AND before_enabled IS NOT NULL)),
                CHECK((after_role IS NULL AND after_enabled IS NULL) OR (after_role IS NOT NULL AND after_enabled IS NOT NULL)),
                CHECK(COALESCE(
                    (action='baseline' AND actor_kind='system' AND target_user_id IS NULL AND before_role IS NULL AND after_role IS NULL AND password_changed=0 AND through_id IS NULL)
                    OR (action='bootstrap' AND actor_kind='system' AND target_user_id IS NOT NULL AND before_role IS NULL AND after_role='admin' AND after_enabled=1 AND password_changed=1 AND affected_count=1 AND through_id IS NULL)
                    OR (action='create' AND target_user_id IS NOT NULL AND before_role IS NULL AND after_role IS NOT NULL AND after_enabled=1 AND password_changed=1 AND affected_count=1 AND through_id IS NULL)
                    OR (action='update' AND target_user_id IS NOT NULL AND before_role IS NOT NULL AND after_role IS NOT NULL AND affected_count=1 AND through_id IS NULL)
                    OR (action='delete' AND target_user_id IS NOT NULL AND before_role IS NOT NULL AND after_role IS NULL AND password_changed=0 AND affected_count=1 AND through_id IS NULL)
                    OR (action='prune' AND target_user_id IS NULL AND before_role IS NULL AND after_role IS NULL AND password_changed=0 AND affected_count>0 AND through_id IS NOT NULL AND through_id<id)
                ,0))
            );",
        )?;
            let started_at = now_ms()?;
            let max_id: i64 =
                transaction.query_row("SELECT COALESCE(MAX(id),0) FROM users", [], |row| {
                    row.get(0)
                })?;
            ensure!(max_id < MAX_SAFE_ID, "administrator user id exhausted");
            transaction.execute("INSERT INTO admin_audit_meta(singleton,started_at_unix_ms,next_user_id) VALUES(1,?1,?2)",params![started_at,max_id+1])?;
            let existing_count: i64 =
                transaction.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
            append_audit(
                &transaction,
                audit_record(
                    AuditAction::Baseline,
                    AuditActorKind::System,
                    None,
                    None,
                    None,
                    None,
                    false,
                    u64::try_from(existing_count)?,
                    None,
                )?,
            )?;
            transaction.execute_batch("PRAGMA user_version=2")?;
        }
        if version < 3 {
            transaction.execute_batch("CREATE TABLE admin_config_operation_meta (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                authority_id TEXT NOT NULL,
                started_at_unix_ms INTEGER NOT NULL,
                next_id INTEGER NOT NULL DEFAULT 1,
                stored_records INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE admin_config_operations (
                id INTEGER PRIMARY KEY CHECK(id BETWEEN 1 AND 9007199254740991),
                operation_id TEXT NOT NULL UNIQUE,
                authority_id TEXT NOT NULL,
                actor_kind TEXT NOT NULL CHECK(actor_kind IN ('system','account')),
                actor_user_id INTEGER CHECK(actor_user_id BETWEEN 1 AND 9007199254740991),
                accepted_at_unix_ms INTEGER NOT NULL CHECK(accepted_at_unix_ms BETWEEN 0 AND 9007199254740991),
                expected_revision INTEGER NOT NULL CHECK(expected_revision BETWEEN 0 AND 9007199254740991),
                candidate_sha256 TEXT NOT NULL,
                store_kind TEXT NOT NULL CHECK(store_kind IN ('local_file','shared_store')),
                authority_epoch TEXT,
                state TEXT NOT NULL CHECK(state IN ('accepted','candidate_activated','conflict','failed','indeterminate')),
                finished_at_unix_ms INTEGER CHECK(finished_at_unix_ms BETWEEN 0 AND 9007199254740991),
                CHECK((actor_kind='system' AND actor_user_id IS NULL) OR (actor_kind='account' AND actor_user_id IS NOT NULL)),
                CHECK((state='accepted' AND finished_at_unix_ms IS NULL) OR (state!='accepted' AND finished_at_unix_ms IS NOT NULL))
            );")?;
            transaction.execute("INSERT INTO admin_config_operation_meta(singleton,authority_id,started_at_unix_ms) VALUES(1,?1,?2)",params![random_hex_id()?,now_ms()?])?;
            transaction.execute_batch("PRAGMA user_version=3")?;
        }
        let (next_user_id,next_audit_id,stored_records,pruned_through,started_at):(i64,i64,i64,i64,i64)=transaction.query_row("SELECT next_user_id,next_audit_id,stored_records,pruned_through,started_at_unix_ms FROM admin_audit_meta WHERE singleton=1",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))?;
        let max_user_id: i64 =
            transaction.query_row("SELECT COALESCE(MAX(id),0) FROM users", [], |row| {
                row.get(0)
            })?;
        let (count, max_audit_id): (i64, i64) = transaction.query_row(
            "SELECT COUNT(*),COALESCE(MAX(id),0) FROM admin_audit",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        ensure!(
            next_user_id > max_user_id
                && (1..=MAX_SAFE_ID + 1).contains(&next_user_id)
                && count == stored_records
                && (1..=AUDIT_CAPACITY).contains(&count)
                && next_audit_id == max_audit_id + 1
                && next_audit_id <= MAX_SAFE_ID + 1
                && pruned_through >= 0
                && pruned_through < next_audit_id
                && (0..=MAX_SAFE_ID).contains(&started_at),
            "administrator audit metadata inconsistent"
        );
        {
            let mut statement=transaction.prepare("SELECT id,time_unix_ms,action,actor_kind,actor_user_id,target_user_id,before_role,before_enabled,after_role,after_enabled,password_changed,affected_count,through_id FROM admin_audit ORDER BY id")?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let record = read_audit_record(row)?;
                ensure!(
                    record.id > pruned_through,
                    "administrator audit history crosses pruned range"
                );
            }
        }
        let (config_authority,config_started,config_next,config_count):(String,i64,i64,i64)=transaction.query_row("SELECT authority_id,started_at_unix_ms,next_id,stored_records FROM admin_config_operation_meta WHERE singleton=1",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?;
        let (actual_config_count, max_config_id): (i64, i64) = transaction.query_row(
            "SELECT COUNT(*),COALESCE(MAX(id),0) FROM admin_config_operations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        ensure!(
            valid_lower_hex(&config_authority, 32)
                && (0..=MAX_SAFE_ID).contains(&config_started)
                && (1..=MAX_SAFE_ID + 1).contains(&config_next)
                && config_count == actual_config_count
                && (0..=CONFIG_OPERATION_CAPACITY).contains(&config_count)
                && config_next == max_config_id + 1
                && config_count == max_config_id
                && config_count == config_next - 1,
            "local config operation metadata inconsistent"
        );
        {
            let mut statement=transaction.prepare("SELECT id,operation_id,authority_id,actor_kind,actor_user_id,accepted_at_unix_ms,expected_revision,candidate_sha256,store_kind,authority_epoch,state,finished_at_unix_ms FROM admin_config_operations ORDER BY id")?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let record = read_config_operation(row)?;
                ensure!(
                    record.authority_id == config_authority,
                    "local config operation authority differs from metadata"
                );
            }
        }
        transaction.commit()?;
        Ok(Self {
            path,
            password_workers: Arc::new(Semaphore::new(2)),
        })
    }

    pub async fn setup_required(&self) -> Result<bool> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let connection = connection(&path)?;
            let count: i64 =
                connection.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
            Ok(count == 0)
        })
        .await?
    }

    pub async fn bootstrap(&self, username: String, password: String) -> Result<Option<User>> {
        validate_username(&username)?;
        validate_password(&password)?;
        let permit = self
            .password_workers
            .clone()
            .try_acquire_owned()
            .context("password capacity exhausted")?;
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let (salt, hash) = hash_new_password(password.as_bytes())?;
            let mut connection = connection(&path)?;
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let count: i64 = transaction.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
            if count != 0 {
                return Ok(None);
            }
            let now = now()?;
            let id = allocate_user_id(&transaction)?;
            transaction.execute(
                "INSERT INTO users(id,username,salt,password_hash,role,enabled,created_at,updated_at) VALUES(?1,?2,?3,?4,'admin',1,?5,?5)",
                params![id, username, salt.as_slice(), hash.as_slice(), now],
            )?;
            let user = User {id,username,role: Role::Admin,enabled:true};
            append_audit(&transaction, audit_record(AuditAction::Bootstrap, AuditActorKind::System, None, Some(id), None, Some(AuditUserState{role:Role::Admin,enabled:true}), true, 1, None)?)?;
            transaction.commit()?;
            Ok(Some(user))
        }).await?
    }

    pub async fn login(&self, username: String, password: String) -> Result<Option<Login>> {
        // Identical Argon2 work for an unknown username. A full login attempt
        // owns one of two password permits before any database work starts.
        let permit = self
            .password_workers
            .clone()
            .try_acquire_owned()
            .context("password capacity exhausted")?;
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut connection = connection(&path)?;
            let candidate: Option<(User, Vec<u8>, Vec<u8>, i64)> = connection.query_row(
                "SELECT id,username,role,enabled,salt,password_hash,password_epoch FROM users WHERE username=?1 COLLATE NOCASE",
                params![username],
                |row| Ok((User {id:row.get(0)?,username:row.get(1)?,role:Role::parse(&row.get::<_,String>(2)?).map_err(|_|rusqlite::Error::InvalidQuery)?,enabled:row.get::<_,i64>(3)?==1}, row.get(4)?,row.get(5)?,row.get(6)?)),
            ).optional()?;
            let dummy_salt = [0x5a_u8;16];
            let dummy_hash = [0_u8;32];
            let (salt,expected) = candidate.as_ref().map(|(_,salt,hash,_)|(salt.as_slice(),hash.as_slice())).unwrap_or((&dummy_salt,&dummy_hash));
            let computed = hash_password(password.as_bytes(),salt)?;
            if !candidate.as_ref().is_some_and(|(user,_,_,_)|user.enabled)
                || !bool::from(computed.as_slice().ct_eq(expected)) {
                return Ok(None);
            }
            let (user,_,_,epoch)=candidate.expect("authenticated candidate");
            let token = random_token()?;
            let token_hash: [u8;32] = Sha256::digest(token.as_bytes()).into();
            let now = now()?;
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let live: Option<i64> = transaction.query_row(
                "SELECT password_epoch FROM users WHERE id=?1 AND enabled=1",
                params![user.id], |row|row.get(0)).optional()?;
            if live != Some(epoch) { return Ok(None); }
            transaction.execute("DELETE FROM sessions WHERE expires_at<=?1",params![now])?;
            let sessions:i64=transaction.query_row("SELECT COUNT(*) FROM sessions",[],|row|row.get(0))?;
            if sessions>=MAX_SESSIONS {
                transaction.execute("DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM sessions ORDER BY created_at,token_hash LIMIT 1)",[])?;
            }
            transaction.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?1,?2,?3,?4)",params![token_hash.as_slice(),user.id,now+SESSION_SECONDS,now])?;
            transaction.commit()?;
            Ok(Some(Login {token,expires_in_seconds:SESSION_SECONDS,user}))
        }).await?
    }

    pub async fn session(&self, token: String) -> Result<Option<User>> {
        if !valid_session_token(&token) {
            return Ok(None);
        }
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let connection=connection(&path)?;
            let user=connection.query_row(
                "SELECT users.id,users.username,users.role,users.enabled FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=?1 AND sessions.expires_at>?2 AND users.enabled=1",
                params![hash.as_slice(),now()?],
                |row|Ok(User{id:row.get(0)?,username:row.get(1)?,role:Role::parse(&row.get::<_,String>(2)?).map_err(|_|rusqlite::Error::InvalidQuery)?,enabled:row.get::<_,i64>(3)?==1}),
            ).optional()?;
            Ok(user)
        }).await?
    }

    pub async fn logout(&self, token: String) -> Result<()> {
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            connection(&path)?.execute(
                "DELETE FROM sessions WHERE token_hash=?1",
                params![hash.as_slice()],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn list(&self, authority: MutationAuthority) -> Result<Vec<User>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection = connection(&path)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            authorize_mutation(&transaction, &authority)?;
            let mut statement =
                transaction.prepare("SELECT id,username,role,enabled FROM users ORDER BY id")?;
            let users = statement
                .query_map([], |row| {
                    Ok(User {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        role: Role::parse(&row.get::<_, String>(2)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        enabled: row.get::<_, i64>(3)? == 1,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(statement);
            transaction.commit()?;
            Ok(users)
        })
        .await?
    }

    pub async fn create(
        &self,
        authority: MutationAuthority,
        username: String,
        password: String,
        role: Role,
    ) -> Result<Option<User>> {
        validate_username(&username)?;
        validate_password(&password)?;
        let permit = self
            .password_workers
            .clone()
            .try_acquire_owned()
            .context("password capacity exhausted")?;
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let _permit=permit;
            let (salt,hash)=hash_new_password(password.as_bytes())?;
            let mut connection=connection(&path)?;
            let transaction=connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let actor_id=authorize_mutation(&transaction, &authority)?;
            let count:i64=transaction.query_row("SELECT COUNT(*) FROM users",[],|row|row.get(0))?;
            if count==0 || count>=MAX_USERS {return Ok(None)}
            if transaction.query_row("SELECT 1 FROM users WHERE username=?1 COLLATE NOCASE",params![username],|row|row.get::<_,i64>(0)).optional()?.is_some(){return Ok(None)}
            let now=now()?;
            let id=allocate_user_id(&transaction)?;
            transaction.execute("INSERT INTO users(id,username,salt,password_hash,role,enabled,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,1,?6,?6)",params![id,username,salt.as_slice(),hash.as_slice(),role.as_str(),now])?;
            let user=User{id,username,role,enabled:true};
            append_audit(&transaction, audit_record(AuditAction::Create, actor_kind(&authority), actor_id, Some(id), None, Some(AuditUserState{role,enabled:true}), true, 1, None)?)?;
            transaction.commit()?;Ok(Some(user))
        }).await?
    }

    pub async fn update(
        &self,
        authority: MutationAuthority,
        id: i64,
        role: Option<Role>,
        enabled: Option<bool>,
        password: Option<String>,
    ) -> Result<(Change, Option<User>)> {
        if let Some(password) = &password {
            validate_password(password)?
        }
        let permit = if password.is_some() {
            Some(
                self.password_workers
                    .clone()
                    .try_acquire_owned()
                    .context("password capacity exhausted")?,
            )
        } else {
            None
        };
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let _permit=permit;
            let new_password=password.map(|p|hash_new_password(p.as_bytes())).transpose()?;
            let mut connection=connection(&path)?;
            let transaction=connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let actor_id=authorize_mutation(&transaction, &authority)?;
            let existing:Option<User>=transaction.query_row("SELECT id,username,role,enabled FROM users WHERE id=?1",params![id],|row|Ok(User{id:row.get(0)?,username:row.get(1)?,role:Role::parse(&row.get::<_,String>(2)?).map_err(|_|rusqlite::Error::InvalidQuery)?,enabled:row.get::<_,i64>(3)?==1})).optional()?;
            let Some(mut user)=existing else{return Ok((Change::NotFound,None))};
            let before=AuditUserState{role:user.role,enabled:user.enabled};
            let next_role=role.unwrap_or(user.role);let next_enabled=enabled.unwrap_or(user.enabled);
            if user.role==Role::Admin && user.enabled && (next_role!=Role::Admin || !next_enabled) {
                let admins:i64=transaction.query_row("SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1",[],|row|row.get(0))?;
                if admins<=1{return Ok((Change::Conflict,None))}
            }
            let password_changed=new_password.is_some();
            if let Some((salt,hash))=new_password {
                transaction.execute("UPDATE users SET salt=?1,password_hash=?2,password_epoch=password_epoch+1,role=?3,enabled=?4,updated_at=?5 WHERE id=?6",params![salt.as_slice(),hash.as_slice(),next_role.as_str(),i64::from(next_enabled),now()?,id])?;
                transaction.execute("DELETE FROM sessions WHERE user_id=?1",params![id])?;
            } else {
                transaction.execute("UPDATE users SET role=?1,enabled=?2,updated_at=?3 WHERE id=?4",params![next_role.as_str(),i64::from(next_enabled),now()?,id])?;
                if !next_enabled || next_role!=user.role {transaction.execute("DELETE FROM sessions WHERE user_id=?1",params![id])?;}
            }
            user.role=next_role;user.enabled=next_enabled;
            append_audit(&transaction, audit_record(AuditAction::Update, actor_kind(&authority), actor_id, Some(id), Some(before), Some(AuditUserState{role:next_role,enabled:next_enabled}), password_changed, 1, None)?)?;
            transaction.commit()?;Ok((Change::Applied,Some(user)))
        }).await?
    }

    pub async fn delete(&self, authority: MutationAuthority, id: i64) -> Result<Change> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection = connection(&path)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let actor_id = authorize_mutation(&transaction, &authority)?;
            let existing: Option<(String, bool)> = transaction
                .query_row(
                    "SELECT role,enabled FROM users WHERE id=?1",
                    params![id],
                    |row| Ok((row.get(0)?, row.get::<_, i64>(1)? == 1)),
                )
                .optional()?;
            let Some((role, enabled)) = existing else {
                return Ok(Change::NotFound);
            };
            if role == "admin" && enabled {
                let admins: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1",
                    [],
                    |row| row.get(0),
                )?;
                if admins <= 1 {
                    return Ok(Change::Conflict);
                }
            }
            transaction.execute("DELETE FROM users WHERE id=?1", params![id])?;
            append_audit(
                &transaction,
                audit_record(
                    AuditAction::Delete,
                    actor_kind(&authority),
                    actor_id,
                    Some(id),
                    Some(AuditUserState {
                        role: Role::parse(&role)?,
                        enabled,
                    }),
                    None,
                    false,
                    1,
                    None,
                )?,
            )?;
            transaction.commit()?;
            Ok(Change::Applied)
        })
        .await?
    }

    pub async fn audit_page(
        &self,
        authority: MutationAuthority,
        after: i64,
        limit: usize,
    ) -> Result<AuditPage> {
        ensure!(
            (0..=MAX_SAFE_ID).contains(&after) && (1..=100).contains(&limit),
            "invalid audit page bounds"
        );
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection=connection(&path)?;
            let transaction=connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            authorize_mutation(&transaction,&authority)?;
            let (started_at,pruned_through,next_audit_id,stored_records):(i64,i64,i64,i64)=transaction.query_row("SELECT started_at_unix_ms,pruned_through,next_audit_id,stored_records FROM admin_audit_meta WHERE singleton=1",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?;
            let oldest_id:Option<i64>=transaction.query_row("SELECT MIN(id) FROM admin_audit",[],|row|row.get(0))?;
            let mut statement=transaction.prepare("SELECT id,time_unix_ms,action,actor_kind,actor_user_id,target_user_id,before_role,before_enabled,after_role,after_enabled,password_changed,affected_count,through_id FROM admin_audit WHERE id>?1 ORDER BY id LIMIT ?2")?;
            let mut records=statement.query_map(params![after,i64::try_from(limit+1)?],read_audit_record)?.collect::<rusqlite::Result<Vec<_>>>()?;
            ensure!(records.iter().all(|record|record.id>pruned_through),"administrator audit history crosses pruned range");
            let has_more=records.len()>limit;
            records.truncate(limit);
            let next_after=records.last().map_or(after,|record|record.id);
            drop(statement);
            let page=AuditPage{scope:"instance",coverage:["bootstrap","create","update","delete","prune"],started_at_unix_ms:started_at,records,next_after,oldest_id,latest_id:next_audit_id-1,pruned_through,truncated:after<pruned_through,stored_records,capacity:AUDIT_CAPACITY,writes_available:stored_records<AUDIT_CAPACITY && next_audit_id<=MAX_SAFE_ID,server_time_unix_ms:now_ms()?,has_more};
            transaction.commit()?;
            Ok(page)
        }).await?
    }

    pub async fn prune_audit(
        &self,
        authority: MutationAuthority,
        through_id: i64,
        expected_latest_id: i64,
    ) -> Result<AuditPruneResult> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection=connection(&path)?;
            let transaction=connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let actor_id=authorize_mutation(&transaction,&authority)?;
            let (pruned_through,next_audit_id):(i64,i64)=transaction.query_row("SELECT pruned_through,next_audit_id FROM admin_audit_meta WHERE singleton=1",[],|row|Ok((row.get(0)?,row.get(1)?)))?;
            let latest_id=next_audit_id-1;
            if expected_latest_id!=latest_id || through_id<=pruned_through || through_id>latest_id {return Err(AuditConflict.into());}
            if next_audit_id>MAX_SAFE_ID {return Err(AuditCapacity.into());}
            let deleted=transaction.execute("DELETE FROM admin_audit WHERE id<=?1",params![through_id])?;
            if deleted==0 {return Err(AuditConflict.into());}
            transaction.execute("UPDATE admin_audit_meta SET pruned_through=?1,stored_records=stored_records-?2 WHERE singleton=1",params![through_id,i64::try_from(deleted)?])?;
            let record=append_audit(&transaction,audit_record(AuditAction::Prune,actor_kind(&authority),actor_id,None,None,None,false,u64::try_from(deleted)?,Some(through_id))?)?;
            transaction.commit()?;
            Ok(AuditPruneResult{pruned_records:u64::try_from(deleted)?,record})
        }).await?
    }

    /// Records local acceptance after live account authorization. This is not
    /// a commit in the separate configuration authority and is not fleet audit.
    pub async fn accept_config(
        &self,
        authority: MutationAuthority,
        request: ConfigAcceptRequest,
    ) -> Result<ConfigOperation> {
        ensure!(
            request.expected_revision <= MAX_SAFE_ID as u64,
            "configuration revision exceeds safe local audit range"
        );
        ensure!(
            valid_lower_hex(&request.candidate_sha256, 64),
            "candidate SHA-256 needs 64 lowercase hexadecimal characters"
        );
        ensure!(
            request
                .authority_epoch
                .as_ref()
                .is_none_or(|epoch| valid_lower_hex(epoch, 32)),
            "authority epoch needs 32 lowercase hexadecimal characters"
        );
        let operation_id = random_hex_id()?;
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection=connection(&path)?;
            let transaction=connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let actor_user_id=authorize_mutation(&transaction,&authority)?;
            let (authority_id,next_id,stored_records):(String,i64,i64)=transaction.query_row("SELECT authority_id,next_id,stored_records FROM admin_config_operation_meta WHERE singleton=1",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
            ensure!(valid_lower_hex(&authority_id,32) && (1..=MAX_SAFE_ID+1).contains(&next_id) && (0..=CONFIG_OPERATION_CAPACITY).contains(&stored_records) && stored_records==next_id-1,"local config operation metadata inconsistent");
            if stored_records>=CONFIG_OPERATION_CAPACITY || !(1..=MAX_SAFE_ID).contains(&next_id) {return Err(ConfigOperationCapacity.into());}
            let record=ConfigOperation{id:next_id,operation_id,authority_id,actor_kind:actor_kind(&authority),actor_user_id,accepted_at_unix_ms:now_ms()?,expected_revision:request.expected_revision,candidate_sha256:request.candidate_sha256,store_kind:request.store_kind,authority_epoch:request.authority_epoch,state:ConfigOperationState::Accepted,finished_at_unix_ms:None};
            ensure!(valid_config_operation(&record),"invalid local config operation");
            transaction.execute("INSERT INTO admin_config_operations(id,operation_id,authority_id,actor_kind,actor_user_id,accepted_at_unix_ms,expected_revision,candidate_sha256,store_kind,authority_epoch,state,finished_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'accepted',NULL)",params![record.id,record.operation_id,record.authority_id,record.actor_kind.as_str(),record.actor_user_id,record.accepted_at_unix_ms,i64::try_from(record.expected_revision)?,record.candidate_sha256,record.store_kind.as_str(),record.authority_epoch])?;
            transaction.execute("UPDATE admin_config_operation_meta SET next_id=?1,stored_records=stored_records+1 WHERE singleton=1",params![next_id+1])?;
            transaction.commit()?;
            Ok(record)
        }).await?
    }

    /// Trusted internal completion only. A terminal state never gets replaced;
    /// a lost completion acknowledgement must be resolved by reading the row.
    pub async fn finish_config(
        &self,
        operation_id: &str,
        state: ConfigOperationState,
    ) -> Result<ConfigOperation> {
        if !valid_lower_hex(operation_id, 32) || state == ConfigOperationState::Accepted {
            return Err(ConfigOperationConflict.into());
        }
        let operation_id = operation_id.to_owned();
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection=connection(&path)?;
            let transaction=connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed=transaction.execute("UPDATE admin_config_operations SET state=?1,finished_at_unix_ms=?2 WHERE operation_id=?3 AND state='accepted'",params![state.as_str(),now_ms()?,operation_id])?;
            if changed!=1 {return Err(ConfigOperationConflict.into());}
            let record=transaction.query_row("SELECT id,operation_id,authority_id,actor_kind,actor_user_id,accepted_at_unix_ms,expected_revision,candidate_sha256,store_kind,authority_epoch,state,finished_at_unix_ms FROM admin_config_operations WHERE operation_id=?1",params![operation_id],read_config_operation)?;
            transaction.commit()?;
            Ok(record)
        }).await?
    }

    pub async fn config_operations(
        &self,
        authority: MutationAuthority,
        after: i64,
        limit: usize,
    ) -> Result<ConfigOperationPage> {
        ensure!(
            (0..=MAX_SAFE_ID).contains(&after) && (1..=100).contains(&limit),
            "invalid local config operation page bounds"
        );
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection=connection(&path)?;
            let transaction=connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            authorize_mutation(&transaction,&authority)?;
            let (authority_id,started_at,next_id,stored_records):(String,i64,i64,i64)=transaction.query_row("SELECT authority_id,started_at_unix_ms,next_id,stored_records FROM admin_config_operation_meta WHERE singleton=1",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?;
            ensure!(valid_lower_hex(&authority_id,32) && (0..=MAX_SAFE_ID).contains(&started_at) && (1..=MAX_SAFE_ID+1).contains(&next_id) && (0..=CONFIG_OPERATION_CAPACITY).contains(&stored_records) && stored_records==next_id-1,"local config operation metadata inconsistent");
            let oldest_id:Option<i64>=transaction.query_row("SELECT MIN(id) FROM admin_config_operations",[],|row|row.get(0))?;
            ensure!(oldest_id==if stored_records==0 {None}else{Some(1)},"local config operation history does not start at id 1");
            let mut statement=transaction.prepare("SELECT id,operation_id,authority_id,actor_kind,actor_user_id,accepted_at_unix_ms,expected_revision,candidate_sha256,store_kind,authority_epoch,state,finished_at_unix_ms FROM admin_config_operations WHERE id>?1 ORDER BY id LIMIT ?2")?;
            let mut records=statement.query_map(params![after,i64::try_from(limit+1)?],read_config_operation)?.collect::<rusqlite::Result<Vec<_>>>()?;
            ensure!(records.iter().all(|record|record.authority_id==authority_id),"local config operation authority mismatch");
            if after<next_id-1 {ensure!(!records.is_empty(),"local config operation page has a gap");}
            for (index,record) in records.iter().enumerate() {
                ensure!(record.id==after+1+i64::try_from(index)?,"local config operation page has a gap");
            }
            let has_more=records.len()>limit;
            records.truncate(limit);
            let next_after=records.last().map_or(after,|record|record.id);
            drop(statement);
            let page=ConfigOperationPage{scope:"instance",coverage:["acceptance","local_outcome"],authority_id,started_at_unix_ms:started_at,records,next_after,oldest_id,latest_id:next_id-1,stored_records,capacity:CONFIG_OPERATION_CAPACITY,writes_available:stored_records<CONFIG_OPERATION_CAPACITY && next_id<=MAX_SAFE_ID,server_time_unix_ms:now_ms()?,has_more};
            transaction.commit()?;
            Ok(page)
        }).await?
    }
}

fn valid_session_token(token: &str) -> bool {
    token.len() == 43
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn valid_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn random_hex_id() -> Result<String> {
    Ok(random_bytes::<16>()?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn valid_config_operation(record: &ConfigOperation) -> bool {
    (1..=MAX_SAFE_ID).contains(&record.id)
        && valid_lower_hex(&record.operation_id, 32)
        && valid_lower_hex(&record.authority_id, 32)
        && match record.actor_kind {
            AuditActorKind::System => record.actor_user_id.is_none(),
            AuditActorKind::Account => record
                .actor_user_id
                .is_some_and(|id| (1..=MAX_SAFE_ID).contains(&id)),
        }
        && (0..=MAX_SAFE_ID).contains(&record.accepted_at_unix_ms)
        && record.expected_revision <= MAX_SAFE_ID as u64
        && valid_lower_hex(&record.candidate_sha256, 64)
        && record
            .authority_epoch
            .as_ref()
            .is_none_or(|epoch| valid_lower_hex(epoch, 32))
        && match record.state {
            ConfigOperationState::Accepted => record.finished_at_unix_ms.is_none(),
            _ => record
                .finished_at_unix_ms
                .is_some_and(|time| (0..=MAX_SAFE_ID).contains(&time)),
        }
}

fn read_config_operation(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConfigOperation> {
    let expected_revision: i64 = row.get(6)?;
    let record = ConfigOperation {
        id: row.get(0)?,
        operation_id: row.get(1)?,
        authority_id: row.get(2)?,
        actor_kind: AuditActorKind::parse(&row.get::<_, String>(3)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        actor_user_id: row.get(4)?,
        accepted_at_unix_ms: row.get(5)?,
        expected_revision: u64::try_from(expected_revision)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        candidate_sha256: row.get(7)?,
        store_kind: ConfigStoreKind::parse(&row.get::<_, String>(8)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        authority_epoch: row.get(9)?,
        state: ConfigOperationState::parse(&row.get::<_, String>(10)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        finished_at_unix_ms: row.get(11)?,
    };
    if !valid_config_operation(&record) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(record)
}

fn authorize_mutation(
    transaction: &Transaction<'_>,
    authority: &MutationAuthority,
) -> Result<Option<i64>> {
    let MutationAuthority::Session(token) = authority else {
        return Ok(None);
    };
    if !valid_session_token(token) {
        return Err(AuthorizationRevoked.into());
    }
    let token_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let valid: Option<i64> = transaction
        .query_row(
            "SELECT users.id FROM sessions JOIN users ON users.id=sessions.user_id \
             WHERE sessions.token_hash=?1 AND sessions.expires_at>?2 \
             AND users.enabled=1 AND users.role='admin'",
            params![token_hash.as_slice(), now()?],
            |row| row.get(0),
        )
        .optional()?;
    if valid.is_none() {
        return Err(AuthorizationRevoked.into());
    }
    Ok(valid)
}

fn actor_kind(authority: &MutationAuthority) -> AuditActorKind {
    match authority {
        MutationAuthority::System => AuditActorKind::System,
        MutationAuthority::Session(_) => AuditActorKind::Account,
    }
}

fn allocate_user_id(transaction: &Transaction<'_>) -> Result<i64> {
    let id: i64 = transaction.query_row(
        "SELECT next_user_id FROM admin_audit_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        (1..=MAX_SAFE_ID).contains(&id),
        "administrator user id exhausted"
    );
    transaction.execute(
        "UPDATE admin_audit_meta SET next_user_id=?1 WHERE singleton=1",
        params![id + 1],
    )?;
    Ok(id)
}

fn now_ms() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

#[allow(clippy::too_many_arguments)]
fn audit_record(
    action: AuditAction,
    actor_kind: AuditActorKind,
    actor_user_id: Option<i64>,
    target_user_id: Option<i64>,
    before: Option<AuditUserState>,
    after: Option<AuditUserState>,
    password_changed: bool,
    affected_count: u64,
    through_id: Option<i64>,
) -> Result<AuditRecord> {
    Ok(AuditRecord {
        id: 0,
        time_unix_ms: now_ms()?,
        action,
        actor_kind,
        actor_user_id,
        target_user_id,
        before,
        after,
        password_changed,
        affected_count,
        through_id,
    })
}

fn append_audit(transaction: &Transaction<'_>, mut record: AuditRecord) -> Result<AuditRecord> {
    let count: i64 = transaction.query_row(
        "SELECT stored_records FROM admin_audit_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if count >= AUDIT_CAPACITY {
        return Err(AuditCapacity.into());
    }
    let id: i64 = transaction.query_row(
        "SELECT next_audit_id FROM admin_audit_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if !(1..=MAX_SAFE_ID).contains(&id) {
        return Err(AuditCapacity.into());
    }
    record.id = id;
    ensure!(
        valid_audit_record(&record),
        "invalid administrator audit event"
    );
    let before_role = record.before.map(|s| s.role.as_str());
    let before_enabled = record.before.map(|s| i64::from(s.enabled));
    let after_role = record.after.map(|s| s.role.as_str());
    let after_enabled = record.after.map(|s| i64::from(s.enabled));
    transaction.execute("INSERT INTO admin_audit(id,time_unix_ms,action,actor_kind,actor_user_id,target_user_id,before_role,before_enabled,after_role,after_enabled,password_changed,affected_count,through_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)", params![id,record.time_unix_ms,record.action.as_str(),record.actor_kind.as_str(),record.actor_user_id,record.target_user_id,before_role,before_enabled,after_role,after_enabled,i64::from(record.password_changed),i64::try_from(record.affected_count)?,record.through_id])?;
    transaction.execute("UPDATE admin_audit_meta SET next_audit_id=?1,stored_records=stored_records+1 WHERE singleton=1", params![id+1])?;
    Ok(record)
}

fn read_audit_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRecord> {
    let before_role: Option<String> = row.get(6)?;
    let before_enabled: Option<i64> = row.get(7)?;
    let after_role: Option<String> = row.get(8)?;
    let after_enabled: Option<i64> = row.get(9)?;
    let state = |role: Option<String>,
                 enabled: Option<i64>|
     -> rusqlite::Result<Option<AuditUserState>> {
        match (role, enabled) {
            (None, None) => Ok(None),
            (Some(role), Some(enabled)) if (0..=1).contains(&enabled) => Ok(Some(AuditUserState {
                role: Role::parse(&role).map_err(|_| rusqlite::Error::InvalidQuery)?,
                enabled: enabled == 1,
            })),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    };
    let password_changed: i64 = row.get(10)?;
    if !(0..=1).contains(&password_changed) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let record = AuditRecord {
        id: row.get(0)?,
        time_unix_ms: row.get(1)?,
        action: AuditAction::parse(&row.get::<_, String>(2)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        actor_kind: AuditActorKind::parse(&row.get::<_, String>(3)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        actor_user_id: row.get(4)?,
        target_user_id: row.get(5)?,
        before: state(before_role, before_enabled)?,
        after: state(after_role, after_enabled)?,
        password_changed: password_changed == 1,
        affected_count: u64::try_from(row.get::<_, i64>(11)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        through_id: row.get(12)?,
    };
    if !valid_audit_record(&record) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(record)
}

fn valid_audit_record(record: &AuditRecord) -> bool {
    if !(1..=MAX_SAFE_ID).contains(&record.id)
        || !(0..=MAX_SAFE_ID).contains(&record.time_unix_ms)
        || record.affected_count > MAX_SAFE_ID as u64
        || record
            .actor_user_id
            .is_some_and(|id| !(1..=MAX_SAFE_ID).contains(&id))
        || record
            .target_user_id
            .is_some_and(|id| !(1..=MAX_SAFE_ID).contains(&id))
        || record
            .through_id
            .is_some_and(|id| !(1..=MAX_SAFE_ID).contains(&id))
        || !match record.actor_kind {
            AuditActorKind::System => record.actor_user_id.is_none(),
            AuditActorKind::Account => record.actor_user_id.is_some(),
        }
    {
        return false;
    }
    match record.action {
        AuditAction::Baseline => {
            record.actor_kind == AuditActorKind::System
                && record.target_user_id.is_none()
                && record.before.is_none()
                && record.after.is_none()
                && !record.password_changed
                && record.through_id.is_none()
        }
        AuditAction::Bootstrap => {
            record.actor_kind == AuditActorKind::System
                && record.target_user_id.is_some()
                && record.before.is_none()
                && record.after
                    == Some(AuditUserState {
                        role: Role::Admin,
                        enabled: true,
                    })
                && record.password_changed
                && record.affected_count == 1
                && record.through_id.is_none()
        }
        AuditAction::Create => {
            record.target_user_id.is_some()
                && record.before.is_none()
                && record.after.is_some_and(|after| after.enabled)
                && record.password_changed
                && record.affected_count == 1
                && record.through_id.is_none()
        }
        AuditAction::Update => {
            record.target_user_id.is_some()
                && record.before.is_some()
                && record.after.is_some()
                && record.affected_count == 1
                && record.through_id.is_none()
        }
        AuditAction::Delete => {
            record.target_user_id.is_some()
                && record.before.is_some()
                && record.after.is_none()
                && !record.password_changed
                && record.affected_count == 1
                && record.through_id.is_none()
        }
        AuditAction::Prune => {
            record.target_user_id.is_none()
                && record.before.is_none()
                && record.after.is_none()
                && !record.password_changed
                && record.affected_count > 0
                && record.through_id.is_some_and(|through| through < record.id)
        }
    }
}

fn connection(path: &Path) -> Result<Connection> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file() && metadata.permissions().mode() & 0o077 == 0,
        "administrator user database must remain a private regular file"
    );
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_secs(2))?;
    connection
        .execute_batch("PRAGMA foreign_keys=ON;PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;")?;
    Ok(connection)
}
fn now() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}
fn argon() -> Result<Argon2<'static>> {
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|error| anyhow::anyhow!("Argon2 settings: {error}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}
fn hash_password(password: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let mut hash = [0u8; 32];
    argon()?
        .hash_password_into(password, salt, &mut hash)
        .map_err(|_| anyhow::anyhow!("password derivation failed"))?;
    Ok(hash)
}
fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("system CSPRNG unavailable"))?;
    Ok(bytes)
}
fn hash_new_password(password: &[u8]) -> Result<([u8; 16], [u8; 32])> {
    let salt = random_bytes()?;
    let hash = hash_password(password, &salt)?;
    Ok((salt, hash))
}
fn random_token() -> Result<String> {
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes::<32>()?))
}
pub fn validate_username(username: &str) -> Result<()> {
    ensure!(
        (3..=64).contains(&username.len())
            && username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.'),
        "username needs 3..64 ASCII letters, digits, _, - or ."
    );
    Ok(())
}
pub fn validate_password(password: &str) -> Result<()> {
    ensure!(
        (12..=1024).contains(&password.len()) && !password.chars().any(char::is_control),
        "password needs 12..1024 bytes without controls"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_request() -> ConfigAcceptRequest {
        ConfigAcceptRequest {
            store_kind: ConfigStoreKind::LocalFile,
            authority_epoch: None,
            expected_revision: 7,
            candidate_sha256: "a".repeat(64),
        }
    }

    fn store() -> (tempfile::TempDir, Arc<Store>) {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("accounts.sqlite3");
        let store = Arc::new(Store::open(path).unwrap());
        (directory, store)
    }

    #[tokio::test]
    async fn v2_to_v3_keeps_users_sessions_and_account_audit() {
        let (directory, store) = store();
        let root = store
            .bootstrap("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        let login = store
            .login("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        let audit_latest = store
            .audit_page(MutationAuthority::System, 0, 100)
            .await
            .unwrap()
            .latest_id;
        let path = directory.path().join("accounts.sqlite3");
        drop(store);
        connection(&path).unwrap().execute_batch("DROP TABLE admin_config_operations; DROP TABLE admin_config_operation_meta; PRAGMA user_version=2;").unwrap();
        let migrated = Store::open(path.clone()).unwrap();
        assert_eq!(
            migrated
                .session(login.token.clone())
                .await
                .unwrap()
                .unwrap()
                .id,
            root.id
        );
        assert_eq!(
            migrated
                .audit_page(MutationAuthority::System, 0, 100)
                .await
                .unwrap()
                .latest_id,
            audit_latest
        );
        let empty = migrated
            .config_operations(MutationAuthority::System, 0, 100)
            .await
            .unwrap();
        assert_eq!(empty.latest_id, 0);
        assert_eq!(empty.stored_records, 0);
        assert!(valid_lower_hex(&empty.authority_id, 32));
        assert_eq!(
            connection(&path)
                .unwrap()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            3
        );
    }

    #[tokio::test]
    async fn config_acceptance_is_durable_and_fenced_by_live_session() {
        let (directory, store) = store();
        store
            .bootstrap("root".into(), "first secure password".into())
            .await
            .unwrap();
        let login = store
            .login("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        let accepted = store
            .accept_config(
                MutationAuthority::Session(login.token.clone()),
                config_request(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.actor_kind, AuditActorKind::Account);
        assert_eq!(accepted.actor_user_id, Some(login.user.id));
        assert_eq!(accepted.state, ConfigOperationState::Accepted);
        assert!(valid_lower_hex(&accepted.operation_id, 32));
        store.logout(login.token.clone()).await.unwrap();
        assert!(
            store
                .accept_config(
                    MutationAuthority::Session(login.token.clone()),
                    config_request()
                )
                .await
                .unwrap_err()
                .is::<AuthorizationRevoked>()
        );
        assert!(
            store
                .config_operations(MutationAuthority::Session(login.token), 0, 100)
                .await
                .unwrap_err()
                .is::<AuthorizationRevoked>()
        );
        let system = store
            .accept_config(
                MutationAuthority::System,
                ConfigAcceptRequest {
                    store_kind: ConfigStoreKind::SharedStore,
                    authority_epoch: Some("b".repeat(32)),
                    ..config_request()
                },
            )
            .await
            .unwrap();
        assert_eq!(system.id, accepted.id + 1);
        let path = directory.path().join("accounts.sqlite3");
        let reopened = Store::open(path).unwrap();
        let page = reopened
            .config_operations(MutationAuthority::System, 0, 100)
            .await
            .unwrap();
        assert_eq!(page.records.len(), 2);
        assert_eq!(page.authority_id, accepted.authority_id);
        assert_eq!(page.records[0].operation_id, accepted.operation_id);
        assert_eq!(page.records[1].authority_epoch, Some("b".repeat(32)));
        let json = serde_json::to_string(&page).unwrap();
        assert!(!json.contains("first secure password"));
        assert!(!json.contains("root"));
    }

    #[tokio::test]
    async fn config_finish_is_one_way_terminal_cas() {
        let (_directory, store) = store();
        let accepted = store
            .accept_config(MutationAuthority::System, config_request())
            .await
            .unwrap();
        assert!(
            store
                .finish_config(&accepted.operation_id, ConfigOperationState::Accepted)
                .await
                .unwrap_err()
                .is::<ConfigOperationConflict>()
        );
        let done = store
            .finish_config(
                &accepted.operation_id,
                ConfigOperationState::CandidateActivated,
            )
            .await
            .unwrap();
        assert_eq!(done.state, ConfigOperationState::CandidateActivated);
        assert!(done.finished_at_unix_ms.is_some());
        assert!(
            store
                .finish_config(&accepted.operation_id, ConfigOperationState::Failed)
                .await
                .unwrap_err()
                .is::<ConfigOperationConflict>()
        );
        assert!(
            store
                .finish_config(&"0".repeat(32), ConfigOperationState::Conflict)
                .await
                .unwrap_err()
                .is::<ConfigOperationConflict>()
        );
        let page = store
            .config_operations(MutationAuthority::System, 0, 1)
            .await
            .unwrap();
        assert_eq!(
            page.records[0].state,
            ConfigOperationState::CandidateActivated
        );
        assert_eq!(page.coverage, ["acceptance", "local_outcome"]);
    }

    #[tokio::test]
    async fn config_acceptance_capacity_blocks_without_evicting_unresolved_rows() {
        let (directory, store) = store();
        let path = directory.path().join("accounts.sqlite3");
        let connection = connection(&path).unwrap();
        connection.execute_batch("WITH RECURSIVE ids(id) AS (SELECT 1 UNION ALL SELECT id+1 FROM ids WHERE id<10000)
            INSERT INTO admin_config_operations(id,operation_id,authority_id,actor_kind,actor_user_id,accepted_at_unix_ms,expected_revision,candidate_sha256,store_kind,authority_epoch,state,finished_at_unix_ms)
            SELECT id,printf('%032x',id),(SELECT authority_id FROM admin_config_operation_meta WHERE singleton=1),'system',NULL,0,0,printf('%064x',1),'local_file',NULL,'accepted',NULL FROM ids;
            UPDATE admin_config_operation_meta SET next_id=10001,stored_records=10000 WHERE singleton=1;").unwrap();
        drop(connection);
        let full = store
            .config_operations(MutationAuthority::System, 0, 1)
            .await
            .unwrap();
        assert_eq!(full.stored_records, CONFIG_OPERATION_CAPACITY);
        assert!(!full.writes_available);
        assert_eq!(full.records[0].state, ConfigOperationState::Accepted);
        assert!(
            store
                .accept_config(MutationAuthority::System, config_request())
                .await
                .unwrap_err()
                .is::<ConfigOperationCapacity>()
        );
        // Finishing a row is allowed but does not silently free history capacity.
        store
            .finish_config(&full.records[0].operation_id, ConfigOperationState::Failed)
            .await
            .unwrap();
        assert!(
            store
                .accept_config(MutationAuthority::System, config_request())
                .await
                .unwrap_err()
                .is::<ConfigOperationCapacity>()
        );
        assert_eq!(
            Store::open(path)
                .unwrap()
                .config_operations(MutationAuthority::System, 0, 1)
                .await
                .unwrap()
                .stored_records,
            CONFIG_OPERATION_CAPACITY
        );
    }

    #[tokio::test]
    async fn malformed_config_operation_rows_fail_page_and_startup() {
        let (directory, store) = store();
        let accepted = store
            .accept_config(MutationAuthority::System, config_request())
            .await
            .unwrap();
        let path = directory.path().join("accounts.sqlite3");
        let connection = connection(&path).unwrap();
        assert!(connection.execute("UPDATE admin_config_operations SET actor_kind='account',actor_user_id=NULL WHERE id=1",[]).is_err());
        connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        for invalid in [
            "UPDATE admin_config_operations SET actor_kind='account',actor_user_id=NULL WHERE id=1",
            "UPDATE admin_config_operations SET state='candidate_activated',finished_at_unix_ms=NULL WHERE id=1",
            "UPDATE admin_config_operations SET accepted_at_unix_ms=-1 WHERE id=1",
            "UPDATE admin_config_operations SET candidate_sha256='garbage' WHERE id=1",
            "UPDATE admin_config_operations SET authority_id='00000000000000000000000000000000' WHERE id=1",
        ] {
            connection.execute(invalid, []).unwrap();
            assert!(
                store
                    .config_operations(MutationAuthority::System, 0, 100)
                    .await
                    .is_err(),
                "malformed operation returned: {invalid}"
            );
            assert!(
                Store::open(path.clone()).is_err(),
                "malformed operation passed reopen: {invalid}"
            );
            connection.execute("UPDATE admin_config_operations SET actor_kind='system',actor_user_id=NULL,state='accepted',finished_at_unix_ms=NULL,accepted_at_unix_ms=?1,candidate_sha256=?2,authority_id=?3 WHERE id=1",params![accepted.accepted_at_unix_ms,accepted.candidate_sha256,accepted.authority_id]).unwrap();
        }
        assert!(Store::open(path).is_ok());
    }

    #[tokio::test]
    async fn failed_v3_migration_rolls_back_and_keeps_v2_accounts() {
        let (directory, store) = store();
        let root = store
            .bootstrap("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        let login = store
            .login("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        let path = directory.path().join("accounts.sqlite3");
        drop(store);
        connection(&path).unwrap().execute_batch("DROP TABLE admin_config_operations; DROP TABLE admin_config_operation_meta; PRAGMA user_version=2; CREATE TABLE admin_config_operation_meta(dummy INTEGER);").unwrap();
        assert!(Store::open(path.clone()).is_err());
        let connection = connection(&path).unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert!(
            connection
                .query_row("SELECT 1 FROM admin_config_operations", [], |row| row
                    .get::<_, i64>(0))
                .is_err()
        );
        connection
            .execute_batch("DROP TABLE admin_config_operation_meta")
            .unwrap();
        drop(connection);
        let migrated = Store::open(path).unwrap();
        assert_eq!(
            migrated.session(login.token).await.unwrap().unwrap().id,
            root.id
        );
        assert_eq!(
            migrated
                .config_operations(MutationAuthority::System, 0, 1)
                .await
                .unwrap()
                .stored_records,
            0
        );
    }

    #[tokio::test]
    async fn missing_middle_operation_fails_open_page_and_next_acceptance() {
        let (directory, store) = store();
        for _ in 0..3 {
            store
                .accept_config(MutationAuthority::System, config_request())
                .await
                .unwrap();
        }
        let path = directory.path().join("accounts.sqlite3");
        connection(&path).unwrap().execute_batch("DELETE FROM admin_config_operations WHERE id=2; UPDATE admin_config_operation_meta SET stored_records=2 WHERE singleton=1;").unwrap();
        assert!(
            Store::open(path).is_err(),
            "startup must reject a missing middle row even when count metadata was adjusted"
        );
        assert!(
            store
                .config_operations(MutationAuthority::System, 0, 100)
                .await
                .is_err(),
            "paged history must not imply a complete range"
        );
        assert!(
            store
                .accept_config(MutationAuthority::System, config_request())
                .await
                .is_err(),
            "a broken sequence cannot accept a new row"
        );
    }

    /// Two local SQLite FULL transactions per pair: acceptance and terminal
    /// observation. Excludes Argon2, HTTP, configuration CAS and data plane.
    #[tokio::test]
    #[ignore = "explicit release-mode local operation journal diagnostic"]
    async fn config_operation_acceptance_microbenchmark() {
        let (_directory, store) = store();
        store
            .bootstrap("root".into(), "first secure password".into())
            .await
            .unwrap();
        let login = store
            .login("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        const PAIRS: usize = 100;
        for account in [false, true] {
            let started = std::time::Instant::now();
            for _ in 0..PAIRS {
                let authority = if account {
                    MutationAuthority::Session(login.token.clone())
                } else {
                    MutationAuthority::System
                };
                let accepted = store
                    .accept_config(authority, config_request())
                    .await
                    .unwrap();
                let finished = store
                    .finish_config(
                        &accepted.operation_id,
                        ConfigOperationState::CandidateActivated,
                    )
                    .await
                    .unwrap();
                assert_eq!(finished.state, ConfigOperationState::CandidateActivated);
            }
            let elapsed = started.elapsed();
            eprintln!(
                "local config acceptance+finish {}: {PAIRS} pairs ({} SQLite FULL writes) in {elapsed:?} ({:.0} pairs/s); excludes Argon2, HTTP, configuration CAS, preparation and data plane",
                if account {
                    "session authority"
                } else {
                    "system authority"
                },
                PAIRS * 2,
                PAIRS as f64 / elapsed.as_secs_f64()
            );
        }
    }

    #[tokio::test]
    async fn audit_migration_preserves_login_and_user_ids_never_recycle() {
        let (directory, store) = store();
        let root = store
            .bootstrap("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        let login = store
            .login("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        let path = directory.path().join("accounts.sqlite3");
        connection(&path)
            .unwrap()
            .execute_batch(
                "DROP TABLE admin_config_operations; DROP TABLE admin_config_operation_meta; DROP TABLE admin_audit; DROP TABLE admin_audit_meta; PRAGMA user_version=1;",
            )
            .unwrap();
        drop(store);
        let reopened = Store::open(path.clone()).unwrap();
        assert_eq!(
            reopened.session(login.token).await.unwrap().unwrap().id,
            root.id
        );
        let page = reopened
            .audit_page(MutationAuthority::System, 0, 100)
            .await
            .unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].action, AuditAction::Baseline);
        assert_eq!(page.records[0].affected_count, 1);
        assert_eq!(
            page.coverage,
            ["bootstrap", "create", "update", "delete", "prune"]
        );
        let second = reopened
            .create(
                MutationAuthority::System,
                "second".into(),
                "second secure password".into(),
                Role::Admin,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            reopened
                .delete(MutationAuthority::System, root.id)
                .await
                .unwrap(),
            Change::Applied
        );
        let third = reopened
            .create(
                MutationAuthority::System,
                "third".into(),
                "third secure password".into(),
                Role::Viewer,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(third.id > second.id && second.id > root.id);
        assert_eq!(
            connection(&path)
                .unwrap()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            3
        );
    }

    #[tokio::test]
    async fn failed_v1_migration_leaves_version_and_accounts_unchanged() {
        let (directory, store) = store();
        let root = store
            .bootstrap("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        let login = store
            .login("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        let path = directory.path().join("accounts.sqlite3");
        drop(store);
        connection(&path).unwrap().execute_batch("DROP TABLE admin_config_operations; DROP TABLE admin_config_operation_meta; DROP TABLE admin_audit; DROP TABLE admin_audit_meta; PRAGMA user_version=1; CREATE TABLE admin_audit_meta(dummy INTEGER);").unwrap();
        assert!(Store::open(path.clone()).is_err());
        let connection = connection(&path).unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert!(
            connection
                .query_row("SELECT 1 FROM admin_audit", [], |row| row.get::<_, i64>(0))
                .is_err()
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM users", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        connection
            .execute_batch("DROP TABLE admin_audit_meta")
            .unwrap();
        drop(connection);
        let migrated = Store::open(path).unwrap();
        assert_eq!(
            migrated.session(login.token).await.unwrap().unwrap().id,
            root.id
        );
        assert_eq!(
            migrated
                .audit_page(MutationAuthority::System, 0, 100)
                .await
                .unwrap()
                .records
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn invalid_audit_provenance_fails_reads_and_reopen() {
        let (directory, store) = store();
        store
            .bootstrap("root".into(), "first secure password".into())
            .await
            .unwrap();
        let path = directory.path().join("accounts.sqlite3");
        let connection = connection(&path).unwrap();
        assert!(
            connection
                .execute(
                    "UPDATE admin_audit SET actor_kind='account',actor_user_id=NULL WHERE id=1",
                    []
                )
                .is_err(),
            "new v2 SQL constraints reject malformed provenance"
        );
        connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        for invalid in [
            "UPDATE admin_audit SET actor_kind='account',actor_user_id=NULL WHERE id=1",
            "UPDATE admin_audit SET action='create',target_user_id=NULL WHERE id=1",
            "UPDATE admin_audit SET time_unix_ms=-1 WHERE id=1",
            "UPDATE admin_audit SET action='prune',through_id=NULL,affected_count=1 WHERE id=1",
            "UPDATE admin_audit SET before_role='admin',before_enabled=NULL WHERE id=1",
            "UPDATE admin_audit SET target_user_id=-5 WHERE id=1",
        ] {
            connection.execute(invalid, []).unwrap();
            assert!(
                store
                    .audit_page(MutationAuthority::System, 0, 10)
                    .await
                    .is_err(),
                "invalid row was returned: {invalid}"
            );
            assert!(
                Store::open(path.clone()).is_err(),
                "invalid row passed startup scan: {invalid}"
            );
            connection.execute_batch("UPDATE admin_audit SET actor_kind='system',actor_user_id=NULL,action='baseline',target_user_id=NULL,time_unix_ms=0,affected_count=0,before_role=NULL,before_enabled=NULL,after_role=NULL,after_enabled=NULL,password_changed=0,through_id=NULL WHERE id=1").unwrap();
        }
        assert!(Store::open(path).is_ok());
    }

    #[tokio::test]
    async fn audit_append_failure_rolls_back_password_sessions_and_sequence() {
        let (directory, store) = store();
        store
            .bootstrap("root".into(), "first secure password".into())
            .await
            .unwrap();
        let target = store
            .create(
                MutationAuthority::System,
                "target".into(),
                "target secure password".into(),
                Role::Admin,
            )
            .await
            .unwrap()
            .unwrap();
        let login = store
            .login("target".into(), "target secure password".into())
            .await
            .unwrap()
            .unwrap();
        let path = directory.path().join("accounts.sqlite3");
        let before = store
            .audit_page(MutationAuthority::System, 0, 100)
            .await
            .unwrap();
        connection(&path).unwrap().execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON admin_audit BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END;").unwrap();
        assert!(
            store
                .update(
                    MutationAuthority::System,
                    target.id,
                    None,
                    Some(false),
                    Some("changed secure password".into())
                )
                .await
                .is_err()
        );
        assert!(store.session(login.token.clone()).await.unwrap().is_some());
        assert!(
            store
                .login("target".into(), "target secure password".into())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .create(
                    MutationAuthority::System,
                    "never".into(),
                    "another secure password".into(),
                    Role::Viewer
                )
                .await
                .is_err()
        );
        assert_eq!(
            store.list(MutationAuthority::System).await.unwrap().len(),
            2
        );
        connection(&path)
            .unwrap()
            .execute_batch("DROP TRIGGER fail_audit")
            .unwrap();
        let next = store
            .create(
                MutationAuthority::System,
                "next".into(),
                "another secure password".into(),
                Role::Viewer,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            next.id,
            target.id + 1,
            "failed create cannot consume a durable user id"
        );
        let after = store
            .audit_page(MutationAuthority::System, 0, 100)
            .await
            .unwrap();
        assert_eq!(after.latest_id, before.latest_id + 1);
        assert!(
            !serde_json::to_string(&after)
                .unwrap()
                .contains("secure password")
        );
        assert!(
            !serde_json::to_string(&after)
                .unwrap()
                .contains(&login.token)
        );
        assert!(
            !serde_json::to_string(&after)
                .unwrap()
                .contains("\"username\"")
        );
    }

    #[tokio::test]
    async fn audit_paging_requires_live_admin_and_prune_is_cas_protected() {
        let (_directory, store) = store();
        store
            .bootstrap("root".into(), "first secure password".into())
            .await
            .unwrap();
        let login = store
            .login("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        store
            .create(
                MutationAuthority::Session(login.token.clone()),
                "viewer".into(),
                "viewer secure password".into(),
                Role::Viewer,
            )
            .await
            .unwrap();
        let first = store
            .audit_page(MutationAuthority::Session(login.token.clone()), 0, 2)
            .await
            .unwrap();
        assert_eq!(first.records.len(), 2);
        assert!(first.has_more);
        let second = store
            .audit_page(
                MutationAuthority::Session(login.token.clone()),
                first.next_after,
                2,
            )
            .await
            .unwrap();
        assert_eq!(second.records.len(), 1);
        assert!(!second.has_more);
        assert_eq!(second.records[0].actor_kind, AuditActorKind::Account);
        assert_eq!(second.records[0].actor_user_id, Some(login.user.id));
        assert!(
            store
                .prune_audit(
                    MutationAuthority::Session(login.token.clone()),
                    first.next_after,
                    first.latest_id - 1
                )
                .await
                .unwrap_err()
                .is::<AuditConflict>()
        );
        let pruned = store
            .prune_audit(
                MutationAuthority::Session(login.token.clone()),
                first.next_after,
                first.latest_id,
            )
            .await
            .unwrap();
        assert_eq!(pruned.pruned_records, 2);
        assert_eq!(pruned.record.action, AuditAction::Prune);
        assert_eq!(pruned.record.through_id, Some(first.next_after));
        let page = store
            .audit_page(MutationAuthority::Session(login.token.clone()), 0, 100)
            .await
            .unwrap();
        assert!(page.truncated);
        assert_eq!(page.pruned_through, first.next_after);
        assert_eq!(page.records.len(), 2);
        store.logout(login.token.clone()).await.unwrap();
        assert!(
            store
                .audit_page(MutationAuthority::Session(login.token.clone()), 0, 1)
                .await
                .unwrap_err()
                .is::<AuthorizationRevoked>()
        );
        assert!(
            store
                .prune_audit(
                    MutationAuthority::Session(login.token),
                    page.latest_id,
                    page.latest_id
                )
                .await
                .unwrap_err()
                .is::<AuthorizationRevoked>()
        );
    }

    #[tokio::test]
    async fn audit_capacity_blocks_writes_and_explicit_prune_recovers() {
        let (directory, store) = store();
        store
            .bootstrap("root".into(), "first secure password".into())
            .await
            .unwrap();
        let path = directory.path().join("accounts.sqlite3");
        let connection = connection(&path).unwrap();
        // Insert inert test records in one statement; ordinary account writes never prune.
        connection.execute_batch("WITH RECURSIVE ids(id) AS (SELECT 3 UNION ALL SELECT id+1 FROM ids WHERE id<100000) INSERT INTO admin_audit(id,time_unix_ms,action,actor_kind,password_changed,affected_count) SELECT id,0,'baseline','system',0,0 FROM ids; UPDATE admin_audit_meta SET next_audit_id=100001,stored_records=100000 WHERE singleton=1;").unwrap();
        drop(connection);
        let before = store
            .audit_page(MutationAuthority::System, 0, 1)
            .await
            .unwrap();
        assert_eq!(before.stored_records, AUDIT_CAPACITY);
        assert!(!before.writes_available);
        assert!(
            store
                .create(
                    MutationAuthority::System,
                    "blocked".into(),
                    "blocked secure password".into(),
                    Role::Viewer
                )
                .await
                .unwrap_err()
                .is::<AuditCapacity>()
        );
        assert_eq!(
            store.list(MutationAuthority::System).await.unwrap().len(),
            1
        );
        let pruned = store
            .prune_audit(MutationAuthority::System, 1000, before.latest_id)
            .await
            .unwrap();
        assert_eq!(pruned.pruned_records, 1000);
        assert!(
            store
                .audit_page(MutationAuthority::System, 0, 1)
                .await
                .unwrap()
                .writes_available
        );
        let user = store
            .create(
                MutationAuthority::System,
                "accepted".into(),
                "accepted secure password".into(),
                Role::Viewer,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user.id, 2, "capacity rejection rolls back next user id");
    }

    #[tokio::test]
    async fn bootstrap_is_atomic_and_sessions_survive_restart_until_logout() {
        let (directory, store) = store();
        let (first, second) = tokio::join!(
            store.bootstrap("first".into(), "correct horse battery".into()),
            store.bootstrap("second".into(), "correct horse battery".into()),
        );
        let created = [first.unwrap(), second.unwrap()]
            .into_iter()
            .filter(Option::is_some)
            .count();
        assert_eq!(created, 1);
        assert!(!store.setup_required().await.unwrap());
        let username = store.list(MutationAuthority::System).await.unwrap()[0]
            .username
            .clone();
        assert!(
            store
                .login(username.clone(), "wrong password".into())
                .await
                .unwrap()
                .is_none()
        );
        let session = store
            .login(username, "correct horse battery".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session.user.role, Role::Admin);
        assert_eq!(session.token.len(), 43);
        assert!(
            store
                .session(session.token.clone())
                .await
                .unwrap()
                .is_some()
        );
        let reopened = Store::open(directory.path().join("accounts.sqlite3")).unwrap();
        assert!(
            reopened
                .session(session.token.clone())
                .await
                .unwrap()
                .is_some()
        );
        reopened.logout(session.token.clone()).await.unwrap();
        assert!(store.session(session.token).await.unwrap().is_none());
        let bytes = std::fs::read(directory.path().join("accounts.sqlite3")).unwrap();
        assert!(
            !bytes
                .windows(b"correct horse battery".len())
                .any(|window| window == b"correct horse battery")
        );
        assert_eq!(
            std::fs::metadata(directory.path().join("accounts.sqlite3"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }

    #[tokio::test]
    async fn last_admin_is_preserved_and_role_password_changes_revoke_sessions() {
        let (_directory, store) = store();
        let root = store
            .bootstrap("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            store
                .delete(MutationAuthority::System, root.id)
                .await
                .unwrap(),
            Change::Conflict
        );
        assert_eq!(
            store
                .update(
                    MutationAuthority::System,
                    root.id,
                    Some(Role::Viewer),
                    None,
                    None
                )
                .await
                .unwrap()
                .0,
            Change::Conflict
        );
        assert_eq!(
            store
                .update(MutationAuthority::System, root.id, None, Some(false), None)
                .await
                .unwrap()
                .0,
            Change::Conflict
        );
        let second = store
            .create(
                MutationAuthority::System,
                "second".into(),
                "second secure password".into(),
                Role::Admin,
            )
            .await
            .unwrap()
            .unwrap();
        let session = store
            .login("second".into(), "second secure password".into())
            .await
            .unwrap()
            .unwrap();
        assert!(
            store
                .session(session.token.clone())
                .await
                .unwrap()
                .is_some()
        );
        let updated = store
            .update(
                MutationAuthority::System,
                second.id,
                Some(Role::Viewer),
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(updated.0, Change::Applied);
        assert!(store.session(session.token).await.unwrap().is_none());
        let session = store
            .login("second".into(), "second secure password".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session.user.role, Role::Viewer);
        store
            .update(
                MutationAuthority::System,
                second.id,
                None,
                None,
                Some("new secure password".into()),
            )
            .await
            .unwrap();
        assert!(store.session(session.token).await.unwrap().is_none());
        assert!(
            store
                .login("second".into(), "second secure password".into())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .login("second".into(), "new secure password".into())
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            store
                .delete(MutationAuthority::System, root.id)
                .await
                .unwrap(),
            Change::Conflict
        );
        assert_eq!(
            store
                .delete(MutationAuthority::System, second.id)
                .await
                .unwrap(),
            Change::Applied
        );
    }

    #[tokio::test]
    async fn mutation_authority_is_rechecked_inside_each_write_transaction() {
        let (directory, store) = store();
        let root = store
            .bootstrap("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        let root_login = store
            .login("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        let viewer = store
            .create(
                MutationAuthority::Session(root_login.token.clone()),
                "viewer".into(),
                "viewer secure password".into(),
                Role::Viewer,
            )
            .await
            .unwrap()
            .unwrap();
        store.logout(root_login.token.clone()).await.unwrap();
        let denied = store
            .update(
                MutationAuthority::Session(root_login.token.clone()),
                viewer.id,
                Some(Role::Admin),
                None,
                None,
            )
            .await
            .unwrap_err();
        assert!(denied.downcast_ref::<AuthorizationRevoked>().is_some());
        assert_eq!(
            store.list(MutationAuthority::System).await.unwrap()[1].role,
            Role::Viewer
        );
        assert!(
            store
                .delete(MutationAuthority::Session(root_login.token), viewer.id)
                .await
                .unwrap_err()
                .downcast_ref::<AuthorizationRevoked>()
                .is_some()
        );

        let viewer_login = store
            .login("viewer".into(), "viewer secure password".into())
            .await
            .unwrap()
            .unwrap();
        assert!(
            store
                .delete(MutationAuthority::Session(viewer_login.token), root.id)
                .await
                .unwrap_err()
                .downcast_ref::<AuthorizationRevoked>()
                .is_some(),
            "a live viewer session cannot gain write authority"
        );

        let fresh = store
            .login("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        let hash: [u8; 32] = Sha256::digest(fresh.token.as_bytes()).into();
        connection(&directory.path().join("accounts.sqlite3"))
            .unwrap()
            .execute(
                "UPDATE sessions SET expires_at=0 WHERE token_hash=?1",
                params![hash.as_slice()],
            )
            .unwrap();
        assert!(
            store
                .delete(MutationAuthority::Session(fresh.token), viewer.id)
                .await
                .unwrap_err()
                .downcast_ref::<AuthorizationRevoked>()
                .is_some(),
            "expired sessions cannot mutate accounts"
        );
        assert_eq!(
            store.list(MutationAuthority::System).await.unwrap().len(),
            2
        );
    }

    #[tokio::test]
    async fn account_list_rechecks_admin_session_in_its_read_transaction() {
        let (directory, store) = store();
        let root = store
            .bootstrap("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        let viewer = store
            .create(
                MutationAuthority::System,
                "viewer".into(),
                "viewer secure password".into(),
                Role::Viewer,
            )
            .await
            .unwrap()
            .unwrap();
        let root_session = store
            .login("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        let authorized = store
            .list(MutationAuthority::Session(root_session.token.clone()))
            .await
            .unwrap();
        assert_eq!(
            authorized.iter().map(|user| user.id).collect::<Vec<_>>(),
            vec![root.id, viewer.id]
        );
        assert_eq!(
            store
                .list(MutationAuthority::System)
                .await
                .unwrap()
                .iter()
                .map(|user| user.id)
                .collect::<Vec<_>>(),
            authorized.iter().map(|user| user.id).collect::<Vec<_>>()
        );

        let viewer_session = store
            .login("viewer".into(), "viewer secure password".into())
            .await
            .unwrap()
            .unwrap();
        assert!(
            store
                .list(MutationAuthority::Session(viewer_session.token))
                .await
                .unwrap_err()
                .is::<AuthorizationRevoked>()
        );

        store.logout(root_session.token.clone()).await.unwrap();
        assert!(
            store
                .list(MutationAuthority::Session(root_session.token))
                .await
                .unwrap_err()
                .is::<AuthorizationRevoked>()
        );

        let expiring = store
            .login("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        let token_hash: [u8; 32] = Sha256::digest(expiring.token.as_bytes()).into();
        connection(&directory.path().join("accounts.sqlite3"))
            .unwrap()
            .execute(
                "UPDATE sessions SET expires_at=0 WHERE token_hash=?1",
                params![token_hash.as_slice()],
            )
            .unwrap();
        assert!(
            store
                .list(MutationAuthority::Session(expiring.token))
                .await
                .unwrap_err()
                .is::<AuthorizationRevoked>()
        );
    }

    #[tokio::test]
    async fn demotion_and_password_change_revoke_queued_mutation_authority() {
        let (_directory, store) = store();
        let root = store
            .bootstrap("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        store
            .create(
                MutationAuthority::System,
                "second".into(),
                "second secure password".into(),
                Role::Admin,
            )
            .await
            .unwrap();
        let root_login = store
            .login("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        store
            .update(
                MutationAuthority::System,
                root.id,
                Some(Role::Viewer),
                None,
                None,
            )
            .await
            .unwrap();
        assert!(
            store
                .create(
                    MutationAuthority::Session(root_login.token),
                    "blocked".into(),
                    "another secure password".into(),
                    Role::Admin,
                )
                .await
                .unwrap_err()
                .downcast_ref::<AuthorizationRevoked>()
                .is_some()
        );
        let second_login = store
            .login("second".into(), "second secure password".into())
            .await
            .unwrap()
            .unwrap();
        let second = store
            .list(MutationAuthority::System)
            .await
            .unwrap()
            .into_iter()
            .find(|user| user.username == "second")
            .unwrap();
        store
            .update(
                MutationAuthority::System,
                second.id,
                None,
                None,
                Some("new second password".into()),
            )
            .await
            .unwrap();
        assert!(
            store
                .delete(MutationAuthority::Session(second_login.token), root.id)
                .await
                .unwrap_err()
                .downcast_ref::<AuthorizationRevoked>()
                .is_some()
        );
        assert_eq!(
            store.list(MutationAuthority::System).await.unwrap().len(),
            2
        );
    }

    /// Diagnostic only: SQLite FULL account writes with and without the
    /// in-transaction session authority query. Password hashing, HTTP, and
    /// data-plane throughput are outside this timed region.
    /// Run with: cargo test --release --lib admin_mutation_authority_microbenchmark -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "explicit release-mode account write diagnostic"]
    async fn admin_mutation_authority_microbenchmark() {
        let (_directory, store) = store();
        store
            .bootstrap("root".into(), "first secure password".into())
            .await
            .unwrap();
        let login = store
            .login("root".into(), "first secure password".into())
            .await
            .unwrap()
            .unwrap();
        let target = store
            .create(
                MutationAuthority::System,
                "viewer".into(),
                "viewer secure password".into(),
                Role::Viewer,
            )
            .await
            .unwrap()
            .unwrap();
        const ITERATIONS: usize = 100;
        for account in [false, true] {
            let started = std::time::Instant::now();
            for index in 0..ITERATIONS {
                let authority = if account {
                    MutationAuthority::Session(login.token.clone())
                } else {
                    MutationAuthority::System
                };
                let (change, _) = store
                    .update(authority, target.id, None, Some(index % 2 == 0), None)
                    .await
                    .unwrap();
                assert_eq!(change, Change::Applied);
            }
            let elapsed = started.elapsed();
            eprintln!(
                "admin SQLite FULL no-password updates {}: {ITERATIONS} writes in {elapsed:?} ({:.0} ops/s); excludes Argon2, HTTP, and data plane",
                if account {
                    "session authority"
                } else {
                    "system authority"
                },
                ITERATIONS as f64 / elapsed.as_secs_f64()
            );
        }
    }

    #[test]
    fn rejects_unsafe_database_path_and_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("fifo");
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(Store::open(fifo).is_err());
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(directory.path().join("missing"), &link).unwrap();
        assert!(Store::open(link).is_err());
        let public = directory.path().join("public.sqlite3");
        std::fs::write(&public, []).unwrap();
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Store::open(public).is_err());
    }

    #[tokio::test]
    async fn database_replacement_does_not_follow_symlink_or_recreate_missing_file() {
        let (directory, store) = store();
        let path = directory.path().join("accounts.sqlite3");
        let moved = directory.path().join("moved.sqlite3");
        std::fs::rename(&path, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &path).unwrap();
        assert!(
            store.list(MutationAuthority::System).await.is_err(),
            "a swapped symlink must not be followed"
        );
        std::fs::remove_file(&path).unwrap();
        assert!(
            store.list(MutationAuthority::System).await.is_err(),
            "a removed database must fail closed"
        );
        assert!(
            !path.exists(),
            "an account request must not recreate the database"
        );
    }

    #[test]
    fn rejects_nonprivate_sqlite_sidecar_before_opening_database() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("accounts.sqlite3");
        std::fs::write(&path, []).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut wal = path.as_os_str().to_os_string();
        wal.push("-wal");
        let wal = PathBuf::from(wal);
        std::fs::write(&wal, []).unwrap();
        std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Store::open(path).is_err());
    }

    #[test]
    fn explicit_database_path_requires_a_nonwritable_parent() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
        let path = directory.path().join("accounts.sqlite3");
        assert!(Store::open(path.clone()).is_err());
        assert!(!path.exists());
    }
}
