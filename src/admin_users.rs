//! Instance-local, durable administrator accounts and revocable bearer sessions.
//! Password derivation and SQLite I/O run on bounded blocking workers, never
//! on the async administration reactor.

use anyhow::{Context, Result, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
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
        let connection = connection(&path)?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        ensure!(
            version <= 1,
            "administrator user database schema is newer than this binary"
        );
        connection.execute_batch(
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
            PRAGMA user_version=1;",
        )?;
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
            transaction.execute(
                "INSERT INTO users(username,salt,password_hash,role,enabled,created_at,updated_at) VALUES(?1,?2,?3,'admin',1,?4,?4)",
                params![username, salt.as_slice(), hash.as_slice(), now],
            )?;
            let user = User {id: transaction.last_insert_rowid(),username,role: Role::Admin,enabled:true};
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
        if token.len() != 43
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
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

    pub async fn list(&self) -> Result<Vec<User>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let connection = connection(&path)?;
            let mut statement =
                connection.prepare("SELECT id,username,role,enabled FROM users ORDER BY id")?;
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
            Ok(users)
        })
        .await?
    }

    pub async fn create(
        &self,
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
            let count:i64=transaction.query_row("SELECT COUNT(*) FROM users",[],|row|row.get(0))?;
            if count==0 || count>=MAX_USERS {return Ok(None)}
            if transaction.query_row("SELECT 1 FROM users WHERE username=?1 COLLATE NOCASE",params![username],|row|row.get::<_,i64>(0)).optional()?.is_some(){return Ok(None)}
            let now=now()?;
            transaction.execute("INSERT INTO users(username,salt,password_hash,role,enabled,created_at,updated_at) VALUES(?1,?2,?3,?4,1,?5,?5)",params![username,salt.as_slice(),hash.as_slice(),role.as_str(),now])?;
            let user=User{id:transaction.last_insert_rowid(),username,role,enabled:true};
            transaction.commit()?;Ok(Some(user))
        }).await?
    }

    pub async fn update(
        &self,
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
            let existing:Option<User>=transaction.query_row("SELECT id,username,role,enabled FROM users WHERE id=?1",params![id],|row|Ok(User{id:row.get(0)?,username:row.get(1)?,role:Role::parse(&row.get::<_,String>(2)?).map_err(|_|rusqlite::Error::InvalidQuery)?,enabled:row.get::<_,i64>(3)?==1})).optional()?;
            let Some(mut user)=existing else{return Ok((Change::NotFound,None))};
            let next_role=role.unwrap_or(user.role);let next_enabled=enabled.unwrap_or(user.enabled);
            if user.role==Role::Admin && user.enabled && (next_role!=Role::Admin || !next_enabled) {
                let admins:i64=transaction.query_row("SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1",[],|row|row.get(0))?;
                if admins<=1{return Ok((Change::Conflict,None))}
            }
            if let Some((salt,hash))=new_password {
                transaction.execute("UPDATE users SET salt=?1,password_hash=?2,password_epoch=password_epoch+1,role=?3,enabled=?4,updated_at=?5 WHERE id=?6",params![salt.as_slice(),hash.as_slice(),next_role.as_str(),i64::from(next_enabled),now()?,id])?;
                transaction.execute("DELETE FROM sessions WHERE user_id=?1",params![id])?;
            } else {
                transaction.execute("UPDATE users SET role=?1,enabled=?2,updated_at=?3 WHERE id=?4",params![next_role.as_str(),i64::from(next_enabled),now()?,id])?;
                if !next_enabled || next_role!=user.role {transaction.execute("DELETE FROM sessions WHERE user_id=?1",params![id])?;}
            }
            user.role=next_role;user.enabled=next_enabled;
            transaction.commit()?;Ok((Change::Applied,Some(user)))
        }).await?
    }

    pub async fn delete(&self, id: i64) -> Result<Change> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection = connection(&path)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
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
            transaction.commit()?;
            Ok(Change::Applied)
        })
        .await?
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

    fn store() -> (tempfile::TempDir, Arc<Store>) {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("accounts.sqlite3");
        let store = Arc::new(Store::open(path).unwrap());
        (directory, store)
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
        let username = store.list().await.unwrap()[0].username.clone();
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
        assert_eq!(store.delete(root.id).await.unwrap(), Change::Conflict);
        assert_eq!(
            store
                .update(root.id, Some(Role::Viewer), None, None)
                .await
                .unwrap()
                .0,
            Change::Conflict
        );
        assert_eq!(
            store
                .update(root.id, None, Some(false), None)
                .await
                .unwrap()
                .0,
            Change::Conflict
        );
        let second = store
            .create(
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
            .update(second.id, Some(Role::Viewer), None, None)
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
            .update(second.id, None, None, Some("new secure password".into()))
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
        assert_eq!(store.delete(root.id).await.unwrap(), Change::Conflict);
        assert_eq!(store.delete(second.id).await.unwrap(), Change::Applied);
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
            store.list().await.is_err(),
            "a swapped symlink must not be followed"
        );
        std::fs::remove_file(&path).unwrap();
        assert!(
            store.list().await.is_err(),
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
