//! Redis-backed whole-configuration storage.
//!
//! A snapshot is one string value. Redis executes each script atomically, so
//! readers cannot observe a revision separately from its JSON. Revisions are
//! compared as canonical decimal strings: Lua never converts a revision to a
//! number (Redis embeds Lua 5.1 numbers, which cannot represent every `u64`).
//!
//! Wire layout `hangang-config-v2\n<epoch>\n<revision>\n<json>`. A legacy
//! `hangang-config-v1\n<revision>\n<json>` value is upgraded in place, inside
//! the script that first reads it, so concurrent readers converge on one
//! epoch. ACME HTTP-01 challenges live under `<key>:acme:<token>` with a TTL.

use crate::{
    config::Config,
    config_store::{
        Access, CasResult, ConfigStore, MAX_CONFIG_BYTES, StoreError, StoreResult, Stored,
        check_challenge, check_challenge_token, check_epoch, decode, encode, new_epoch,
        next_revision, resolve_cas,
    },
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use async_trait::async_trait;
use redis::{ConnectionAddr, IntoConnectionInfo, aio::ConnectionManagerConfig};
use std::{future::Future, net::IpAddr, sync::Arc, time::Duration};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(6);
const MAX_KEY_BYTES: usize = 1024;
const ACME_KEY_SEPARATOR: &str = ":acme:";
const LEGACY_WIRE_PREFIX: &str = "hangang-config-v1\n";
const WIRE_PREFIX: &str = "hangang-config-v2\n";
// Prefix + 20 decimal u64 digits + separator. JSON itself is at most 1 MiB.
const MAX_LEGACY_WIRE_BYTES: usize = MAX_CONFIG_BYTES + LEGACY_WIRE_PREFIX.len() + 21;
// The v2 layout adds a 32 character epoch line.
const MAX_WIRE_BYTES: usize = MAX_LEGACY_WIRE_BYTES + 33;
const _: () = assert!(MAX_LEGACY_WIRE_BYTES == 1_048_615 && MAX_WIRE_BYTES == 1_048_648);

// Shared prelude: the size test happens in Redis, before it sends the value
// to this process, and a legacy value is rewritten to the v2 layout with the
// fresh epoch passed as the last argument. Only the first script to see the
// legacy value rewrites it; later callers read the winner's epoch.
macro_rules! normalized_script {
    ($body:literal) => {
        concat!(
            r#"
local current = redis.call('GET', KEYS[1])
if current then
  if string.len(current) > 1048648 then
    return redis.error_reply('hangang config value exceeds size limit')
  end
  local legacy = 'hangang-config-v1\n'
  if string.sub(current, 1, string.len(legacy)) == legacy then
    if string.len(current) > 1048615 then
      return redis.error_reply('hangang config value exceeds size limit')
    end
    current = 'hangang-config-v2\n' .. ARGV[#ARGV] .. '\n' .. string.sub(current, string.len(legacy) + 1)
    redis.call('SET', KEYS[1], current)
  end
end
"#,
            $body
        )
    };
}

// ARGV[1] = fresh epoch for a legacy upgrade.
const LOAD_SCRIPT: &str = normalized_script!(
    r#"
if not current then return false end
return current
"#
);

// ARGV[1] = new wire value, ARGV[2] = its epoch (also used for a legacy upgrade).
const BOOTSTRAP_SCRIPT: &str = normalized_script!(
    r#"
if not current then
  redis.call('SET', KEYS[1], ARGV[1])
  return ARGV[1]
end
return current
"#
);

// ARGV[1] = caller epoch, ARGV[2] = expected revision (canonical decimal),
// ARGV[3] = new wire value, ARGV[4] = fresh epoch for a legacy upgrade.
const CAS_SCRIPT: &str = normalized_script!(
    r#"
if not current then
  return redis.error_reply('hangang configuration store is not initialized')
end
local prefix = 'hangang-config-v2\n'
if string.sub(current, 1, string.len(prefix)) ~= prefix then
  return redis.error_reply('hangang config value has an invalid schema')
end
local epoch_end = string.find(current, '\n', string.len(prefix) + 1, true)
if not epoch_end then
  return redis.error_reply('hangang config value has no epoch separator')
end
local revision_end = string.find(current, '\n', epoch_end + 1, true)
if not revision_end then
  return redis.error_reply('hangang config value has no revision separator')
end
local epoch = string.sub(current, string.len(prefix) + 1, epoch_end - 1)
local revision = string.sub(current, epoch_end + 1, revision_end - 1)
if epoch == ARGV[1] and revision == ARGV[2] then
  redis.call('SET', KEYS[1], ARGV[3])
  return {1, false}
end
return {0, current}
"#
);

/// A Redis `ConfigStore` using one caller-owned key.
///
/// `connect` requires verified TLS (`rediss://`). For local development and
/// owned test instances, `connect_unencrypted` accepts `redis://` only when
/// the URL contains a literal loopback address or `localhost`.
#[derive(Clone)]
pub struct RedisConfigStore {
    connection: redis::aio::ConnectionManager,
    key: Arc<str>,
}

impl RedisConfigStore {
    /// Connect to Redis with certificate and hostname verification.
    pub async fn connect(url: &str, key: impl Into<String>) -> Result<Self> {
        let key = key.into();
        validate_key(&key)?;
        let info = parse_connection(url)?;
        require_verified_tls(&info)?;
        let client = redis::Client::open(info).context("create Redis configuration client")?;
        Self::connect_client(client, key).await
    }

    /// Connect to Redis with certificate and hostname verification using a
    /// caller supplied PEM encoded CA certificate or chain.
    ///
    /// The CA is passed to redis' native TLS configuration, so hostname
    /// verification remains enabled. The constructor requires a verified
    /// `rediss://` URL just like [`Self::connect`].
    pub async fn connect_with_ca(
        url: &str,
        key: impl Into<String>,
        root_cert_pem: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let key = key.into();
        validate_key(&key)?;
        let info = parse_connection(url)?;
        require_verified_tls(&info)?;
        ensure!(
            !root_cert_pem.as_ref().is_empty(),
            "Redis custom CA certificate must not be empty"
        );
        let client = redis::Client::build_with_tls(
            info,
            redis::TlsCertificates {
                client_tls: None,
                root_cert: Some(root_cert_pem.as_ref().to_vec()),
            },
        )
        .context("create Redis TLS configuration client")?;
        Self::connect_client(client, key).await
    }

    /// Connect without TLS to a Redis server on a literal loopback host.
    pub async fn connect_unencrypted(url: &str, key: impl Into<String>) -> Result<Self> {
        let key = key.into();
        validate_key(&key)?;
        let info = parse_connection(url)?;
        match info.addr() {
            ConnectionAddr::Tcp(host, _) if is_loopback_host(host) => {}
            ConnectionAddr::Tcp(_, _) => {
                bail!("unencrypted Redis is limited to loopback hosts")
            }
            _ => bail!("unencrypted Redis requires a redis:// loopback URL"),
        }
        let client = redis::Client::open(info).context("create Redis configuration client")?;
        Self::connect_client(client, key).await
    }

    async fn connect_client(client: redis::Client, key: String) -> Result<Self> {
        debug_assert!(validate_key(&key).is_ok());
        let settings = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(CONNECT_TIMEOUT))
            .set_response_timeout(Some(RESPONSE_TIMEOUT))
            .set_number_of_retries(2)
            .set_min_delay(Duration::from_millis(50))
            .set_max_delay(Duration::from_millis(250));
        let connection = tokio::time::timeout(
            OPERATION_TIMEOUT,
            redis::aio::ConnectionManager::new_with_config(client, settings),
        )
        .await
        .context("Redis configuration store connection timed out")?
        .context("connect Redis configuration store")?;
        Ok(Self {
            connection,
            key: key.into(),
        })
    }

    fn challenge_key(&self, token: &str) -> String {
        format!("{}{ACME_KEY_SEPARATOR}{token}", self.key)
    }

    /// Bound one round trip and type its failure. The connection manager
    /// never re-sends a command, so an unanswered mutation is indeterminate.
    async fn run<T>(
        &self,
        access: Access,
        context: &'static str,
        operation: impl Future<Output = redis::RedisResult<T>>,
    ) -> StoreResult<T> {
        match tokio::time::timeout(OPERATION_TIMEOUT, operation).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(classify(error, access, context)),
            Err(_) => Err(access.transport(anyhow!("{context} timed out"))),
        }
    }

    async fn load_wire(&self) -> StoreResult<Option<Vec<u8>>> {
        let mut connection = self.connection.clone();
        let script = redis::Script::new(LOAD_SCRIPT);
        let mut invocation = script.prepare_invoke();
        invocation.key(self.key.as_bytes()).arg(new_epoch()?);
        let operation = invocation.invoke_async(&mut connection);
        self.run(Access::Read, "read Redis configuration store", operation)
            .await
    }
}

fn validate_key(key: &str) -> Result<()> {
    ensure!(!key.is_empty(), "Redis configuration key must not be empty");
    ensure!(
        key.len() <= MAX_KEY_BYTES,
        "Redis configuration key exceeds 1024 bytes"
    );
    ensure!(
        !key.contains(ACME_KEY_SEPARATOR),
        "Redis configuration key contains reserved ACME namespace separator {ACME_KEY_SEPARATOR}"
    );
    Ok(())
}

/// Server replies that describe our own value, or a value of the wrong type,
/// are content failures. Anything unanswered (I/O, timeout, dropped
/// connection) is a transport failure typed by the access; any other server
/// error (`OOM`, `READONLY`, `NOAUTH`, ...) rejected the request, so nothing
/// changed and the store is unavailable for it.
fn classify(error: redis::RedisError, access: Access, context: &'static str) -> StoreError {
    use redis::ErrorKind;
    let content = error.code() == Some("hangang")
        || error.code() == Some("WRONGTYPE")
        || error
            .detail()
            .is_some_and(|detail| detail.contains("hangang config"))
        || matches!(
            error.kind(),
            ErrorKind::Parse | ErrorKind::UnexpectedReturnType
        );
    let unanswered = error.is_io_error()
        || error.is_timeout()
        || error.is_connection_dropped()
        || error.is_connection_refusal()
        || matches!(error.kind(), ErrorKind::Io);
    let error = anyhow!(error).context(context);
    if content {
        StoreError::Invalid(error)
    } else if unanswered {
        access.transport(error)
    } else {
        StoreError::Unavailable(error)
    }
}

#[async_trait]
impl ConfigStore for RedisConfigStore {
    async fn load_latest(&self) -> StoreResult<Option<Stored>> {
        self.load_wire()
            .await?
            .map(|wire| decode_wire(&wire))
            .transpose()
    }

    async fn bootstrap(&self, initial: Config) -> StoreResult<Stored> {
        let epoch = new_epoch()?;
        let wire = encode_wire(&epoch, &initial)?;
        let mut connection = self.connection.clone();
        let script = redis::Script::new(BOOTSTRAP_SCRIPT);
        let mut invocation = script.prepare_invoke();
        invocation.key(self.key.as_bytes()).arg(wire).arg(epoch);
        let operation = invocation.invoke_async::<Vec<u8>>(&mut connection);
        let winner = self
            .run(
                Access::Mutation,
                "bootstrap Redis configuration store",
                operation,
            )
            .await?;
        decode_wire(&winner)
    }

    async fn compare_and_swap(
        &self,
        epoch: &str,
        expected: u64,
        mut next: Config,
    ) -> StoreResult<CasResult> {
        next.revision = next_revision(expected)?;
        let wire = encode_wire(epoch, &next)?;
        let mut connection = self.connection.clone();
        // The script compares the full canonical decimal string. Do not change
        // this to Lua tonumber() or INCR: both alter the revision contract.
        let script = redis::Script::new(CAS_SCRIPT);
        let mut invocation = script.prepare_invoke();
        invocation
            .key(self.key.as_bytes())
            .arg(epoch)
            .arg(expected.to_string())
            .arg(wire)
            .arg(new_epoch()?);
        let operation = invocation.invoke_async::<(i64, Option<Vec<u8>>)>(&mut connection);
        let (status, current) = self
            .run(
                Access::Mutation,
                "compare and swap Redis configuration store",
                operation,
            )
            .await?;
        match status {
            1 if current.is_none() => Ok(CasResult::Applied(Stored {
                epoch: epoch.to_owned(),
                config: next,
            })),
            0 => {
                let current = current.ok_or_else(|| {
                    StoreError::Invalid(anyhow!("Redis CAS conflict omitted the current value"))
                })?;
                Ok(resolve_cas(decode_wire(&current)?, epoch, &next))
            }
            _ => Err(StoreError::Invalid(anyhow!(
                "Redis CAS returned an invalid response"
            ))),
        }
    }

    async fn publish_challenge(
        &self,
        token: &str,
        key_authorization: &str,
        ttl: Duration,
    ) -> StoreResult<()> {
        check_challenge(token, key_authorization, ttl)?;
        let mut connection = self.connection.clone();
        let mut command = redis::cmd("SET");
        command
            .arg(self.challenge_key(token))
            .arg(key_authorization)
            .arg("PX")
            .arg(u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX));
        let operation = command.query_async::<()>(&mut connection);
        self.run(Access::Mutation, "publish Redis ACME challenge", operation)
            .await
    }

    async fn lookup_challenge(&self, token: &str) -> StoreResult<Option<String>> {
        check_challenge_token(token)?;
        let mut connection = self.connection.clone();
        let mut command = redis::cmd("GET");
        command.arg(self.challenge_key(token));
        let operation = command.query_async::<Option<String>>(&mut connection);
        self.run(Access::Read, "look up Redis ACME challenge", operation)
            .await
    }

    async fn withdraw_challenge(&self, token: &str) -> StoreResult<()> {
        check_challenge_token(token)?;
        let mut connection = self.connection.clone();
        let mut command = redis::cmd("DEL");
        command.arg(self.challenge_key(token));
        let operation = command.query_async::<()>(&mut connection);
        self.run(Access::Mutation, "withdraw Redis ACME challenge", operation)
            .await
    }
}

fn parse_connection(url: &str) -> Result<redis::ConnectionInfo> {
    // `ConnectionInfo`'s Debug implementation redacts credentials. Avoid
    // attaching the original URL to errors because it may contain a password.
    url.into_connection_info()
        .context("parse Redis configuration URL")
}

fn require_verified_tls(info: &redis::ConnectionInfo) -> Result<()> {
    match info.addr() {
        ConnectionAddr::TcpTls {
            insecure: false, ..
        } => Ok(()),
        ConnectionAddr::TcpTls { insecure: true, .. } => {
            bail!("insecure Redis TLS is forbidden")
        }
        _ => bail!("remote Redis requires a rediss:// URL with verified TLS"),
    }
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn encode_wire(epoch: &str, config: &Config) -> StoreResult<Vec<u8>> {
    check_epoch(epoch)?;
    let json = encode(config)?;
    let mut wire = Vec::with_capacity(WIRE_PREFIX.len() + 33 + 21 + json.len());
    wire.extend_from_slice(WIRE_PREFIX.as_bytes());
    wire.extend_from_slice(epoch.as_bytes());
    wire.push(b'\n');
    wire.extend_from_slice(config.revision.to_string().as_bytes());
    wire.push(b'\n');
    wire.extend_from_slice(json.as_bytes());
    if wire.len() > MAX_WIRE_BYTES {
        return Err(StoreError::Invalid(anyhow!(
            "Redis configuration wire value exceeds size limit"
        )));
    }
    Ok(wire)
}

/// Decode a v2 value. A v1 value never reaches this process: every script
/// upgrades it before returning.
fn decode_wire(wire: &[u8]) -> StoreResult<Stored> {
    if wire.len() > MAX_WIRE_BYTES {
        return Err(StoreError::Invalid(anyhow!(
            "Redis configuration wire value exceeds size limit"
        )));
    }
    let body = wire.strip_prefix(WIRE_PREFIX.as_bytes()).ok_or_else(|| {
        StoreError::Invalid(anyhow!("stored Redis configuration has an invalid schema"))
    })?;
    let epoch_end = body.iter().position(|byte| *byte == b'\n').ok_or_else(|| {
        StoreError::Invalid(anyhow!("stored Redis configuration has no epoch separator"))
    })?;
    let epoch = std::str::from_utf8(&body[..epoch_end])
        .map_err(|_| StoreError::Invalid(anyhow!("stored Redis epoch is not UTF-8")))?;
    check_epoch(epoch)?;
    let body = &body[epoch_end + 1..];
    let separator = body.iter().position(|byte| *byte == b'\n').ok_or_else(|| {
        StoreError::Invalid(anyhow!(
            "stored Redis configuration has no revision separator"
        ))
    })?;
    let revision = decode_revision(&body[..separator])?;
    let json = std::str::from_utf8(&body[separator + 1..]).map_err(|_| {
        StoreError::Invalid(anyhow!("stored Redis configuration JSON is not UTF-8"))
    })?;
    Ok(Stored {
        epoch: epoch.to_owned(),
        config: decode(revision, json)?,
    })
}

fn decode_revision(bytes: &[u8]) -> StoreResult<u64> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| StoreError::Invalid(anyhow!("stored Redis revision is not UTF-8")))?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(StoreError::Invalid(anyhow!(
            "stored Redis revision is not an unsigned decimal integer"
        )));
    }
    let revision = text.parse::<u64>().map_err(|_| {
        StoreError::Invalid(anyhow!("stored Redis revision is outside the u64 range"))
    })?;
    if revision.to_string() != text {
        return Err(StoreError::Invalid(anyhow!(
            "stored Redis revision is not canonical decimal"
        )));
    }
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> String {
        "0123456789abcdef0123456789abcdef".into()
    }

    #[test]
    fn wire_round_trip_preserves_full_u64_precision() {
        let config = Config {
            certificates: vec![],
            revision: u64::MAX,
            ..Config::default()
        };
        let stored = decode_wire(&encode_wire(&epoch(), &config).unwrap()).unwrap();
        assert_eq!(stored.config, config);
        assert_eq!(stored.epoch, epoch());
    }

    #[test]
    fn wire_rejects_noncanonical_revision_and_unknown_schema() {
        let e = epoch();
        for wire in [
            format!("hangang-config-v2\n{e}\n01\n{{\"revision\":1}}"),
            "hangang-config-v1\n1\n{\"revision\":1}".to_owned(),
            "hangang-config-v3\n1\n{\"revision\":1}".to_owned(),
            format!("hangang-config-v2\n{e}\n{{\"revision\":1}}"),
            "hangang-config-v2\nnot-an-epoch\n1\n{\"revision\":1}".to_owned(),
            format!(
                "hangang-config-v2\n{}\n1\n{{\"revision\":1}}",
                e.to_uppercase()
            ),
        ] {
            assert!(
                matches!(decode_wire(wire.as_bytes()), Err(StoreError::Invalid(_))),
                "{wire:?}"
            );
        }
        assert!(matches!(
            encode_wire("short", &Config::default()),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn scripts_share_the_legacy_upgrade_prelude_and_size_guards() {
        let prelude = normalized_script!("");
        assert!(prelude.contains("hangang-config-v1\\n"));
        for script in [LOAD_SCRIPT, BOOTSTRAP_SCRIPT, CAS_SCRIPT] {
            assert!(script.contains(&format!("> {MAX_WIRE_BYTES}")));
            assert!(script.contains(&format!("> {MAX_LEGACY_WIRE_BYTES}")));
            assert!(script.contains("ARGV[#ARGV]"));
            assert!(script.starts_with(prelude));
        }
    }

    #[test]
    fn transport_policy_requires_verified_tls_or_literal_loopback_plaintext() {
        let plaintext_remote = parse_connection("redis://redis.example:6379/").unwrap();
        assert!(require_verified_tls(&plaintext_remote).is_err());
        assert!(!matches!(
            plaintext_remote.addr(),
            ConnectionAddr::Tcp(host, _) if is_loopback_host(host)
        ));

        let insecure_tls = parse_connection("rediss://localhost:6379/#insecure").unwrap();
        assert!(require_verified_tls(&insecure_tls).is_err());

        let verified_tls = parse_connection("rediss://localhost:6379/").unwrap();
        assert!(require_verified_tls(&verified_tls).is_ok());
        let loopback = parse_connection("redis://127.0.0.1:6379/").unwrap();
        assert!(matches!(
            loopback.addr(),
            ConnectionAddr::Tcp(host, _) if is_loopback_host(host)
        ));
    }

    #[tokio::test]
    async fn configuration_keys_cannot_alias_an_acme_challenge_namespace() {
        for key in ["tenant:acme:token", ":acme:", "prefix:acme:suffix"] {
            let error = RedisConfigStore::connect_unencrypted("redis://127.0.0.1:1/", key)
                .await
                .err()
                .expect("reserved key must fail before connection");
            assert!(
                error.to_string().contains("reserved ACME namespace"),
                "{error:#}"
            );
        }
        assert!(validate_key("tenant:config").is_ok());
    }
}
