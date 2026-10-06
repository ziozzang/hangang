//! Shared security counters. All keys use a namespace hash tag; scripts are atomic.
//! Redis must reserve these keys against eviction. Abandoned observations expire;
//! callbacks cannot recreate expired or administrator-cleared records.
use crate::{
    path_failure_bans::{BanEvent, BanInfo, Rule as BanRule, Scope},
    path_rate_limits::Rule as RateRule,
};
use hyper::Request;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::Semaphore;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub url_env: String,
    pub namespace: String,
    #[serde(default)]
    pub allow_insecure_remote: bool,
}
impl Settings {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.url_env.starts_with("HANGANG_SECURITY_REDIS_")
                && self.url_env.len() <= 128
                && self
                    .url_env
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
            "invalid security Redis environment reference"
        );
        anyhow::ensure!(
            !self.namespace.is_empty()
                && self.namespace.len() <= 128
                && self
                    .namespace
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_:.".contains(&b)),
            "invalid security Redis namespace"
        );
        Ok(())
    }
}
#[derive(Debug, Clone, Copy)]
pub(crate) struct Error {
    pub status: u16,
}
impl Error {
    pub fn status(self) -> u16 {
        self.status
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "security backend unavailable ({})", self.status)
    }
}
impl std::error::Error for Error {}
fn unavailable(_: impl std::fmt::Debug) -> Error {
    Error { status: 503 }
}

pub(crate) struct Backend {
    pub settings: Settings,
    connection: redis::aio::ConnectionManager,
    permits: Semaphore,
    prefix: String,
    nonce: String,
    sequence: AtomicU64,
}
impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityRedis")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}
fn digest<T: Serialize>(value: &T) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("serializable security rule"))
    )
}
impl Backend {
    pub fn new(settings: Settings) -> Result<Arc<Self>, Error> {
        settings.validate().map_err(unavailable)?;
        let url = std::env::var(&settings.url_env).map_err(unavailable)?;
        Self::from_url(settings, &url)
    }
    fn from_url(settings: Settings, url: &str) -> Result<Arc<Self>, Error> {
        settings.validate().map_err(unavailable)?;
        use redis::{ConnectionAddr, IntoConnectionInfo};
        let info = url.into_connection_info().map_err(unavailable)?;
        match info.addr() {
            ConnectionAddr::TcpTls {
                insecure: false, ..
            } => {}
            ConnectionAddr::Tcp(host, _)
                if settings.allow_insecure_remote
                    || host.eq_ignore_ascii_case("localhost")
                    || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()) => {}
            _ => return Err(Error { status: 503 }),
        }
        tokio::runtime::Handle::try_current().map_err(unavailable)?;
        let client = redis::Client::open(info).map_err(unavailable)?;
        let cfg = redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Some(Duration::from_millis(900)))
            .set_response_timeout(Some(Duration::from_millis(900)))
            .set_number_of_retries(0);
        let connection = redis::aio::ConnectionManager::new_lazy_with_config(client, cfg)
            .map_err(unavailable)?;
        let mut random = [0; 32];
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut random)
            .map_err(unavailable)?;
        let nonce = format!("{:x}", Sha256::digest(random));
        let prefix = format!("hangang:security:{{{}}}", digest(&settings.namespace));
        Ok(Arc::new(Self {
            settings,
            connection,
            permits: Semaphore::new(64),
            prefix,
            nonce,
            sequence: AtomicU64::new(0),
        }))
    }
    async fn invoke<T: redis::FromRedisValue>(
        &self,
        script: &str,
        keys: Vec<String>,
        args: Vec<String>,
    ) -> Result<T, Error> {
        let _permit = self.permits.try_acquire().map_err(unavailable)?;
        let mut connection = self.connection.clone();
        let script = redis::Script::new(script);
        let mut call = script.prepare_invoke();
        for key in keys {
            call.key(key);
        }
        for arg in args {
            call.arg(arg);
        }
        tokio::time::timeout(Duration::from_secs(1), call.invoke_async(&mut connection))
            .await
            .map_err(unavailable)?
            .map_err(unavailable)
    }
    fn rate_key(&self, rule: &RateRule) -> String {
        format!("{}:rate:{}", self.prefix, digest(rule))
    }
    fn ban_keys(&self, rule: &BanRule) -> [String; 2] {
        let base = format!("{}:ban:{}", self.prefix, digest(rule));
        [format!("{base}:index"), format!("{base}:records")]
    }
    pub async fn check_rates(
        &self,
        rules: &[RateRule],
        request: &Request<()>,
        host: Option<&str>,
    ) -> Result<(), Error> {
        let mut keys = vec![];
        let mut args = vec![];
        for rule in rules {
            if selected(
                &rule.path,
                &rule.hosts,
                rule.include_subpaths,
                request,
                host,
            )? {
                keys.push(self.rate_key(rule));
                args.push(serde_json::to_string(rule).map_err(unavailable)?);
            }
        }
        if keys.is_empty() {
            return Ok(());
        }
        let admitted: i64 = self.invoke(RATE, keys, args).await?;
        if admitted == 1 {
            Ok(())
        } else {
            Err(Error { status: 429 })
        }
    }
    pub async fn check_bans(
        &self,
        rules: &[BanRule],
        request: &Request<()>,
        host: Option<&str>,
        ip: IpAddr,
        scope: Scope,
    ) -> Result<(), Error> {
        tokio::time::timeout(
            Duration::from_secs(1),
            self.check_bans_inner(rules, request, host, ip, scope),
        )
        .await
        .map_err(unavailable)?
    }
    pub async fn observe(
        self: &Arc<Self>,
        rules: &[BanRule],
        request: &Request<()>,
        host: Option<&str>,
        ip: IpAddr,
    ) -> Result<Observation, Error> {
        tokio::time::timeout(
            Duration::from_secs(1),
            self.observe_inner(rules, request, host, ip),
        )
        .await
        .map_err(unavailable)?
    }
    pub async fn list(
        &self,
        rules: &[BanRule],
        ip: Option<IpAddr>,
        limit: usize,
    ) -> Result<(Vec<BanInfo>, bool), Error> {
        tokio::time::timeout(Duration::from_secs(1), self.list_inner(rules, ip, limit))
            .await
            .map_err(unavailable)?
    }
    async fn check_bans_inner(
        &self,
        rules: &[BanRule],
        request: &Request<()>,
        host: Option<&str>,
        ip: IpAddr,
        scope: Scope,
    ) -> Result<(), Error> {
        for rule in rules {
            let selector = crate::path_blocks::Rule {
                path: rule.path.clone(),
                hosts: rule.hosts.clone(),
            };
            let applies = match scope {
                Scope::Global => true,
                Scope::Host => crate::path_blocks::scope_host_matches(&selector, request, host),
                Scope::Url => selected(
                    &rule.path,
                    &rule.hosts,
                    rule.include_subpaths,
                    request,
                    host,
                )?,
            };
            if applies {
                let banned: i64 = self
                    .invoke(
                        BAN,
                        self.ban_keys(rule).to_vec(),
                        vec!["check".into(), ip.to_canonical().to_string()],
                    )
                    .await?;
                if banned == 1 {
                    return Err(Error { status: 429 });
                }
            }
        }
        Ok(())
    }
    async fn observe_inner(
        self: &Arc<Self>,
        rules: &[BanRule],
        request: &Request<()>,
        host: Option<&str>,
        ip: IpAddr,
    ) -> Result<Observation, Error> {
        let mut records = Vec::new();
        let ip = ip.to_canonical().to_string();
        for rule in rules {
            if !selected(
                &rule.path,
                &rule.hosts,
                rule.include_subpaths,
                request,
                host,
            )? {
                continue;
            }
            let token = format!(
                "{}:{}",
                self.nonce,
                self.sequence.fetch_add(1, Ordering::Relaxed)
            );
            let epoch: String = self
                .invoke(
                    BAN,
                    self.ban_keys(rule).to_vec(),
                    vec!["reserve".into(), ip.clone(), token, ttl(rule).to_string()],
                )
                .await?;
            if epoch == "capacity" {
                return Err(Error { status: 503 });
            }
            if epoch == "banned" {
                return Err(Error { status: 429 });
            }
            records.push((rule.clone(), epoch));
        }
        Ok(Observation {
            backend: self.clone(),
            ip,
            records,
        })
    }
    async fn list_inner(
        &self,
        rules: &[BanRule],
        ip: Option<IpAddr>,
        limit: usize,
    ) -> Result<(Vec<BanInfo>, bool), Error> {
        let mut out = vec![];
        let mut truncated = false;
        let limit = limit.min(200);
        for rule in rules {
            let entries: Vec<String> = self
                .invoke(
                    BAN,
                    self.ban_keys(rule).to_vec(),
                    vec![
                        "list".into(),
                        ip.map(|ip| ip.to_canonical().to_string())
                            .unwrap_or_default(),
                        (limit.saturating_sub(out.len()) + 1).to_string(),
                    ],
                )
                .await?;
            for entry in entries {
                let (ip, seconds) = entry.split_once('|').ok_or(Error { status: 503 })?;
                if out.len() == limit {
                    truncated = true;
                    break;
                }
                out.push(BanInfo {
                    ip: ip.parse().map_err(unavailable)?,
                    path: rule.path.clone(),
                    remaining_seconds: seconds.parse().map_err(unavailable)?,
                });
            }
            if truncated {
                break;
            }
        }
        out.sort_by(|a, b| a.ip.cmp(&b.ip).then_with(|| a.path.cmp(&b.path)));
        Ok((out, truncated))
    }
    pub async fn clear_ip(&self, rules: &[BanRule], ip: IpAddr) -> Result<usize, Error> {
        let mut keys = vec![];
        for rule in rules {
            keys.extend(self.ban_keys(rule));
        }
        if keys.is_empty() {
            return Ok(0);
        }
        self.invoke(CLEAR, keys, vec![ip.to_canonical().to_string()])
            .await
    }
}
fn ttl(rule: &BanRule) -> u32 {
    rule.window_seconds.max(rule.ban_seconds).max(60)
}
fn selected(
    path: &str,
    hosts: &[String],
    sub: bool,
    request: &Request<()>,
    host: Option<&str>,
) -> Result<bool, Error> {
    crate::path_blocks::selector_matches(
        &crate::path_blocks::Rule {
            path: path.into(),
            hosts: hosts.to_vec(),
        },
        request,
        host,
        sub,
    )
    .map_err(|status| Error { status })
}
pub(crate) struct Observation {
    backend: Arc<Backend>,
    ip: String,
    records: Vec<(BanRule, String)>,
}
impl Observation {
    pub fn is_failure(&self, status: u16) -> bool {
        self.records
            .iter()
            .any(|(rule, _)| rule.statuses.contains(&status))
    }
    pub async fn record(self, status: u16) -> Result<Vec<BanEvent>, Error> {
        tokio::time::timeout(Duration::from_secs(1), self.record_inner(status))
            .await
            .map_err(unavailable)?
    }
    async fn record_inner(self, status: u16) -> Result<Vec<BanEvent>, Error> {
        let mut events = vec![];
        for (rule, epoch) in self.records {
            let banned: i64 = self
                .backend
                .invoke(
                    BAN,
                    self.backend.ban_keys(&rule).to_vec(),
                    vec![
                        "record".into(),
                        self.ip.clone(),
                        epoch,
                        u8::from(rule.statuses.contains(&status)).to_string(),
                        rule.failures.to_string(),
                        rule.window_seconds.to_string(),
                        rule.ban_seconds.to_string(),
                        ttl(&rule).to_string(),
                        format!(
                            "{}:{}",
                            self.backend.nonce,
                            self.backend.sequence.fetch_add(1, Ordering::Relaxed)
                        ),
                    ],
                )
                .await?;
            if banned == -1 {
                return Err(Error { status: 503 });
            }
            if banned == 1 {
                events.push(BanEvent {
                    path: rule.path,
                    ban_seconds: rule.ban_seconds,
                });
            }
        }
        Ok(events)
    }
}
const RATE: &str = r#"
local t=redis.call('TIME'); local now=tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000)
local pending={}
for i,key in ipairs(KEYS) do
 local rule=cjson.decode(ARGV[i]); local old=redis.call('GET',key); local state=old and cjson.decode(old) or {updated=now,credit=rule.burst,windows={}}
 local maxage=1000
 if rule.tps then
  state.credit=math.min(rule.burst,state.credit+math.max(0,now-state.updated)*rule.tps/1000)
  if state.credit<1 then return 0 end
  state.credit=state.credit-1; maxage=math.max(maxage,math.ceil(rule.burst/rule.tps*1000))
 end
 state.updated=math.max(now,state.updated)
 for j,w in ipairs(rule.limits or {}) do
  local bucket=math.floor(now/(w.window_seconds*1000)); local previous=state.windows[j]
  local count=(previous and previous.bucket==bucket) and previous.count or 0
  if count>=w.requests then return 0 end
  state.windows[j]={bucket=bucket,count=count+1}; maxage=math.max(maxage,w.window_seconds*1000)
 end
 pending[i]={state=state,ttl=maxage+1000}
end
for i,key in ipairs(KEYS) do redis.call('SET',key,cjson.encode(pending[i].state),'PX',pending[i].ttl) end
return 1
"#;
const CLEAR: &str = r#"
local count=0
for i=1,#KEYS,2 do count=count+redis.call('HDEL',KEYS[i+1],ARGV[1]); redis.call('ZREM',KEYS[i],ARGV[1]) end
return count
"#;
const BAN: &str = r#"
local t=redis.call('TIME'); local now=tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000)
local expired=redis.call('ZRANGEBYSCORE',KEYS[1],'-inf',now,'LIMIT',0,1024)
for _,ip in ipairs(expired) do redis.call('HDEL',KEYS[2],ip); redis.call('ZREM',KEYS[1],ip) end
local mode=ARGV[1]; local ip=ARGV[2]
local raw=redis.call('HGET',KEYS[2],ip); local state=raw and cjson.decode(raw) or nil
if mode=='check' then return (state and state.banned>now) and 1 or 0 end
if mode=='list' then
 local result={}; local members=ip~='' and {ip} or redis.call('ZRANGE',KEYS[1],0,1023)
 for _,member in ipairs(members) do
  local value=redis.call('HGET',KEYS[2],member)
  if value then local s=cjson.decode(value); if s.banned>now then table.insert(result,member..'|'..math.ceil((s.banned-now)/1000)); if #result>=tonumber(ARGV[3]) then break end end end
 end
 return result
end
if mode=='reserve' then
 if state and state.banned>now then return 'banned' end
 if not state then
  if redis.call('ZCARD',KEYS[1])>=1024 then return 'capacity' end
  state={epoch=ARGV[3],count=0,started=now,banned=0,flight=0}
 end
 state.flight=state.flight+1
 local expiry=now+tonumber(ARGV[4])*1000
 redis.call('HSET',KEYS[2],ip,cjson.encode(state)); redis.call('ZADD',KEYS[1],expiry,ip)
 redis.call('PEXPIRE',KEYS[1],tonumber(ARGV[4])*1000+1000); redis.call('PEXPIRE',KEYS[2],tonumber(ARGV[4])*1000+1000)
 return state.epoch
end
if mode=='record' then
 if not state then return ARGV[4]=='1' and -1 or 0 end
 if state.epoch~=ARGV[3] then return 0 end
 state.flight=math.max(0,state.flight-1)
 if state.banned>now then redis.call('HSET',KEYS[2],ip,cjson.encode(state)); return 0 end
 if now-state.started>=tonumber(ARGV[6])*1000 or state.banned>0 then state.started=now;state.count=0;state.banned=0 end
 local event=0
 if ARGV[4]=='1' then
  if state.count==0 then state.started=now end
  state.count=state.count+1
  if state.count>=tonumber(ARGV[5]) then state.banned=now+tonumber(ARGV[7])*1000;state.epoch=ARGV[9];state.flight=0;event=1 end
 end
 if state.count==0 and state.flight==0 then redis.call('HDEL',KEYS[2],ip);redis.call('ZREM',KEYS[1],ip)
 else
  redis.call('HSET',KEYS[2],ip,cjson.encode(state));redis.call('ZADD',KEYS[1],now+tonumber(ARGV[8])*1000,ip)
  redis.call('PEXPIRE',KEYS[1],tonumber(ARGV[8])*1000+1000);redis.call('PEXPIRE',KEYS[2],tonumber(ARGV[8])*1000+1000)
 end
 return event
end
return redis.error_reply('invalid security operation')
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_rate_limits::Window;
    fn settings(namespace: &str) -> Settings {
        Settings {
            url_env: "HANGANG_SECURITY_REDIS_TEST_URL".into(),
            namespace: namespace.into(),
            allow_insecure_remote: false,
        }
    }
    fn backend(namespace: &str) -> Arc<Backend> {
        Backend::from_url(
            Settings {
                allow_insecure_remote: true,
                ..settings(namespace)
            },
            &std::env::var("HANGANG_SECURITY_REDIS_TEST_URL").expect("isolated test Redis URL"),
        )
        .unwrap()
    }
    fn rate(path: &str, requests: u32) -> RateRule {
        RateRule {
            path: path.into(),
            hosts: vec![],
            include_subpaths: false,
            tps: None,
            burst: 1,
            limits: vec![
                Window {
                    requests,
                    window_seconds: 60,
                },
                Window {
                    requests: 100,
                    window_seconds: 86400,
                },
            ],
        }
    }
    fn ban() -> BanRule {
        BanRule {
            path: "/login".into(),
            hosts: vec!["example.test".into()],
            include_subpaths: false,
            failures: 2,
            window_seconds: 60,
            ban_seconds: 60,
            statuses: vec![401, 403],
        }
    }
    fn request(path: &str) -> Request<()> {
        Request::builder()
            .uri(path)
            .header("host", "example.test")
            .body(())
            .unwrap()
    }
    #[test]
    fn settings_never_accept_inline_credentials_or_unrelated_environment() {
        for env in [
            "REDIS_URL",
            "HANGANG_SECURITY_REDIS_password",
            "HANGANG_SECURITY_REDIS_\n",
        ] {
            let mut config = settings("tests");
            config.url_env = env.into();
            assert!(config.validate().is_err());
        }
        for namespace in ["", "{x}", "a\nb"] {
            assert!(settings(namespace).validate().is_err());
        }
        assert!(settings("test.example-1").validate().is_ok());
    }
    #[tokio::test]
    async fn remote_transport_requires_verified_tls_or_explicit_plaintext_opt_in() {
        for url in [
            "redis://:private-secret@192.0.2.1/",
            "rediss://:private-secret@localhost/#insecure",
            "unix:///tmp/private-secret",
            "https://private-secret/",
        ] {
            let error = Backend::from_url(settings("transport-test"), url).unwrap_err();
            assert_eq!(error.status, 503);
            assert!(!format!("{error:?} {error}").contains("private-secret"));
        }
        for url in [
            "redis://127.0.0.1/",
            "redis://localhost/",
            "rediss://redis.example.test/",
        ] {
            assert!(Backend::from_url(settings("transport-test"), url).is_ok());
        }
        assert!(
            Backend::from_url(
                Settings {
                    allow_insecure_remote: true,
                    ..settings("transport-test")
                },
                "redis://192.0.2.1/"
            )
            .is_ok()
        );
        assert!(
            Backend::from_url(
                Settings {
                    allow_insecure_remote: true,
                    ..settings("transport-test")
                },
                "rediss://localhost/#insecure"
            )
            .is_err()
        );
    }
    #[tokio::test]
    #[ignore = "requires isolated HANGANG_SECURITY_REDIS_TEST_URL"]
    async fn first_failure_starts_window_and_expired_ban_fences_older_observations() {
        let name = format!("test-generation-{}", std::process::id());
        let a = backend(&name);
        let rules = vec![ban()];
        let ip = "192.0.2.45".parse().unwrap();
        let old = a
            .observe(&rules, &request("/login"), None, ip)
            .await
            .unwrap();
        let first = a
            .observe(&rules, &request("/login"), None, ip)
            .await
            .unwrap();
        let reserved:i64=a.invoke("local t=redis.call('TIME');local s=cjson.decode(redis.call('HGET',KEYS[2],ARGV[1]));s.started=tonumber(t[1])*1000-30000;redis.call('HSET',KEYS[2],ARGV[1],cjson.encode(s));return s.started",a.ban_keys(&rules[0]).to_vec(),vec![ip.to_string()]).await.unwrap();
        assert!(first.record(401).await.unwrap().is_empty());
        let started: i64 = a
            .invoke(
                "local s=cjson.decode(redis.call('HGET',KEYS[2],ARGV[1]));return s.started",
                a.ban_keys(&rules[0]).to_vec(),
                vec![ip.to_string()],
            )
            .await
            .unwrap();
        assert!(started >= reserved + 30000);
        let second = a
            .observe(&rules, &request("/login"), None, ip)
            .await
            .unwrap();
        assert_eq!(second.record(401).await.unwrap().len(), 1);
        let _:i64=a.invoke("local s=cjson.decode(redis.call('HGET',KEYS[2],ARGV[1]));s.banned=1;redis.call('HSET',KEYS[2],ARGV[1],cjson.encode(s));return 1",a.ban_keys(&rules[0]).to_vec(),vec![ip.to_string()]).await.unwrap();
        let fresh = a
            .observe(&rules, &request("/login"), None, ip)
            .await
            .unwrap();
        assert!(old.record(401).await.unwrap().is_empty());
        assert!(fresh.record(401).await.unwrap().is_empty());
        assert!(
            a.check_bans(&rules, &request("/login"), None, ip, Scope::Url)
                .await
                .is_ok()
        );
    }
    #[tokio::test]
    async fn stalled_backend_fails_closed_with_bounded_deadline_and_unmatched_urls_pass() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = Backend::from_url(
            settings("offline-test"),
            &format!("redis://{}/", listener.local_addr().unwrap()),
        )
        .unwrap();
        let rules = vec![rate("/login", 1)];
        assert!(
            a.check_rates(&rules, &request("/images/x"), None)
                .await
                .is_ok()
        );
        let started = std::time::Instant::now();
        assert_eq!(
            a.check_rates(&rules, &request("/login"), None)
                .await
                .unwrap_err()
                .status,
            503
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }
    #[tokio::test]
    #[ignore = "requires isolated HANGANG_SECURITY_REDIS_TEST_URL"]
    async fn shared_limits_are_atomic_across_nodes_and_all_matching_rules() {
        let name = format!("test-rate-{}", std::process::id());
        let a = backend(&name);
        let b = backend(&name);
        let rules = vec![rate("/login", 7)];
        let mut tasks = vec![];
        for n in 0..32 {
            let backend = if n % 2 == 0 { a.clone() } else { b.clone() };
            let rules = rules.clone();
            tasks.push(tokio::spawn(async move {
                backend.check_rates(&rules, &request("/login"), None).await
            }));
        }
        let mut accepted = 0;
        for task in tasks {
            match task.await.unwrap() {
                Ok(()) => accepted += 1,
                Err(error) => assert_eq!(error.status, 429),
            }
        }
        assert_eq!(accepted, 7);
        assert!(
            a.check_rates(&rules, &request("/images/a.png"), None)
                .await
                .is_ok()
        );
        let name = format!("test-atomic-{}", std::process::id());
        let a = backend(&name);
        let rules = vec![rate("/login", 3), rate("/login", 1)];
        assert!(
            a.check_rates(&rules, &request("/login"), None)
                .await
                .is_ok()
        );
        assert_eq!(
            a.check_rates(&rules, &request("/login"), None)
                .await
                .unwrap_err()
                .status,
            429
        );
        let only = vec![rules[0].clone()];
        assert!(a.check_rates(&only, &request("/login"), None).await.is_ok());
        assert!(a.check_rates(&only, &request("/login"), None).await.is_ok());
        assert_eq!(
            a.check_rates(&only, &request("/login"), None)
                .await
                .unwrap_err()
                .status,
            429
        );
    }
    #[tokio::test]
    #[ignore = "requires isolated HANGANG_SECURITY_REDIS_TEST_URL"]
    async fn simultaneous_tps_minute_and_day_limits_all_apply() {
        let name = format!("test-daily-{}", std::process::id());
        let a = backend(&name);
        let mut rule = rate("/login", 100);
        rule.limits[1].requests = 1;
        assert!(
            a.check_rates(std::slice::from_ref(&rule), &request("/login"), None)
                .await
                .is_ok()
        );
        assert_eq!(
            a.check_rates(std::slice::from_ref(&rule), &request("/login"), None)
                .await
                .unwrap_err()
                .status,
            429
        );
        let name = format!("test-tps-{}", std::process::id());
        let a = backend(&name);
        let mut rule = rate("/login", 100);
        rule.tps = Some(1);
        rule.burst = 2;
        for _ in 0..2 {
            assert!(
                a.check_rates(std::slice::from_ref(&rule), &request("/login"), None)
                    .await
                    .is_ok()
            );
        }
        assert_eq!(
            a.check_rates(std::slice::from_ref(&rule), &request("/login"), None)
                .await
                .unwrap_err()
                .status,
            429
        );
    }
    #[tokio::test]
    #[ignore = "requires isolated HANGANG_SECURITY_REDIS_TEST_URL"]
    async fn reservation_capacity_and_expired_callbacks_are_bounded() {
        let name = format!("test-capacity-{}", std::process::id());
        let a = backend(&name);
        let rules = vec![ban()];
        let ip = "192.0.2.43".parse().unwrap();
        let stale = a
            .observe(&rules, &request("/login"), None, ip)
            .await
            .unwrap();
        let _: i64 = a
            .invoke(
                "redis.call('ZADD',KEYS[1],0,ARGV[1]); return 1",
                a.ban_keys(&rules[0]).to_vec(),
                vec![ip.to_string()],
            )
            .await
            .unwrap();
        assert!(
            a.check_bans(&rules, &request("/login"), None, ip, Scope::Url)
                .await
                .is_ok()
        );
        assert_eq!(stale.record(401).await.unwrap_err().status, 503);
        let _:i64=a.invoke("local t=redis.call('TIME'); for i=1,1024 do redis.call('ZADD',KEYS[1],tonumber(t[1])*1000+60000,'client-'..i) end;return 1",a.ban_keys(&rules[0]).to_vec(),vec![]).await.unwrap();
        assert_eq!(
            a.observe(&rules, &request("/login"), None, ip)
                .await
                .err()
                .unwrap()
                .status,
            503
        );
        assert!(
            a.observe(&rules, &request("/images/x"), None, ip)
                .await
                .unwrap()
                .record(200)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    #[ignore = "requires isolated HANGANG_SECURITY_REDIS_TEST_URL"]
    async fn shared_bans_scope_admin_release_and_late_response_fencing() {
        let name = format!("test-ban-{}", std::process::id());
        let a = backend(&name);
        let b = backend(&name);
        let rules = vec![ban()];
        let ip = "192.0.2.42".parse().unwrap();
        let stale = a
            .observe(&rules, &request("/login"), None, ip)
            .await
            .unwrap();
        a.observe(&rules, &request("/login"), None, ip)
            .await
            .unwrap()
            .record(401)
            .await
            .unwrap();
        let events = b
            .observe(&rules, &request("/login"), None, ip)
            .await
            .unwrap()
            .record(403)
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert!(
            b.check_bans(&rules, &request("/image"), None, ip, Scope::Url)
                .await
                .is_ok()
        );
        assert_eq!(
            b.check_bans(&rules, &request("/image"), None, ip, Scope::Host)
                .await
                .unwrap_err()
                .status,
            429
        );
        let different = Request::builder()
            .uri("/image")
            .header("host", "other.test")
            .body(())
            .unwrap();
        assert!(
            b.check_bans(&rules, &different, None, ip, Scope::Host)
                .await
                .is_ok()
        );
        assert_eq!(
            b.check_bans(&rules, &different, None, ip, Scope::Global)
                .await
                .unwrap_err()
                .status,
            429
        );
        let (listed, truncated) = b.list(&rules, Some(ip), 200).await.unwrap();
        assert!(!truncated);
        assert_eq!(listed.len(), 1);
        assert_eq!(b.clear_ip(&rules, ip).await.unwrap(), 1);
        a.observe(&rules, &request("/login"), None, ip)
            .await
            .unwrap()
            .record(401)
            .await
            .unwrap();
        assert!(stale.record(401).await.unwrap().is_empty());
        assert!(
            b.check_bans(&rules, &request("/login"), None, ip, Scope::Url)
                .await
                .is_ok()
        );
        b.observe(&rules, &request("/login"), None, ip)
            .await
            .unwrap()
            .record(401)
            .await
            .unwrap();
        assert_eq!(
            a.check_bans(&rules, &request("/login"), None, ip, Scope::Url)
                .await
                .unwrap_err()
                .status,
            429
        );
    }
}
