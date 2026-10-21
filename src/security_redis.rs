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
    /// Shared rules keep their established single key. A per-client rule
    /// keeps every client's state in one hash (field = canonical client IP)
    /// plus a sorted set of last-use times, so the script can hold the rule
    /// to `max_clients` clients. Every key carries the namespace hash tag.
    fn rate_keys(&self, rule: &RateRule) -> Vec<String> {
        let key = format!("{}:rate:{}", self.prefix, digest(rule));
        if rule.per_client {
            vec![format!("{key}:clients"), format!("{key}:order")]
        } else {
            vec![key]
        }
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
        client: IpAddr,
    ) -> Result<(), Error> {
        let mut keys = vec![];
        let mut args = vec![client.to_canonical().to_string()];
        for rule in rules {
            if selected(
                &rule.path,
                &rule.hosts,
                rule.include_subpaths,
                request,
                host,
            )? {
                keys.extend(self.rate_keys(rule));
                args.push(serde_json::to_string(rule).map_err(unavailable)?);
                let capacity = if rule.per_client {
                    rule.client_capacity()
                } else {
                    0
                };
                args.push(capacity.to_string());
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
// ARGV[1] is the canonical client IP, then a rule and its client capacity per
// selected rule (0 = one budget shared by every client, one key). A per-client
// rule uses two keys: a hash of client states and a sorted set of last-use
// times. Before a new client is stored, clients idle longer than the state
// lifetime are dropped, then the least recently used beyond the capacity, so
// the hash never holds more than `max_clients` clients even with many gateways.
// Last-use scores are microseconds raised to one above the newest score, so
// they strictly increase per rule: requests in the same instant, or after the
// Redis clock steps back, keep their order and a client used (or rejected) a
// moment ago is never dropped before older clients.
const RATE: &str = r#"
local t=redis.call('TIME'); local now=tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000)
local now_us=tonumber(t[1])*1000000+tonumber(t[2])
local client=ARGV[1]
local pending={}
local k=1
local function touch(order,flag)
 local stamp=now_us; local top=redis.call('ZRANGE',order,-1,-1,'WITHSCORES')
 if top[2] and tonumber(top[2])>=stamp then stamp=tonumber(top[2])+1 end
 if flag then redis.call('ZADD',order,flag,string.format('%.0f',stamp),client)
 else redis.call('ZADD',order,string.format('%.0f',stamp),client) end
end
-- A rejected client still counts as recently used, as in local mode; XX never
-- adds one, and its stored state is left exactly as it was.
local function reject(order)
 for _,p in ipairs(pending) do if p.order then touch(p.order,'XX') end end
 if order then touch(order,'XX') end
 return 0
end
for i=2,#ARGV,2 do
 local rule=cjson.decode(ARGV[i]); local cap=tonumber(ARGV[i+1])
 local key=KEYS[k]; local order=false; local old; k=k+1
 if cap>0 then order=KEYS[k]; k=k+1; old=redis.call('HGET',key,client) else old=redis.call('GET',key) end
 local state=old and cjson.decode(old) or {updated=now,credit=rule.burst,windows={}}
 local maxage=1000
 if rule.tps then
  state.credit=math.min(rule.burst,state.credit+math.max(0,now-state.updated)*rule.tps/1000)
  if state.credit<1 then return reject(order) end
  state.credit=state.credit-1; maxage=math.max(maxage,math.ceil(rule.burst/rule.tps*1000))
 end
 state.updated=math.max(now,state.updated)
 for j,w in ipairs(rule.limits or {}) do
  local bucket=math.floor(now/(w.window_seconds*1000)); local previous=state.windows[j]
  local count=(previous and previous.bucket==bucket) and previous.count or 0
  if count>=w.requests then return reject(order) end
  state.windows[j]={bucket=bucket,count=count+1}; maxage=math.max(maxage,w.window_seconds*1000)
 end
 pending[#pending+1]={key=key,order=order,cap=cap,state=state,ttl=maxage+1000}
end
for _,p in ipairs(pending) do
 if p.order then
  if not redis.call('ZSCORE',p.order,client) then
   if redis.call('ZCARD',p.order)==0 then redis.call('DEL',p.key) end
   local drop=redis.call('ZRANGEBYSCORE',p.order,'-inf',string.format('%.0f',now_us-p.ttl*1000),'LIMIT',0,64)
   local excess=redis.call('ZCARD',p.order)-#drop-p.cap+1
   if excess>0 then
    for _,member in ipairs(redis.call('ZRANGE',p.order,#drop,#drop+math.min(excess,1024)-1)) do drop[#drop+1]=member end
   end
   for _,member in ipairs(drop) do redis.call('HDEL',p.key,member); redis.call('ZREM',p.order,member) end
  end
  redis.call('HSET',p.key,client,cjson.encode(p.state)); touch(p.order,false)
  redis.call('PEXPIRE',p.key,p.ttl); redis.call('PEXPIRE',p.order,p.ttl)
 else
  redis.call('SET',p.key,cjson.encode(p.state),'PX',p.ttl)
 end
end
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
    const CLIENT: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 50));
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
            per_client: false,
            max_clients: None,
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
    #[tokio::test]
    async fn per_client_rate_keys_are_a_bounded_hash_and_order_and_keep_shared_keys() {
        let backend = Backend::from_url(
            Settings {
                allow_insecure_remote: true,
                ..settings("key-test")
            },
            "redis://127.0.0.1:1/",
        )
        .unwrap();
        let shared = rate("/login", 2);
        let mut per_client = shared.clone();
        per_client.per_client = true;
        let shared_keys = backend.rate_keys(&shared);
        assert_eq!(shared_keys.len(), 1);
        assert!(!shared_keys[0].contains("client"));
        let keys = backend.rate_keys(&per_client);
        assert_eq!(keys.len(), 2);
        assert!(keys[0].ends_with(":clients") && keys[1].ends_with(":order"));
        assert!(keys.iter().all(|key| key.starts_with(&backend.prefix)));
        // A different capacity is a different rule with its own keys.
        let mut other = per_client.clone();
        other.max_clients = Some(3);
        assert_ne!(backend.rate_keys(&other), keys);
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
    async fn stopped_backend_fails_every_shared_check_closed_without_local_fallback() {
        // HG-44: a Redis that refuses connections (stopped process) must turn
        // every selected shared check into 503, never into a silent pass, while
        // URLs no rule selects keep working without contacting Redis.
        let address = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap()
        };
        let a =
            Backend::from_url(settings("stopped-test"), &format!("redis://{address}/")).unwrap();
        let rates = vec![rate("/login", 1)];
        let bans = vec![ban()];
        let ip: IpAddr = "192.0.2.46".parse().unwrap();
        let other = || {
            Request::builder()
                .uri("/images/x")
                .header("host", "other.test")
                .body(())
                .unwrap()
        };
        let started = std::time::Instant::now();
        assert!(
            a.check_rates(&[], &request("/login"), None, CLIENT)
                .await
                .is_ok()
        );
        assert!(
            a.check_rates(&rates, &request("/images/x"), None, CLIENT)
                .await
                .is_ok()
        );
        assert_eq!(
            a.check_rates(&rates, &request("/login"), None, CLIENT)
                .await
                .unwrap_err()
                .status,
            503
        );
        assert!(
            a.check_bans(&bans, &request("/images/x"), None, ip, Scope::Url)
                .await
                .is_ok()
        );
        assert!(
            a.check_bans(&bans, &other(), None, ip, Scope::Host)
                .await
                .is_ok()
        );
        for (request, scope) in [
            (request("/login"), Scope::Url),
            (request("/images/x"), Scope::Host),
            (other(), Scope::Global),
        ] {
            assert_eq!(
                a.check_bans(&bans, &request, None, ip, scope)
                    .await
                    .unwrap_err()
                    .status,
                503,
                "{scope:?}"
            );
        }
        assert!(
            a.observe(&bans, &request("/images/x"), None, ip)
                .await
                .is_ok()
        );
        assert_eq!(
            a.observe(&bans, &request("/login"), None, ip)
                .await
                .err()
                .unwrap()
                .status,
            503
        );
        assert_eq!(a.list(&bans, None, 10).await.unwrap_err().status, 503);
        assert_eq!(a.clear_ip(&bans, ip).await.unwrap_err().status, 503);
        assert!(started.elapsed() < Duration::from_secs(5));
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
            a.check_rates(&rules, &request("/images/x"), None, CLIENT)
                .await
                .is_ok()
        );
        let started = std::time::Instant::now();
        assert_eq!(
            a.check_rates(&rules, &request("/login"), None, CLIENT)
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
                backend
                    .check_rates(&rules, &request("/login"), None, CLIENT)
                    .await
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
            a.check_rates(&rules, &request("/images/a.png"), None, CLIENT)
                .await
                .is_ok()
        );
        let name = format!("test-atomic-{}", std::process::id());
        let a = backend(&name);
        let rules = vec![rate("/login", 3), rate("/login", 1)];
        assert!(
            a.check_rates(&rules, &request("/login"), None, CLIENT)
                .await
                .is_ok()
        );
        assert_eq!(
            a.check_rates(&rules, &request("/login"), None, CLIENT)
                .await
                .unwrap_err()
                .status,
            429
        );
        let only = vec![rules[0].clone()];
        assert!(
            a.check_rates(&only, &request("/login"), None, CLIENT)
                .await
                .is_ok()
        );
        assert!(
            a.check_rates(&only, &request("/login"), None, CLIENT)
                .await
                .is_ok()
        );
        assert_eq!(
            a.check_rates(&only, &request("/login"), None, CLIENT)
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
            a.check_rates(
                std::slice::from_ref(&rule),
                &request("/login"),
                None,
                CLIENT
            )
            .await
            .is_ok()
        );
        assert_eq!(
            a.check_rates(
                std::slice::from_ref(&rule),
                &request("/login"),
                None,
                CLIENT
            )
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
                a.check_rates(
                    std::slice::from_ref(&rule),
                    &request("/login"),
                    None,
                    CLIENT
                )
                .await
                .is_ok()
            );
        }
        assert_eq!(
            a.check_rates(
                std::slice::from_ref(&rule),
                &request("/login"),
                None,
                CLIENT
            )
            .await
            .unwrap_err()
            .status,
            429
        );
    }
    #[tokio::test]
    #[ignore = "requires isolated HANGANG_SECURITY_REDIS_TEST_URL"]
    async fn per_client_rules_keep_separate_shared_budgets() {
        let name = format!("test-per-client-{}", std::process::id());
        let a = backend(&name);
        let b = backend(&name);
        let mut rule = rate("/login", 2);
        rule.per_client = true;
        let rules = std::slice::from_ref(&rule);
        let other: IpAddr = "198.51.100.9".parse().unwrap();
        for node in [&a, &b] {
            assert!(
                node.check_rates(rules, &request("/login"), None, CLIENT)
                    .await
                    .is_ok()
            );
        }
        // Both nodes charged the same client budget.
        assert_eq!(
            a.check_rates(rules, &request("/login"), None, CLIENT)
                .await
                .unwrap_err()
                .status,
            429
        );
        assert!(
            b.check_rates(rules, &request("/login"), None, other)
                .await
                .is_ok()
        );
        let mapped: IpAddr = "::ffff:192.0.2.50".parse().unwrap();
        assert_eq!(
            b.check_rates(rules, &request("/login"), None, mapped)
                .await
                .unwrap_err()
                .status,
            429
        );
    }
    fn per_client_daily(max_clients: u32) -> RateRule {
        RateRule {
            limits: vec![Window {
                requests: 1,
                window_seconds: 86400,
            }],
            per_client: true,
            max_clients: Some(max_clients),
            ..rate("/login", 1)
        }
    }
    async fn stored_clients(backend: &Backend, rule: &RateRule) -> (i64, i64) {
        let counts: Vec<i64> = backend
            .invoke(
                "return {redis.call('HLEN',KEYS[1]),redis.call('ZCARD',KEYS[2])}",
                backend.rate_keys(rule),
                vec![],
            )
            .await
            .unwrap();
        (counts[0], counts[1])
    }
    fn client(n: u32) -> IpAddr {
        IpAddr::V6(std::net::Ipv6Addr::from(
            0x2001_0db8_0000_0000_0000_0000_0000_0000_u128 + u128::from(n),
        ))
    }
    #[tokio::test]
    #[ignore = "requires isolated HANGANG_SECURITY_REDIS_TEST_URL"]
    async fn per_client_redis_state_is_bounded_and_evicts_least_recently_used() {
        let name = format!("test-per-client-lru-{}", std::process::id());
        let a = backend(&name);
        let rule = per_client_daily(3);
        let rules = std::slice::from_ref(&rule);
        let login = || request("/login");
        for n in 1..=3 {
            assert!(
                a.check_rates(rules, &login(), None, client(n))
                    .await
                    .is_ok()
            );
        }
        // A rejected client still counts as recently used, so client 2 is now
        // the least recently used and makes room for client 4.
        let rejected = a.check_rates(rules, &login(), None, client(1)).await;
        assert_eq!(rejected.unwrap_err().status, 429);
        assert!(
            a.check_rates(rules, &login(), None, client(4))
                .await
                .is_ok()
        );
        assert_eq!(stored_clients(&a, &rule).await, (3, 3));
        let kept = a.check_rates(rules, &login(), None, client(1)).await;
        assert_eq!(kept.unwrap_err().status, 429, "client 1 kept its state");
        assert!(
            a.check_rates(rules, &login(), None, client(2))
                .await
                .is_ok(),
            "evicted client 2 starts again with a full budget"
        );
        // A flood of fresh addresses never stores more than max_clients.
        for n in 100..400 {
            assert!(
                a.check_rates(rules, &login(), None, client(n))
                    .await
                    .is_ok()
            );
        }
        assert_eq!(stored_clients(&a, &rule).await, (3, 3));
    }
    async fn is_stored(backend: &Backend, rule: &RateRule, ip: IpAddr) -> bool {
        let stored: i64 = backend
            .invoke(
                "return (redis.call('HEXISTS',KEYS[1],ARGV[1])==1 and redis.call('ZSCORE',KEYS[2],ARGV[1])) and 1 or 0",
                backend.rate_keys(rule),
                vec![ip.to_string()],
            )
            .await
            .unwrap();
        stored == 1
    }
    #[tokio::test]
    #[ignore = "requires isolated HANGANG_SECURITY_REDIS_TEST_URL"]
    async fn per_client_redis_same_instant_never_drops_the_client_just_rejected() {
        // Review repro: A, B and C fill a three-client rule, A is rejected,
        // then D arrives — all inside one script, so one Redis clock reading.
        // Equal millisecond scores used to drop A by address order and hand
        // it a fresh daily budget; B is the least recently used and must go.
        let name = format!("test-per-client-same-instant-{}", std::process::id());
        let a = backend(&name);
        let rule = per_client_daily(3);
        let keys = a.rate_keys(&rule);
        a.invoke::<i64>(
            "return redis.call('DEL',KEYS[1],KEYS[2])",
            keys.clone(),
            vec![],
        )
        .await
        .unwrap();
        let script = format!(
            "local function rate(KEYS,ARGV)\n{RATE}\nend\nlocal results={{}}\n\
             for i=3,#ARGV do results[#results+1]=rate(KEYS,{{ARGV[i],ARGV[1],ARGV[2]}}) end\n\
             return results"
        );
        let order = [1, 2, 3, 1, 4, 1];
        let mut args = vec![serde_json::to_string(&rule).unwrap(), "3".into()];
        args.extend(order.iter().map(|n| client(*n).to_string()));
        let results: Vec<i64> = a.invoke(&script, keys, args).await.unwrap();
        assert_eq!(results, [1, 1, 1, 0, 1, 0]);
        assert!(is_stored(&a, &rule, client(1)).await, "rejected A is kept");
        assert!(!is_stored(&a, &rule, client(2)).await, "B was least recent");
        assert_eq!(stored_clients(&a, &rule).await, (3, 3));
        let again = a
            .check_rates(
                std::slice::from_ref(&rule),
                &request("/login"),
                None,
                client(1),
            )
            .await;
        assert_eq!(again.unwrap_err().status, 429, "A keeps its spent budget");
    }
    #[tokio::test]
    #[ignore = "requires isolated HANGANG_SECURITY_REDIS_TEST_URL"]
    async fn per_client_redis_order_survives_a_clock_step_back() {
        // Scores far ahead of the Redis clock stand in for a clock that
        // stepped back; new uses must still rank above them.
        let name = format!("test-per-client-clock-{}", std::process::id());
        let a = backend(&name);
        let rule = per_client_daily(3);
        let rules = std::slice::from_ref(&rule);
        let keys = a.rate_keys(&rule);
        a.invoke::<i64>(
            "return redis.call('DEL',KEYS[1],KEYS[2])",
            keys.clone(),
            vec![],
        )
        .await
        .unwrap();
        for n in 1..=3 {
            assert!(
                a.check_rates(rules, &request("/login"), None, client(n))
                    .await
                    .is_ok()
            );
        }
        let ahead = (1..=3)
            .map(|n| format!("900000000000000{n}"))
            .chain((1..=3).map(|n| client(n).to_string()));
        a.invoke::<i64>(
            "for i=1,3 do redis.call('ZADD',KEYS[2],'XX',ARGV[i],ARGV[i+3]) end return 1",
            keys,
            ahead.collect(),
        )
        .await
        .unwrap();
        let rejected = a
            .check_rates(rules, &request("/login"), None, client(1))
            .await;
        assert_eq!(rejected.unwrap_err().status, 429);
        assert!(
            a.check_rates(rules, &request("/login"), None, client(4))
                .await
                .is_ok()
        );
        assert!(is_stored(&a, &rule, client(1)).await, "rejected A is kept");
        assert!(!is_stored(&a, &rule, client(2)).await, "B was least recent");
    }
    #[tokio::test]
    #[ignore = "requires isolated HANGANG_SECURITY_REDIS_TEST_URL"]
    async fn per_client_redis_rejected_client_stays_rejected_across_gateways() {
        // Two gateways alternate: one keeps rejecting A, the other brings a
        // new address each time. Many of these land in the same millisecond;
        // A is always the most recent but one, so it must never be dropped.
        let name = format!("test-per-client-gateways-{}", std::process::id());
        let gateways = [backend(&name), backend(&name)];
        let rule = per_client_daily(3);
        let rules = std::slice::from_ref(&rule);
        gateways[0]
            .invoke::<i64>(
                "return redis.call('DEL',KEYS[1],KEYS[2])",
                gateways[0].rate_keys(&rule),
                vec![],
            )
            .await
            .unwrap();
        for n in 1..=3 {
            assert!(
                gateways[0]
                    .check_rates(rules, &request("/login"), None, client(n))
                    .await
                    .is_ok()
            );
        }
        for round in 0..400_u32 {
            let (rejecting, adding) = (
                &gateways[(round % 2) as usize],
                &gateways[(1 - round % 2) as usize],
            );
            let rejected = rejecting
                .check_rates(rules, &request("/login"), None, client(1))
                .await;
            assert_eq!(
                rejected.unwrap_err().status,
                429,
                "round {round}: A got a new budget"
            );
            let fresh = adding
                .check_rates(rules, &request("/login"), None, client(10_000 + round))
                .await;
            assert!(fresh.is_ok(), "round {round}: new client has a budget");
        }
        assert!(is_stored(&gateways[1], &rule, client(1)).await);
        assert_eq!(stored_clients(&gateways[1], &rule).await, (3, 3));
    }
    #[tokio::test]
    #[ignore = "requires isolated HANGANG_SECURITY_REDIS_TEST_URL"]
    async fn per_client_redis_bound_holds_across_concurrent_gateways() {
        let name = format!("test-per-client-fleet-{}", std::process::id());
        let a = backend(&name);
        let b = backend(&name);
        let rule = per_client_daily(16);
        let mut tasks = vec![];
        for task in 0..32_u32 {
            let backend = if task % 2 == 0 { a.clone() } else { b.clone() };
            let rules = vec![rule.clone()];
            tasks.push(tokio::spawn(async move {
                let mut admitted = 0;
                for n in 0..16 {
                    let ip = client(1000 + task * 16 + n);
                    if backend
                        .check_rates(&rules, &request("/login"), None, ip)
                        .await
                        .is_ok()
                    {
                        admitted += 1;
                    }
                }
                admitted
            }));
        }
        let mut admitted = 0;
        for task in tasks {
            admitted += task.await.unwrap();
        }
        assert_eq!(admitted, 512, "every new client starts with a budget");
        assert_eq!(stored_clients(&a, &rule).await, (16, 16));
        assert_eq!(stored_clients(&b, &rule).await, (16, 16));
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
