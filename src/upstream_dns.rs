//! Explicit per-upstream DNS; no hosts-file/search-domain/system-resolver fallback.
use anyhow::Context;
use anyhow::{Result, ensure};
use hickory_resolver::{
    Resolver,
    config::{
        ConnectionConfig, LookupIpStrategy, NameServerConfig, ProtocolConfig, ResolveHosts,
        ResolverConfig,
    },
    net::runtime::TokioRuntimeProvider,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

type Key = (Vec<SocketAddr>, String);
struct Entry {
    ips: Vec<IpAddr>,
    expires: Instant,
}
static CACHE: OnceLock<Mutex<HashMap<Key, Entry>>> = OnceLock::new();
static INFLIGHT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(64);

pub async fn resolve(host: &str, servers: &[SocketAddr]) -> Result<Vec<IpAddr>> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    ensure!(
        !servers.is_empty() && servers.len() <= 4 && servers.iter().all(|s| s.port() > 0),
        "invalid upstream DNS servers"
    );
    ensure!(host.len() <= 253, "upstream DNS name too long");
    let name = format!("{}.", host.trim_end_matches('.').to_ascii_lowercase());
    ensure!(
        name != "localhost." && !name.ends_with(".localhost."),
        "localhost is reserved; use an explicit loopback IP with selected DNS"
    );
    let key = (servers.to_vec(), name.clone());
    let cache = CACHE.get_or_init(Default::default);
    if let Some(entry) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&key)
        && entry.expires > Instant::now()
    {
        return Ok(entry.ips.clone());
    }
    let _permit = INFLIGHT
        .try_acquire()
        .map_err(|_| anyhow::anyhow!("upstream DNS capacity exhausted"))?;
    let mut name_servers = Vec::new();
    for server in servers {
        let mut connections = Vec::new();
        for protocol in [ProtocolConfig::Udp, ProtocolConfig::Tcp] {
            let mut connection = ConnectionConfig::new(protocol);
            connection.port = server.port();
            connections.push(connection);
        }
        // trust_negative_responses = true: a NXDOMAIN from an explicitly
        // selected server is authoritative for this stub resolver.
        name_servers.push(NameServerConfig::new(server.ip(), true, connections));
    }
    let mut builder = Resolver::builder_with_config(
        ResolverConfig::from_parts(None, vec![], name_servers),
        TokioRuntimeProvider::default(),
    );
    let opts = builder.options_mut();
    opts.timeout = Duration::from_millis(800);
    opts.attempts = 1;
    opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    opts.use_hosts_file = ResolveHosts::Never;
    opts.cache_size = 0;
    opts.positive_max_ttl = Some(Duration::from_secs(300));
    let resolver = builder.build().context("build upstream DNS resolver")?;
    let lookup = tokio::time::timeout(Duration::from_secs(2), resolver.lookup_ip(name)).await??;
    let ips: Vec<_> = lookup.iter().take(16).collect();
    ensure!(!ips.is_empty(), "upstream DNS returned no addresses");
    let expires = lookup
        .valid_until()
        .min(Instant::now() + Duration::from_secs(300));
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() >= 2048 {
        cache.retain(|_, e| e.expires > Instant::now());
    }
    if cache.len() >= 2048 {
        cache.clear();
    }
    cache.insert(
        key,
        Entry {
            ips: ips.clone(),
            expires,
        },
    );
    Ok(ips)
}
