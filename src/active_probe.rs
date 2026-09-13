//! Per-snapshot, bounded upstream HTTP probes. Snapshot replacement cancels
//! old probes; each task retains only a weak runtime reference between ticks.
use crate::{
    config::{HttpRuntime, Snapshot},
    discovery::{Discovery, Protocol, ResolvedTarget},
    http_outbound::Pools,
    pool_member::{Backend, DesiredState},
    proxy::{Body, BodyError},
};
use anyhow::{Context, Result, ensure};
use arc_swap::{ArcSwap, ArcSwapOption};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Uri};
use std::{
    sync::{Arc, Weak},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub fn spawn_monitor(
    active: Arc<ArcSwap<Snapshot>>,
    pools: Arc<Pools>,
    shutdown: CancellationToken,
) {
    spawn_monitor_with_discovery(active, pools, Arc::new(ArcSwapOption::empty()), shutdown);
}

pub fn spawn_monitor_with_discovery(
    active: Arc<ArcSwap<Snapshot>>,
    pools: Arc<Pools>,
    discovery: Arc<ArcSwapOption<Discovery>>,
    shutdown: CancellationToken,
) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(run_monitor(active, pools, discovery, shutdown));
    }
}

async fn run_monitor(
    active: Arc<ArcSwap<Snapshot>>,
    pools: Arc<Pools>,
    discovery: Arc<ArcSwapOption<Discovery>>,
    shutdown: CancellationToken,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut current = Weak::<Snapshot>::new();
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            _ = interval.tick() => {}
        }
        let snapshot = active.load_full();
        if current
            .upgrade()
            .is_some_and(|previous| Arc::ptr_eq(&previous, &snapshot))
        {
            continue;
        }
        // Cancellation alone does not establish that old tasks have stopped
        // touching a shared balancer. Reap every old task before starting the
        // next generation, preserving the configured probe-task bound.
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        if shutdown.is_cancelled() {
            break;
        }
        // Joining yields: select the latest published generation again so
        // a concurrent replacement is not delayed by a retired candidate.
        let snapshot = active.load_full();
        current = Arc::downgrade(&snapshot);
        for runtime in &snapshot.http {
            if !runtime.route.enabled || runtime.route.balance.active_health.is_none() {
                continue;
            }
            let prepared = snapshot.upstream_tls.get(&runtime.route.id).cloned();
            for (index, backend) in runtime.route.backends.iter().enumerate() {
                if matches!(backend, Backend::Member(member) if member.desired_state == DesiredState::Maintenance)
                {
                    continue;
                }
                tasks.spawn(run_backend(
                    Arc::downgrade(runtime),
                    index,
                    backend.address().to_owned(),
                    prepared.clone(),
                    pools.clone(),
                    discovery.clone(),
                    shutdown.clone(),
                ));
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

async fn run_backend(
    runtime: Weak<HttpRuntime>,
    index: usize,
    backend: String,
    prepared: Option<Arc<rustls::ClientConfig>>,
    pools: Arc<Pools>,
    discovery: Arc<ArcSwapOption<Discovery>>,
    cancel: CancellationToken,
) {
    let Some(initial) = runtime.upgrade() else {
        return;
    };
    let Some(policy) = initial.route.balance.active_health.as_ref() else {
        return;
    };
    let interval_ms = policy.interval_ms;
    drop(initial);
    let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {}
        }
        let Some(current) = runtime.upgrade() else {
            break;
        };
        let policy = current
            .route
            .balance
            .active_health
            .as_ref()
            .expect("route policy is immutable");
        let resolved = discovery.load_full();
        let Some(target) = resolve_probe_target(&backend, resolved.as_deref()) else {
            // Missing Docker references have no endpoint to qualify. The
            // proxy independently excludes them from selection until a new
            // discovery epoch appears.
            continue;
        };
        if !current.balancer.observe_epoch(index, target.epoch) {
            continue;
        }
        let probe = probe_once(
            &current,
            &backend,
            &target,
            resolved,
            prepared.as_ref(),
            &pools,
        );
        let outcome = tokio::select! {
            _ = cancel.cancelled() => break,
            result = tokio::time::timeout(Duration::from_millis(policy.timeout_ms), probe) => result,
        };
        // A removed container or a replacement at the same IP:port cannot
        // borrow the earlier probe's healthy result. Discovery epochs include
        // restart and removal/reappearance transitions.
        let latest = discovery.load_full();
        if resolve_probe_target(&backend, latest.as_deref()).as_ref() != Some(&target) {
            continue;
        }
        match outcome {
            Ok(Ok(status)) => {
                current
                    .balancer
                    .record_active_status_for(index, target.epoch, status)
            }
            Ok(Err(error)) => {
                tracing::debug!(route = %current.route.id, backend = %backend, error = %error, "active upstream probe failed");
                current
                    .balancer
                    .record_active_transport_failure_for(index, target.epoch);
            }
            Err(_) => current
                .balancer
                .record_active_timeout_for(index, target.epoch),
        }
        drop(current);
    }
}

async fn probe_once(
    runtime: &Arc<HttpRuntime>,
    configured: &str,
    target: &ResolvedTarget,
    discovery: Option<Arc<Discovery>>,
    prepared: Option<&Arc<rustls::ClientConfig>>,
    pools: &Pools,
) -> Result<u16> {
    let policy = runtime
        .route
        .balance
        .active_health
        .as_ref()
        .expect("probe route");
    let upstream: Uri = target
        .endpoint
        .parse()
        .context("parse active probe backend")?;
    ensure!(
        matches!(upstream.scheme_str(), Some("http" | "https")),
        "active probe backend must be HTTP or HTTPS"
    );
    let authority = upstream
        .authority()
        .context("active probe backend has no authority")?;
    let host = policy.host.as_deref().unwrap_or(authority.host());
    let uri = Uri::builder()
        .scheme(
            upstream
                .scheme()
                .context("active probe backend has no scheme")?
                .clone(),
        )
        // The connector dials the fixed backend. The URI authority carries
        // the probe Host for HTTP/1 and :authority for HTTP/2, so neither
        // protocol gets a duplicate regular Host field.
        .authority(host)
        .path_and_query(policy.path.as_str())
        .build()
        .context("build active probe URI")?;
    let body: Body = Full::new(Bytes::new())
        .map_err(BodyError::from_error)
        .boxed_unsync();
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .body(body)
        .context("build active probe request")?;
    let client = pools.client_for_epoch(runtime, configured, target, discovery, prepared)?;
    let response = client
        .request(request)
        .await
        .context("active probe HTTP request")?;
    Ok(response.status().as_u16())
}

fn resolve_probe_target(backend: &str, discovery: Option<&Discovery>) -> Option<ResolvedTarget> {
    if backend.starts_with("docker://") {
        discovery?.resolve_with_epoch(backend, Protocol::Http)
    } else {
        Some(ResolvedTarget {
            endpoint: backend.to_owned(),
            epoch: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::{
        net::SocketAddr,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    async fn counting_origin() -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let server = tokio::spawn({
            let hits = hits.clone();
            async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    hits.fetch_add(1, Ordering::Relaxed);
                    let mut request = [0; 256];
                    let _ = stream.read(&mut request).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                }
            }
        });
        (address, hits, server)
    }

    async fn wait_for_hits(hits: &AtomicUsize, threshold: usize) {
        tokio::time::timeout(Duration::from_secs(4), async {
            while hits.load(Ordering::Relaxed) < threshold {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("active probe did not reach endpoint");
    }

    #[tokio::test]
    async fn maintenance_skips_real_probes_while_draining_continues_and_serving_resumes() {
        let (draining_address, draining_hits, draining_server) = counting_origin().await;
        let (maintenance_address, maintenance_hits, maintenance_server) = counting_origin().await;
        let config: Config = serde_json::from_value(serde_json::json!({"http":[{
            "id":"member-probe-states",
            "backends":[
                {"id":"drain","address":format!("http://{draining_address}")},
                {"id":"maint","address":format!("http://{maintenance_address}")}
            ],
            "balance":{"active_health":{
                "path":"/ready","interval_ms":100,"timeout_ms":100,
                "healthy_statuses":[200],"unhealthy_statuses":[503],
                "healthy_successes":1,"unhealthy_http_failures":1,
                "unhealthy_tcp_failures":1,"unhealthy_timeouts":1
            }}
        }]}))
        .unwrap();
        let mut initial = Snapshot::new(config.clone()).unwrap();
        // Serving named members are valid in this isolated base. Model the
        // prepared non-serving generation directly until Config publication
        // accepts these states in the integration branch.
        for (index, state) in [DesiredState::Draining, DesiredState::Maintenance]
            .into_iter()
            .enumerate()
        {
            let runtime = Arc::get_mut(&mut initial.http[0]).unwrap();
            let Backend::Member(member) = &mut runtime.route.backends[index] else {
                panic!("named fixture member expected");
            };
            member.desired_state = state;
        }
        let active = Arc::new(ArcSwap::from(Arc::new(initial)));
        let pools = Arc::new(Pools::new(crate::tls::client_config(None).unwrap(), 1));
        let shutdown = CancellationToken::new();
        spawn_monitor(active.clone(), pools, shutdown.clone());
        wait_for_hits(&draining_hits, 3).await;
        assert_eq!(maintenance_hits.load(Ordering::Acquire), 0);

        // A fresh serving snapshot starts the previously skipped probe.
        active.store(Arc::new(Snapshot::new(config).unwrap()));
        wait_for_hits(&maintenance_hits, 2).await;
        shutdown.cancel();
        draining_server.abort();
        maintenance_server.abort();
    }

    #[tokio::test]
    async fn snapshot_replacement_stops_old_probes_and_shutdown_stops_new_probes() {
        let (old_address, old_hits, old_server) = counting_origin().await;
        let (new_address, new_hits, new_server) = counting_origin().await;
        let make_snapshot = |address| {
            let value = serde_json::json!({"http":[{
                "id":"swappable-probe", "backends":[format!("http://{address}")],
                "balance":{"active_health":{
                    "path":"/ready","interval_ms":100,"timeout_ms":100,
                    "healthy_statuses":[200],"unhealthy_statuses":[503],
                    "healthy_successes":1,"unhealthy_http_failures":2,
                    "unhealthy_tcp_failures":2,"unhealthy_timeouts":2
                }}
            }]});
            Arc::new(Snapshot::new(serde_json::from_value::<Config>(value).unwrap()).unwrap())
        };
        let active = Arc::new(ArcSwap::from(make_snapshot(old_address)));
        let pools = Arc::new(Pools::new(crate::tls::client_config(None).unwrap(), 1));
        let shutdown = CancellationToken::new();
        spawn_monitor(active.clone(), pools, shutdown.clone());
        wait_for_hits(&old_hits, 2).await;
        let old = active.swap(make_snapshot(new_address));
        let old_weak = Arc::downgrade(&old);
        drop(old);
        wait_for_hits(&new_hits, 2).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let old_stopped = old_hits.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(old_hits.load(Ordering::Relaxed), old_stopped);
        assert!(
            old_weak.upgrade().is_none(),
            "old snapshot must be released"
        );
        shutdown.cancel();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let new_stopped = new_hits.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(new_hits.load(Ordering::Relaxed), new_stopped);
        old_server.abort();
        new_server.abort();
    }

    #[tokio::test]
    async fn shutdown_reaps_a_stalled_probe_before_monitor_returns() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let source = serde_json::json!({"http":[{
            "id":"stalled", "backends":[format!("http://{address}")],
            "balance":{"active_health":{
                "path":"/ready", "interval_ms":60000, "timeout_ms":60000,
                "healthy_statuses":[200], "unhealthy_statuses":[503],
                "healthy_successes":1, "unhealthy_http_failures":1,
                "unhealthy_tcp_failures":1, "unhealthy_timeouts":1,
                "initial_state":"checking"
            }}
        }]});
        let snapshot = Arc::new(Snapshot::new(serde_json::from_value(source).unwrap()).unwrap());
        let runtime = Arc::downgrade(&snapshot.http[0]);
        let active = Arc::new(ArcSwap::from(snapshot));
        let pools = Arc::new(Pools::new(crate::tls::client_config(None).unwrap(), 1));
        let shutdown = CancellationToken::new();
        let monitor = tokio::spawn(run_monitor(
            active,
            pools,
            Arc::new(ArcSwapOption::empty()),
            shutdown.clone(),
        ));
        let (mut connection, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut request = [0; 4096];
        let bytes = tokio::time::timeout(Duration::from_secs(3), connection.read(&mut request))
            .await
            .unwrap()
            .unwrap();
        assert!(bytes > 0);
        assert!(
            runtime.upgrade().is_some(),
            "the blocked probe retains its runtime"
        );
        // Keep the origin socket alive without responding. Cancellation must
        // not wait for the 60-second request timeout, and returning from the
        // monitor guarantees the old task has released its runtime.
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), monitor)
            .await
            .unwrap()
            .unwrap();
        assert!(
            runtime.upgrade().is_none(),
            "no probe task remains after shutdown"
        );
        drop(connection);
    }

    #[tokio::test]
    async fn monitor_probe_marks_unhealthy_then_recovers_on_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let status = Arc::new(std::sync::atomic::AtomicU16::new(503));
        let seen_host = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server = tokio::spawn({
            let status = status.clone();
            let seen_host = seen_host.clone();
            let requests = requests.clone();
            async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        break;
                    };
                    requests.fetch_add(1, Ordering::Relaxed);
                    let mut bytes = Vec::with_capacity(1024);
                    while bytes.len() < 4096 && !bytes.ends_with(b"\r\n\r\n") {
                        let mut chunk = [0u8; 512];
                        let Ok(size) = stream.read(&mut chunk).await else {
                            break;
                        };
                        if size == 0 {
                            break;
                        }
                        bytes.extend_from_slice(&chunk[..size]);
                    }
                    if bytes
                        .windows(b"Host: probe.local".len())
                        .any(|part| part.eq_ignore_ascii_case(b"Host: probe.local"))
                    {
                        seen_host.store(true, Ordering::Release);
                    }
                    let answer = format!(
                        "HTTP/1.1 {} PROBE\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        status.load(Ordering::Acquire)
                    );
                    let _ = stream.write_all(answer.as_bytes()).await;
                }
            }
        });
        let source = serde_json::json!({"http":[{
            "id":"probe-route","host":"probe.local",
            "backends":[format!("http://{address}")],
            "balance":{"active_health":{
                "path":"/health/readiness","host":"probe.local","interval_ms":100,"timeout_ms":100,
                "healthy_statuses":[200],"unhealthy_statuses":[503],
                "healthy_successes":1,"unhealthy_http_failures":2,"unhealthy_tcp_failures":2,"unhealthy_timeouts":2
            }}
        }]});
        let snapshot =
            Arc::new(Snapshot::new(serde_json::from_value::<Config>(source).unwrap()).unwrap());
        let runtime = snapshot.http[0].clone();
        let active = Arc::new(ArcSwap::from(snapshot));
        let pools = Arc::new(Pools::new(crate::tls::client_config(None).unwrap(), 1));
        let shutdown = CancellationToken::new();
        spawn_monitor(active.clone(), pools, shutdown.clone());
        tokio::time::timeout(Duration::from_secs(4), async {
            while runtime.balancer.available(0) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert!(seen_host.load(Ordering::Acquire));
        status.store(200, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(4), async {
            while !runtime.balancer.available(0) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        shutdown.cancel();
        // Allow an already-dispatched request to arrive, then assert the
        // monitor does not schedule another interval after shutdown.
        tokio::time::sleep(Duration::from_millis(30)).await;
        let stopped = requests.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(requests.load(Ordering::Relaxed), stopped);
        server.abort();
    }
}
