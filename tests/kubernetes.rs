use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use hangang::kubernetes::{ConfigSink, Controller, ControllerOptions, ControllerSnapshot};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

struct ChannelSink(mpsc::UnboundedSender<ControllerSnapshot>);
#[async_trait]
impl ConfigSink for ChannelSink {
    async fn apply(&self, snapshot: ControllerSnapshot) -> Result<()> {
        self.0
            .send(snapshot)
            .map_err(|_| anyhow::anyhow!("test stopped"))
    }
}

/// Records snapshots and every authority report.
struct ReportingSink {
    snapshots: mpsc::UnboundedSender<ControllerSnapshot>,
    authority: mpsc::UnboundedSender<(bool, String)>,
}
#[async_trait]
impl ConfigSink for ReportingSink {
    async fn apply(&self, snapshot: ControllerSnapshot) -> Result<()> {
        self.snapshots
            .send(snapshot)
            .map_err(|_| anyhow::anyhow!("test stopped"))
    }
    async fn report_authority(&self, healthy: bool, reason: &str) {
        let _ = self.authority.send((healthy, reason.to_owned()));
    }
}

struct RejectingSink;
#[async_trait]
impl ConfigSink for RejectingSink {
    async fn apply(&self, _snapshot: ControllerSnapshot) -> Result<()> {
        anyhow::bail!("re deliberately rejected")
    }
}

/// Accepts the first snapshot, then blocks every later one until released so
/// the watch channel fills up behind a slow reconciliation.
struct BlockingSink {
    applies: AtomicUsize,
    release: CancellationToken,
}
#[async_trait]
impl ConfigSink for BlockingSink {
    async fn apply(&self, _snapshot: ControllerSnapshot) -> Result<()> {
        if self.applies.fetch_add(1, Ordering::SeqCst) > 0 {
            self.release.cancelled().await;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Delete,
    Relist,
    StallStatus,
    CrossNamespace,
    LargeSecrets,
    Capacity,
    CapacityStuck,
    FullChannel,
    Conflict,
    /// Two replicas, told apart by bearer token, observe different histories
    /// of the same final object set.
    Histories,
    /// Watches fail until `resume` is set.
    Stale,
    /// One shared Ingress status document with a real resourceVersion
    /// precondition, written by two replicas.
    Merge,
    /// An older and a younger claimant of one host; the younger one already
    /// carries the address.
    Withdrawn,
    /// Every Ingress watch expires immediately.
    Storm,
    /// Status patches stall until `resume` is set while the first Ingress
    /// watch streams create/delete pairs with unique names.
    Churn,
    /// The listed Ingress conflicts on patch; the re-read returns an object
    /// recreated under the same name with another uid and class.
    Recreated,
    /// The first Ingress watch expires; the relist's Service list stalls.
    SlowRelist,
    /// The initial Ingress list answers late while the Service list was
    /// quick; watches fail until `resume` is set.
    SlowIngressList,
    /// Watches are accepted late and then deliver an unparseable body.
    LateWatch,
}
struct ApiState {
    mode: Mode,
    ingress_watches: AtomicUsize,
    service_watches: AtomicUsize,
    secret_watches: AtomicUsize,
    service_lists: AtomicUsize,
    ingress_lists: AtomicUsize,
    patches: AtomicUsize,
    gets: AtomicUsize,
    resume: AtomicBool,
    authorization: Mutex<Vec<String>>,
    secret_queries: Mutex<Vec<String>>,
    /// (status path, patch body) of every status patch.
    patch_log: Mutex<Vec<(String, serde_json::Value)>>,
    /// Shared Ingress status: resourceVersion and address list.
    status: Mutex<(u64, Vec<serde_json::Value>)>,
    oversized: OnceLock<Bytes>,
    /// (namespace, name, certificate PEM, key PEM) served as TLS Secrets.
    material: Mutex<Vec<(String, String, String, String)>>,
}
impl ApiState {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            ingress_watches: AtomicUsize::new(0),
            service_watches: AtomicUsize::new(0),
            secret_watches: AtomicUsize::new(0),
            service_lists: AtomicUsize::new(0),
            ingress_lists: AtomicUsize::new(0),
            patches: AtomicUsize::new(0),
            gets: AtomicUsize::new(0),
            resume: AtomicBool::new(false),
            authorization: Mutex::new(Vec::new()),
            secret_queries: Mutex::new(Vec::new()),
            patch_log: Mutex::new(Vec::new()),
            status: Mutex::new((11, Vec::new())),
            oversized: OnceLock::new(),
            material: Mutex::new(Vec::new()),
        }
    }
}

struct Harness {
    state: Arc<ApiState>,
    options: ControllerOptions,
    server_cancel: CancellationToken,
    server: tokio::task::JoinHandle<Result<()>>,
    directory: tempfile::TempDir,
}
async fn harness(mode: Mode, namespace: Option<&str>) -> Result<Harness> {
    let directory = tempfile::tempdir()?;
    let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let ca_path = directory.path().join("ca.crt");
    let token_path = directory.path().join("token");
    std::fs::write(&ca_path, pair.cert.pem())?;
    std::fs::write(&token_path, "token\n")?;
    let state = Arc::new(ApiState::new(mode));
    let server_cancel = CancellationToken::new();
    let (address, server) = serve_tls(pair, state.clone(), server_cancel.clone()).await?;
    let options = ControllerOptions {
        api_server: format!("https://localhost:{}/", address.port()).parse()?,
        ca_path,
        token_path,
        namespace: namespace.map(str::to_owned),
        ingress_class: "hangang".into(),
        watch_secrets: false,
        publish_address: None,
        list_page_size: 10,
        max_objects: 20,
        watch_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(3),
        stale_after: Duration::from_secs(60),
    };
    Ok(Harness {
        state,
        options,
        server_cancel,
        server,
        directory,
    })
}
impl Harness {
    /// Options for a second replica that authenticates with `token`.
    fn replica(&self, token: &str) -> Result<ControllerOptions> {
        let token_path = self.directory.path().join(token);
        std::fs::write(&token_path, format!("{token}\n"))?;
        let mut options = self.options.clone();
        options.token_path = token_path;
        Ok(options)
    }
    async fn stop(self) -> Result<()> {
        self.server_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), self.server).await???;
        Ok(())
    }
}
fn spawn(controller: Controller) -> (CancellationToken, tokio::task::JoinHandle<()>) {
    let cancel = CancellationToken::new();
    let task = tokio::spawn({
        let cancel = cancel.clone();
        async move { controller.run(cancel).await }
    });
    (cancel, task)
}
async fn next_snapshot(
    rx: &mut mpsc::UnboundedReceiver<ControllerSnapshot>,
    timeout: Duration,
) -> Result<ControllerSnapshot> {
    tokio::time::timeout(timeout, rx.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("controller stopped"))
}
/// Drain authority reports until one with the expected value arrives.
async fn await_authority(
    rx: &mut mpsc::UnboundedReceiver<(bool, String)>,
    expected: bool,
    timeout: Duration,
) -> Result<String> {
    tokio::time::timeout(timeout, async {
        loop {
            let (healthy, reason) = rx.recv().await.ok_or_else(|| anyhow::anyhow!("stopped"))?;
            if healthy == expected {
                return Ok::<_, anyhow::Error>(reason);
            }
        }
    })
    .await?
}

#[tokio::test]
async fn tls_api_paginates_rotates_token_and_applies_watch_deletion() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let ca_path = directory.path().join("ca.crt");
    let token_path = directory.path().join("token");
    let ca_pem = pair.cert.pem();
    std::fs::write(&ca_path, &ca_pem)?;
    std::fs::write(&token_path, "token-a\n")?;

    let state = Arc::new(ApiState::new(Mode::Delete));
    let cancel_server = CancellationToken::new();
    let (address, server) = serve_tls(pair, state.clone(), cancel_server.clone()).await?;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let options = ControllerOptions {
        api_server: format!("https://localhost:{}/", address.port()).parse()?,
        ca_path: ca_path.clone(),
        token_path: token_path.clone(),
        namespace: Some("blue".into()),
        ingress_class: "hangang".into(),
        watch_secrets: true,
        publish_address: None,
        list_page_size: 1,
        max_objects: 20,
        watch_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(3),
        stale_after: Duration::from_secs(60),
    };
    let controller = Controller::new(options, Arc::new(ChannelSink(tx)))?;
    let cancel = CancellationToken::new();
    let task = tokio::spawn({
        let cancel = cancel.clone();
        async move { controller.run(cancel).await }
    });

    let first = tokio::time::timeout(Duration::from_secs(4), rx.recv())
        .await?
        .unwrap();
    assert_eq!(first.config.http.len(), 1);
    assert_eq!(first.config.http[0].backends, ["http://api.blue.svc:8080"]);
    assert_eq!(first.certificates.len(), 1);
    assert_eq!(first.certificates[0].hosts, ["api.example.test"]);

    // The first watch is deliberately rejected. The retry must reread the
    // projected token file, then process the deletion as a whole snapshot.
    std::fs::write(&token_path, "token-b\n")?;
    let wrong_ca = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    std::fs::write(&ca_path, wrong_ca.cert.pem())?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        rx.try_recv().is_err(),
        "an event arrived through the wrong API CA"
    );
    std::fs::write(&ca_path, ca_pem)?;
    let deleted = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let value = rx.recv().await.unwrap();
            if value.config.http.is_empty() {
                break value;
            }
        }
    })
    .await?;
    assert!(deleted.certificates.is_empty());
    assert!(
        state
            .authorization
            .lock()
            .unwrap()
            .iter()
            .any(|value| value == "Bearer token-b")
    );

    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    cancel_server.cancel();
    tokio::time::timeout(Duration::from_secs(2), server).await???;
    Ok(())
}

#[tokio::test]
async fn gone_relist_survives_an_outage_without_publishing_a_partial_snapshot() -> Result<()> {
    let harness = harness(Mode::Relist, Some("blue")).await?;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let controller = Controller::new(harness.options.clone(), Arc::new(ChannelSink(tx)))?;
    let (cancel, task) = spawn(controller);
    assert_eq!(
        next_snapshot(&mut rx, Duration::from_secs(4))
            .await?
            .config
            .http
            .len(),
        1
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err()
    );
    // The expired watch relists after the spacing window; the outage on that
    // relist is retried after another window, so the deletion lands after
    // roughly two windows.
    assert!(
        next_snapshot(&mut rx, Duration::from_secs(16))
            .await?
            .config
            .http
            .is_empty()
    );
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn stale_threshold_must_exceed_the_watch_timeout() -> Result<()> {
    let mut harness = harness(Mode::Delete, Some("blue")).await?;
    let (tx, _rx) = mpsc::unbounded_channel();
    harness.options.stale_after = harness.options.watch_timeout;
    let error = Controller::new(harness.options.clone(), Arc::new(ChannelSink(tx.clone())))
        .err()
        .expect("an idle watch cannot prove freshness within its own timeout");
    assert!(error.to_string().contains("stale threshold"), "{error}");
    harness.options.stale_after = Duration::from_secs(3601);
    assert!(Controller::new(harness.options.clone(), Arc::new(ChannelSink(tx.clone()))).is_err());
    harness.options.stale_after = harness.options.watch_timeout + Duration::from_millis(1);
    assert!(Controller::new(harness.options.clone(), Arc::new(ChannelSink(tx))).is_ok());
    harness.stop().await
}

#[tokio::test]
async fn rejected_snapshot_does_not_patch_status() -> Result<()> {
    let mut harness = harness(Mode::Delete, Some("blue")).await?;
    harness.options.publish_address = Some("192.0.2.1".into());
    let controller = Controller::new(harness.options.clone(), Arc::new(RejectingSink))?;
    let (cancel, task) = spawn(controller);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(harness.state.patches.load(Ordering::SeqCst), 0);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn cancellation_interrupts_a_stalled_status_patch() -> Result<()> {
    let mut harness = harness(Mode::StallStatus, Some("blue")).await?;
    harness.options.publish_address = Some("192.0.2.1".into());
    let (tx, _rx) = mpsc::unbounded_channel();
    let controller = Controller::new(harness.options.clone(), Arc::new(ChannelSink(tx)))?;
    let (cancel, task) = spawn(controller);
    let state = harness.state.clone();
    tokio::time::timeout(Duration::from_secs(2), async {
        while state.patches.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    cancel.cancel();
    tokio::time::timeout(Duration::from_millis(500), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn publication_is_not_blocked_by_a_stalled_status_endpoint() -> Result<()> {
    let mut harness = harness(Mode::StallStatus, Some("blue")).await?;
    harness.options.publish_address = Some("192.0.2.1".into());
    // A patch that blocks publication would hold it for the whole request
    // timeout; make that window much wider than the bound asserted below.
    harness.options.request_timeout = Duration::from_secs(10);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let controller = Controller::new(harness.options.clone(), Arc::new(ChannelSink(tx)))?;
    let (cancel, task) = spawn(controller);
    let first = next_snapshot(&mut rx, Duration::from_secs(4)).await?;
    assert_eq!(first.config.http.len(), 1);
    // The status patch for the first snapshot stalls for 30 seconds. The
    // Ingress watch delivers a change right away; its snapshot must not wait
    // behind the patch.
    let second = next_snapshot(&mut rx, Duration::from_secs(4)).await?;
    assert_eq!(second.config.http.len(), 2);
    // The patch runs in the background queue; it reaches the mock shortly
    // after publication rather than before it.
    let started = std::time::Instant::now();
    while harness.state.patches.load(Ordering::SeqCst) < 1 {
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "the status patch never reached the API"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn cross_namespace_host_claims_never_hijack_the_older_owner() -> Result<()> {
    let mut harness = harness(Mode::CrossNamespace, None).await?;
    harness.options.watch_secrets = true;
    let zulu = rcgen::generate_simple_self_signed(vec!["api.example.test".into()])?;
    let alpha = rcgen::generate_simple_self_signed(vec!["api.example.test".into()])?;
    let zulu_cert = zulu.cert.pem();
    *harness.state.material.lock().unwrap() = vec![
        (
            "zulu".into(),
            "api-tls".into(),
            zulu_cert.clone(),
            zulu.signing_key.serialize_pem(),
        ),
        (
            "alpha".into(),
            "api-tls".into(),
            alpha.cert.pem(),
            alpha.signing_key.serialize_pem(),
        ),
    ];
    let (tx, mut rx) = mpsc::unbounded_channel();
    let controller = Controller::new(harness.options.clone(), Arc::new(ChannelSink(tx)))?;
    let (cancel, task) = spawn(controller);
    // The watch adds a younger attacker Ingress without TLS (sorts first by
    // namespace), then one with its own valid certificate for the same host.
    // Between them the victim changes so a new snapshot is observable.
    let mut seen = Vec::new();
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            let snapshot = rx.recv().await.unwrap();
            let done = snapshot.config.http.len() == 3;
            seen.push(snapshot);
            if done {
                break;
            }
        }
    })
    .await?;
    assert!(seen.len() >= 3, "snapshots: {}", seen.len());
    for snapshot in &seen {
        assert!(!snapshot.config.http.is_empty());
        for route in &snapshot.config.http {
            assert_eq!(route.host.as_deref(), Some("api.example.test"));
            assert_eq!(route.backends, ["http://api.zulu.svc:8080"], "{}", route.id);
        }
        assert_eq!(snapshot.certificates.len(), 1);
        assert_eq!(snapshot.certificates[0].cert_pem, zulu_cert.as_bytes());
    }
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn replicas_with_different_histories_publish_identical_snapshots() -> Result<()> {
    let harness = harness(Mode::Histories, None).await?;
    // The warm replica listed only the younger claimant and then watched the
    // older one appear; the cold replica lists both at once.
    let (warm_tx, mut warm_rx) = mpsc::unbounded_channel();
    let warm = Controller::new(harness.options.clone(), Arc::new(ChannelSink(warm_tx)))?;
    let (cold_tx, mut cold_rx) = mpsc::unbounded_channel();
    let cold = Controller::new(
        harness.replica("token-cold")?,
        Arc::new(ChannelSink(cold_tx)),
    )?;
    let (warm_cancel, warm_task) = spawn(warm);
    let (cold_cancel, cold_task) = spawn(cold);
    let first = next_snapshot(&mut warm_rx, Duration::from_secs(4)).await?;
    assert_eq!(first.config.http[0].backends, ["http://api.red.svc:8080"]);
    let warm_final = next_snapshot(&mut warm_rx, Duration::from_secs(4)).await?;
    let cold_final = next_snapshot(&mut cold_rx, Duration::from_secs(4)).await?;
    // A cold start over a contested host publishes the oldest claimant
    // instead of rejecting both, and both replicas agree.
    assert_eq!(cold_final.config.http.len(), 1);
    assert_eq!(
        cold_final.config.http[0].backends,
        ["http://api.blue.svc:8080"]
    );
    assert_eq!(warm_final, cold_final);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), cold_rx.recv())
            .await
            .is_err(),
        "the cold replica republished"
    );
    warm_cancel.cancel();
    cold_cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), warm_task).await??;
    tokio::time::timeout(Duration::from_secs(2), cold_task).await??;
    harness.stop().await
}

#[tokio::test]
async fn readiness_expires_while_watches_are_stale_and_returns_when_the_api_resumes() -> Result<()>
{
    let mut harness = harness(Mode::Stale, Some("blue")).await?;
    harness.options.stale_after = Duration::from_millis(1500);
    let (snapshots, mut rx) = mpsc::unbounded_channel();
    let (authority, mut reports) = mpsc::unbounded_channel();
    let controller = Controller::new(
        harness.options.clone(),
        Arc::new(ReportingSink {
            snapshots,
            authority,
        }),
    )?;
    let (cancel, task) = spawn(controller);
    assert_eq!(
        next_snapshot(&mut rx, Duration::from_secs(4))
            .await?
            .config
            .http
            .len(),
        1
    );
    await_authority(&mut reports, true, Duration::from_secs(2)).await?;
    // Every watch fails: after `stale_after` the replica must stop claiming
    // authority while still serving the snapshot it has.
    let reason = await_authority(&mut reports, false, Duration::from_secs(4)).await?;
    assert!(reason.contains("silent"), "{reason}");
    assert!(rx.try_recv().is_err(), "the snapshot was withdrawn");
    harness.state.resume.store(true, Ordering::SeqCst);
    await_authority(&mut reports, true, Duration::from_secs(8)).await?;
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn incomplete_cache_reports_not_ready_until_the_relist_succeeds() -> Result<()> {
    let mut harness = harness(Mode::Capacity, Some("blue")).await?;
    harness.options.max_objects = 1;
    let (snapshots, mut rx) = mpsc::unbounded_channel();
    let (authority, mut reports) = mpsc::unbounded_channel();
    let controller = Controller::new(
        harness.options.clone(),
        Arc::new(ReportingSink {
            snapshots,
            authority,
        }),
    )?;
    let (cancel, task) = spawn(controller);
    next_snapshot(&mut rx, Duration::from_secs(4)).await?;
    await_authority(&mut reports, true, Duration::from_secs(2)).await?;
    // `ADDED second` is rejected at the cap: the cache is incomplete.
    let reason = await_authority(&mut reports, false, Duration::from_secs(4)).await?;
    assert!(reason.contains("incomplete"), "{reason}");
    // `DELETED main` frees a slot; the recovering relist completes the cache.
    await_authority(&mut reports, true, Duration::from_secs(12)).await?;
    assert!(harness.state.service_lists.load(Ordering::SeqCst) >= 2);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn replicas_with_different_addresses_merge_their_status_entries() -> Result<()> {
    let mut harness = harness(Mode::Merge, Some("blue")).await?;
    harness.options.publish_address = Some("192.0.2.1".into());
    let mut other = harness.replica("token-y")?;
    other.publish_address = Some("192.0.2.2".into());
    let (x_tx, _x_rx) = mpsc::unbounded_channel();
    let (y_tx, _y_rx) = mpsc::unbounded_channel();
    let x = Controller::new(harness.options.clone(), Arc::new(ChannelSink(x_tx)))?;
    let y = Controller::new(other, Arc::new(ChannelSink(y_tx)))?;
    let (x_cancel, x_task) = spawn(x);
    let (y_cancel, y_task) = spawn(y);
    let state = harness.state.clone();
    let addresses = |state: &ApiState| -> Vec<String> {
        let mut ips: Vec<String> = state
            .status
            .lock()
            .unwrap()
            .1
            .iter()
            .filter_map(|entry| entry["ip"].as_str().map(str::to_owned))
            .collect();
        ips.sort();
        ips
    };
    tokio::time::timeout(Duration::from_secs(8), async {
        while addresses(&state) != ["192.0.2.1", "192.0.2.2"] {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    // Neither replica removes the other's entry afterwards.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(addresses(&state), ["192.0.2.1", "192.0.2.2"]);
    x_cancel.cancel();
    y_cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), x_task).await??;
    tokio::time::timeout(Duration::from_secs(2), y_task).await??;
    harness.stop().await
}

#[tokio::test]
async fn withdrawn_ingress_never_receives_the_address_and_loses_it() -> Result<()> {
    let mut harness = harness(Mode::Withdrawn, None).await?;
    harness.options.publish_address = Some("192.0.2.1".into());
    let (tx, mut rx) = mpsc::unbounded_channel();
    let controller = Controller::new(harness.options.clone(), Arc::new(ChannelSink(tx)))?;
    let (cancel, task) = spawn(controller);
    let snapshot = next_snapshot(&mut rx, Duration::from_secs(4)).await?;
    assert_eq!(
        snapshot.config.http[0].backends,
        ["http://api.blue.svc:8080"]
    );
    let state = harness.state.clone();
    let patched = |state: &ApiState| -> Vec<(String, Vec<String>)> {
        state
            .patch_log
            .lock()
            .unwrap()
            .iter()
            .map(|(path, body)| {
                let ips = body["status"]["loadBalancer"]["ingress"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|entry| entry["ip"].as_str().map(str::to_owned))
                    .collect();
                (path.clone(), ips)
            })
            .collect()
    };
    tokio::time::timeout(Duration::from_secs(4), async {
        while patched(&state).len() < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    let log = patched(&state);
    let blue = "/apis/networking.k8s.io/v1/namespaces/blue/ingresses/app/status";
    let red = "/apis/networking.k8s.io/v1/namespaces/red/ingresses/app/status";
    assert!(
        log.contains(&(blue.to_owned(), vec!["192.0.2.1".to_owned()])),
        "{log:?}"
    );
    // The withdrawn younger claimant loses the address it carried and never
    // receives it.
    assert!(log.contains(&(red.to_owned(), Vec::new())), "{log:?}");
    assert!(
        log.iter()
            .all(|(path, ips)| path != red || !ips.iter().any(|ip| ip == "192.0.2.1")),
        "{log:?}"
    );
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn expired_watches_relist_at_most_once_per_spacing_window() -> Result<()> {
    let harness = harness(Mode::Storm, Some("blue")).await?;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let controller = Controller::new(harness.options.clone(), Arc::new(ChannelSink(tx)))?;
    let (cancel, task) = spawn(controller);
    next_snapshot(&mut rx, Duration::from_secs(4)).await?;
    // Every Ingress watch expires at once. Without spacing this loops
    // list -> watch -> 410 -> list as fast as the server answers.
    tokio::time::sleep(Duration::from_millis(6500)).await;
    let lists = harness.state.ingress_lists.load(Ordering::SeqCst);
    assert!((1..=2).contains(&lists), "{lists} lists in 6.5 seconds");
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn oversized_secret_page_is_retried_with_smaller_pages() -> Result<()> {
    let mut harness = harness(Mode::LargeSecrets, Some("blue")).await?;
    harness.options.watch_secrets = true;
    harness.options.list_page_size = 500;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let controller = Controller::new(harness.options.clone(), Arc::new(ChannelSink(tx)))?;
    let (cancel, task) = spawn(controller);
    let first = tokio::time::timeout(Duration::from_secs(8), rx.recv())
        .await?
        .unwrap();
    assert_eq!(first.config.http.len(), 1);
    assert_eq!(first.certificates.len(), 1);
    let queries = harness.state.secret_queries.lock().unwrap().clone();
    let limits: Vec<usize> = queries.iter().map(|query| limit_of(query)).collect();
    assert_eq!(limits, [50, 25, 12, 6, 3, 1], "{queries:?}");
    assert!(
        queries.iter().all(|query| {
            query.contains("fieldSelector=type%3Dkubernetes.io%2Ftls")
                && !query.contains("resourceVersion=0")
        }),
        "{queries:?}"
    );
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn object_rejected_at_capacity_is_recovered_by_a_relist() -> Result<()> {
    let mut harness = harness(Mode::Capacity, Some("blue")).await?;
    harness.options.max_objects = 1;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let controller = Controller::new(harness.options.clone(), Arc::new(ChannelSink(tx)))?;
    let (cancel, task) = spawn(controller);
    let first = tokio::time::timeout(Duration::from_secs(4), rx.recv())
        .await?
        .unwrap();
    assert_eq!(
        first.config.http[0].host.as_deref(),
        Some("api.example.test")
    );
    // `ADDED second` is rejected at the cap and never sent again by the
    // watch; `DELETED main` frees a slot and must trigger a recovering relist
    // after the relist spacing window.
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            let snapshot = rx.recv().await.unwrap();
            if snapshot.config.http.len() == 1
                && snapshot.config.http[0].host.as_deref() == Some("second.example.test")
            {
                break;
            }
        }
    })
    .await?;
    assert!(harness.state.service_lists.load(Ordering::SeqCst) >= 2);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn failed_recovery_relist_keeps_watching_from_the_last_version() -> Result<()> {
    let mut harness = harness(Mode::CapacityStuck, Some("blue")).await?;
    harness.options.max_objects = 1;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let controller = Controller::new(harness.options.clone(), Arc::new(ChannelSink(tx)))?;
    let (cancel, task) = spawn(controller);
    // The recovery relist finds the server still over the cap and fails; the
    // controller must resume watching instead of stalling on list retries.
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            let snapshot = rx.recv().await.unwrap();
            if snapshot.config.http.len() == 1
                && snapshot.config.http[0].host.as_deref() == Some("third.example.test")
            {
                break;
            }
        }
    })
    .await?;
    assert!(harness.state.ingress_lists.load(Ordering::SeqCst) >= 2);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn cancellation_completes_while_watchers_block_on_a_full_channel() -> Result<()> {
    let harness = harness(Mode::FullChannel, Some("blue")).await?;
    let release = CancellationToken::new();
    let sink = Arc::new(BlockingSink {
        applies: AtomicUsize::new(0),
        release: release.clone(),
    });
    let controller = Controller::new(harness.options.clone(), sink.clone())?;
    let (cancel, task) = spawn(controller);
    tokio::time::timeout(Duration::from_secs(4), async {
        while sink.applies.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    // The Service watch floods the channel while reconciliation is stuck, and
    // the Ingress watch keeps closing immediately and reporting ticks.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!task.is_finished());
    cancel.cancel();
    release.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    // Immediate empty closures back off instead of reconnecting in a tight loop.
    assert!(
        harness.state.ingress_watches.load(Ordering::SeqCst) < 20,
        "{} ingress watch requests",
        harness.state.ingress_watches.load(Ordering::SeqCst)
    );
    harness.stop().await
}

#[tokio::test]
async fn status_conflict_retries_that_object_without_relisting() -> Result<()> {
    let mut harness = harness(Mode::Conflict, Some("blue")).await?;
    harness.options.publish_address = Some("192.0.2.1".into());
    let (tx, mut rx) = mpsc::unbounded_channel();
    let controller = Controller::new(harness.options.clone(), Arc::new(ChannelSink(tx)))?;
    let (cancel, task) = spawn(controller);
    tokio::time::timeout(Duration::from_secs(4), rx.recv())
        .await?
        .unwrap();
    let state = harness.state.clone();
    tokio::time::timeout(Duration::from_secs(4), async {
        while state.patches.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    // Ticks from the closing Ingress watch keep arriving; the cached object
    // carries the patched status so nothing is patched again.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(state.patches.load(Ordering::SeqCst), 2);
    assert_eq!(state.gets.load(Ordering::SeqCst), 1);
    assert_eq!(state.service_lists.load(Ordering::SeqCst), 1);
    assert!(state.ingress_watches.load(Ordering::SeqCst) >= 2);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn status_queue_stays_bounded_under_churn_while_patches_stall() -> Result<()> {
    let mut harness = harness(Mode::Churn, Some("blue")).await?;
    harness.options.publish_address = Some("192.0.2.1".into());
    harness.options.request_timeout = Duration::from_secs(10);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let controller = Controller::new(harness.options.clone(), Arc::new(ChannelSink(tx)))?;
    let (cancel, task) = spawn(controller);
    assert_eq!(
        next_snapshot(&mut rx, Duration::from_secs(4))
            .await?
            .config
            .http
            .len(),
        1
    );
    // Forty Ingresses with unique names are created and deleted while every
    // status patch stalls; the final change to `main` marks the end of the
    // churn (deletions publish nothing new, they restore the last snapshot).
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let snapshot = rx.recv().await.unwrap();
            if snapshot.config.http.len() == 2
                && snapshot
                    .config
                    .http
                    .iter()
                    .all(|route| route.host.as_deref() == Some("api.example.test"))
            {
                break;
            }
        }
    })
    .await?;
    let state = harness.state.clone();
    let churn_patches = |state: &ApiState| -> usize {
        state
            .patch_log
            .lock()
            .unwrap()
            .iter()
            .filter(|(path, _)| path.contains("/ingresses/churn-"))
            .count()
    };
    let stalled = churn_patches(&state);
    assert!(
        stalled <= 4,
        "{stalled} patches in flight beyond the concurrency cap"
    );
    // Releasing the stalled patches lets the worker drain whatever is still
    // queued. Work for the deleted objects must have been dropped with them,
    // not retained until the API answered.
    state.resume.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let churned = churn_patches(&state);
    assert!(
        churned <= 4,
        "{churned} status patches were sent for deleted Ingresses"
    );
    assert!(
        state
            .patch_log
            .lock()
            .unwrap()
            .iter()
            .any(|(path, _)| path.ends_with("/ingresses/main/status")),
        "the live Ingress never received its address"
    );
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn status_retry_after_a_conflict_does_not_adopt_a_recreated_object() -> Result<()> {
    let mut harness = harness(Mode::Recreated, Some("blue")).await?;
    harness.options.publish_address = Some("192.0.2.1".into());
    let (tx, mut rx) = mpsc::unbounded_channel();
    let controller = Controller::new(harness.options.clone(), Arc::new(ChannelSink(tx)))?;
    let (cancel, task) = spawn(controller);
    next_snapshot(&mut rx, Duration::from_secs(4)).await?;
    let state = harness.state.clone();
    // The patch against the admitted object (uid u1) conflicts; the re-read
    // returns the same name recreated as uid u2 in another class.
    tokio::time::timeout(Duration::from_secs(4), async {
        while state.gets.load(Ordering::SeqCst) < 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let log = state.patch_log.lock().unwrap().clone();
    assert_eq!(
        log.len(),
        1,
        "the retry patched an object that was never admitted: {log:?}"
    );
    assert_eq!(log[0].1["metadata"]["resourceVersion"], "11");
    assert_eq!(state.gets.load(Ordering::SeqCst), 1);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn staleness_is_assessed_while_a_relist_is_in_progress() -> Result<()> {
    let mut harness = harness(Mode::SlowRelist, Some("blue")).await?;
    harness.options.request_timeout = Duration::from_secs(20);
    harness.options.stale_after = Duration::from_secs(8);
    let (snapshots, mut rx) = mpsc::unbounded_channel();
    let (authority, mut reports) = mpsc::unbounded_channel();
    let controller = Controller::new(
        harness.options.clone(),
        Arc::new(ReportingSink {
            snapshots,
            authority,
        }),
    )?;
    let (cancel, task) = spawn(controller);
    next_snapshot(&mut rx, Duration::from_secs(4)).await?;
    await_authority(&mut reports, true, Duration::from_secs(2)).await?;
    // The Ingress watch expires at once. The relist starts after the spacing
    // window (4-6 s) and its Service list stalls for 6 s, so the 8 s
    // threshold measured from the first list passes while the list request
    // is pending. Readiness must expire then, not when the list returns.
    let reason = await_authority(&mut reports, false, Duration::from_secs(12)).await?;
    assert!(reason.contains("silent"), "{reason}");
    // The mock counts a list when it answers it: the relist's Service list
    // was still pending when readiness was withdrawn.
    assert_eq!(harness.state.service_lists.load(Ordering::SeqCst), 1);
    // The completed relist confirms both kinds again.
    await_authority(&mut reports, true, Duration::from_secs(8)).await?;
    assert_eq!(harness.state.service_lists.load(Ordering::SeqCst), 2);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn a_completed_list_confirms_each_kind_at_the_moment_it_was_read() -> Result<()> {
    let mut harness = harness(Mode::SlowIngressList, Some("blue")).await?;
    harness.options.request_timeout = Duration::from_secs(20);
    harness.options.stale_after = Duration::from_secs(3);
    let (snapshots, mut rx) = mpsc::unbounded_channel();
    let (authority, mut reports) = mpsc::unbounded_channel();
    let controller = Controller::new(
        harness.options.clone(),
        Arc::new(ReportingSink {
            snapshots,
            authority,
        }),
    )?;
    let (cancel, task) = spawn(controller);
    // Services were listed at once; the Ingress list answers 4 s later. By
    // then the Service snapshot is older than the threshold, so completing
    // the list must not make the replica authoritative.
    next_snapshot(&mut rx, Duration::from_secs(8)).await?;
    assert!(
        await_authority(&mut reports, true, Duration::from_secs(4))
            .await
            .is_err(),
        "a Service snapshot older than the threshold was reported fresh"
    );
    // Once the watches are accepted and closed normally, readiness returns.
    harness.state.resume.store(true, Ordering::SeqCst);
    await_authority(&mut reports, true, Duration::from_secs(15)).await?;
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    harness.stop().await
}

#[tokio::test]
async fn an_accepted_watch_response_alone_does_not_restore_readiness() -> Result<()> {
    let mut harness = harness(Mode::LateWatch, Some("blue")).await?;
    harness.options.request_timeout = Duration::from_secs(10);
    harness.options.stale_after = Duration::from_secs(2);
    let (snapshots, mut rx) = mpsc::unbounded_channel();
    let (authority, mut reports) = mpsc::unbounded_channel();
    let controller = Controller::new(
        harness.options.clone(),
        Arc::new(ReportingSink {
            snapshots,
            authority,
        }),
    )?;
    let (cancel, task) = spawn(controller);
    next_snapshot(&mut rx, Duration::from_secs(4)).await?;
    await_authority(&mut reports, true, Duration::from_secs(2)).await?;
    // No watch answers within the threshold: readiness expires.
    let reason = await_authority(&mut reports, false, Duration::from_secs(4)).await?;
    assert!(reason.contains("silent"), "{reason}");
    // A second later every watch is accepted with a 200 whose body never
    // yields an event, bookmark, or normal closure. Response headers alone
    // prove nothing about catch-up, so readiness must stay withdrawn.
    assert!(
        await_authority(&mut reports, true, Duration::from_secs(3))
            .await
            .is_err(),
        "readiness returned on an accepted watch that delivered nothing"
    );
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), task).await??;
    harness.stop().await
}

fn limit_of(query: &str) -> usize {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("limit="))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

async fn serve_tls(
    pair: rcgen::CertifiedKey<rcgen::KeyPair>,
    state: Arc<ApiState>,
    cancel: CancellationToken,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let mut config = hangang::tls::server_config(
        pair.cert.pem().as_bytes(),
        pair.signing_key.serialize_pem().as_bytes(),
    )?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let accepted = tokio::select! { _ = cancel.cancelled() => break, value = listener.accept() => value };
            let (stream, _) = accepted?;
            let acceptor = acceptor.clone();
            let state = state.clone();
            connections.spawn(async move {
                let stream = acceptor.accept(stream).await?;
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |request| handle(request, state.clone())),
                    )
                    .await?;
                Ok::<_, anyhow::Error>(())
            });
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        Ok(())
    });
    Ok((address, task))
}

async fn handle(
    request: Request<Incoming>,
    state: Arc<ApiState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let authorization = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    state
        .authorization
        .lock()
        .unwrap()
        .push(authorization.clone());
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or("").to_owned();
    let body = request
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();
    if method == hyper::Method::PATCH {
        state.patches.fetch_add(1, Ordering::SeqCst);
        let patch: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        state
            .patch_log
            .lock()
            .unwrap()
            .push((path.clone(), patch.clone()));
        if matches!(state.mode, Mode::StallStatus) {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        if matches!(state.mode, Mode::Conflict) {
            return Ok(handle_conflict_patch(&body));
        }
        if matches!(state.mode, Mode::Merge) {
            return Ok(handle_merge_patch(&patch, &state));
        }
        if matches!(state.mode, Mode::Churn) {
            while !state.resume.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if path.contains("/ingresses/churn-") {
                return Ok(response(StatusCode::NOT_FOUND, "gone"));
            }
            return Ok(json(
                StatusCode::OK,
                ingress_at("12", Some(serde_json::json!({"ip":"192.0.2.1"}))),
            ));
        }
        if matches!(state.mode, Mode::Recreated) {
            return Ok(handle_recreated_patch(&patch));
        }
        return Ok(response(StatusCode::OK, "{}"));
    }
    if matches!(state.mode, Mode::Conflict) && path.ends_with("/ingresses/main") {
        state.gets.fetch_add(1, Ordering::SeqCst);
        return Ok(json(StatusCode::OK, ingress_at("12", None)));
    }
    if matches!(state.mode, Mode::Recreated) && path.ends_with("/ingresses/main") {
        state.gets.fetch_add(1, Ordering::SeqCst);
        // Same name, new uid, another class, no address yet.
        let mut recreated = identified(ingress_at("20", None), "u2", 1);
        recreated["spec"]["ingressClassName"] = "other".into();
        return Ok(json(StatusCode::OK, recreated));
    }
    // Stalls that must happen while the request is pending.
    let watch = query.contains("watch=true");
    match state.mode {
        Mode::SlowRelist
            if path.ends_with("/services")
                && !watch
                && state.service_lists.load(Ordering::SeqCst) == 1 =>
        {
            tokio::time::sleep(Duration::from_secs(6)).await;
        }
        Mode::SlowIngressList if path.ends_with("/ingresses") && !watch => {
            tokio::time::sleep(Duration::from_secs(4)).await;
        }
        Mode::LateWatch if watch => {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        _ => {}
    }
    let response = match state.mode {
        Mode::Relist => handle_relist(&path, &query, &state),
        Mode::CrossNamespace => handle_cross_namespace(&path, &query, &state),
        Mode::LargeSecrets => handle_large_secrets(&path, &query, &state),
        Mode::Capacity | Mode::CapacityStuck => handle_capacity(&path, &query, &state),
        Mode::FullChannel => handle_full_channel(&path, &query, &state),
        Mode::Conflict => handle_conflict(&path, &query, &state),
        Mode::StallStatus => handle_stall_status(&path, &query, &state),
        Mode::Histories => handle_histories(&path, &query, &authorization, &state),
        Mode::Stale => handle_stale(&path, &query, &state),
        Mode::Merge => handle_merge(&path, &query, &state),
        Mode::Withdrawn => handle_withdrawn(&path, &query),
        Mode::Storm => handle_storm(&path, &query, &state),
        Mode::Delete => handle_delete(&path, &query, &state),
        Mode::Churn => handle_churn(&path, &query, &state),
        Mode::Recreated => handle_recreated(&path, &query, &state),
        Mode::SlowRelist => handle_slow_relist(&path, &query, &state),
        Mode::SlowIngressList => handle_stale(&path, &query, &state),
        Mode::LateWatch => handle_late_watch(&path, &query),
    };
    Ok(response)
}

/// Forty create/delete pairs with unique names on the first Ingress watch,
/// then a change to `main` that marks the end of the churn.
fn handle_churn(path: &str, query: &str, state: &ApiState) -> Response<Full<Bytes>> {
    if query.contains("watch=true") {
        if path.ends_with("/ingresses") && state.ingress_watches.fetch_add(1, Ordering::SeqCst) == 0
        {
            let mut events = Vec::new();
            for index in 0..40 {
                let name = format!("churn-{index}");
                let host = format!("{name}.example.test");
                events.push(event(
                    "ADDED",
                    ingress_in(
                        "blue",
                        &name,
                        &format!("{}", 100 + 2 * index),
                        &host,
                        &["/"],
                        None,
                    ),
                ));
                events.push(event(
                    "DELETED",
                    ingress_in(
                        "blue",
                        &name,
                        &format!("{}", 101 + 2 * index),
                        &host,
                        &["/"],
                        None,
                    ),
                ));
            }
            events.push(event(
                "MODIFIED",
                ingress_in(
                    "blue",
                    "main",
                    "200",
                    "api.example.test",
                    &["/", "/v2"],
                    Some("api-tls"),
                ),
            ));
            return stream(events);
        }
        return response(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    }
    if path.ends_with("/services") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"10"},"items":[service()]}),
        );
    }
    if path.ends_with("/ingresses") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"11"},"items":[ingress()]}),
        );
    }
    response(StatusCode::NOT_FOUND, "not found")
}

/// The admitted Ingress is uid `u1`; watches fail so the recreation is only
/// visible through the conflict re-read.
fn handle_recreated(path: &str, query: &str, _state: &ApiState) -> Response<Full<Bytes>> {
    if query.contains("watch=true") {
        return response(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    }
    if path.ends_with("/services") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"10"},"items":[service()]}),
        );
    }
    if path.ends_with("/ingresses") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"11"},"items":[identified(ingress(), "u1", 1)]}),
        );
    }
    response(StatusCode::NOT_FOUND, "not found")
}
/// The observed `resourceVersion` 11 belongs to the deleted object; any
/// other version is accepted, which is what a transplanted retry would do.
fn handle_recreated_patch(patch: &serde_json::Value) -> Response<Full<Bytes>> {
    match patch["metadata"]["resourceVersion"].as_str() {
        Some("11") => json(
            StatusCode::CONFLICT,
            serde_json::json!({"kind":"Status","code":409,"reason":"Conflict"}),
        ),
        _ => response(StatusCode::OK, "{}"),
    }
}

/// The first Ingress watch expires so a relist follows; the handler delays
/// that relist's Service list before this function answers it.
fn handle_slow_relist(path: &str, query: &str, state: &ApiState) -> Response<Full<Bytes>> {
    if query.contains("watch=true") {
        if path.ends_with("/ingresses") && state.ingress_watches.fetch_add(1, Ordering::SeqCst) == 0
        {
            return json(
                StatusCode::OK,
                serde_json::json!({"type":"ERROR","object":{"kind":"Status","code":410,"reason":"Expired"}}),
            );
        }
        return response(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    }
    if path.ends_with("/services") {
        state.service_lists.fetch_add(1, Ordering::SeqCst);
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"10"},"items":[service()]}),
        );
    }
    if path.ends_with("/ingresses") {
        let attempt = state.ingress_lists.fetch_add(1, Ordering::SeqCst);
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":format!("{}", 11 + attempt)},"items":[ingress()]}),
        );
    }
    response(StatusCode::NOT_FOUND, "not found")
}

/// Watches are accepted (after the handler's delay) with a body that is not
/// a watch event, so they end in an error rather than a normal closure.
fn handle_late_watch(path: &str, query: &str) -> Response<Full<Bytes>> {
    if query.contains("watch=true") {
        return response(StatusCode::OK, "not a watch event\n");
    }
    if path.ends_with("/services") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"10"},"items":[service()]}),
        );
    }
    if path.ends_with("/ingresses") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"11"},"items":[ingress()]}),
        );
    }
    response(StatusCode::NOT_FOUND, "not found")
}

fn handle_delete(path: &str, query: &str, state: &ApiState) -> Response<Full<Bytes>> {
    if query.contains("watch=true") {
        if path.ends_with("/secrets") {
            let attempt = state.secret_watches.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                response(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable")
            } else {
                json(
                    StatusCode::OK,
                    serde_json::json!({"type":"DELETED","object":{"apiVersion":"v1","kind":"Secret","metadata":{"name":"api-tls","namespace":"blue","resourceVersion":"13"}}}),
                )
            }
        } else {
            response(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable")
        }
    } else if path.ends_with("/services") {
        if query.contains("continue=next") {
            json(
                StatusCode::OK,
                serde_json::json!({"metadata":{"resourceVersion":"10"},"items":[]}),
            )
        } else {
            json(
                StatusCode::OK,
                serde_json::json!({"metadata":{"resourceVersion":"10","continue":"next"},"items":[service()]}),
            )
        }
    } else if path.ends_with("/ingresses") {
        json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"11"},"items":[ingress()]}),
        )
    } else if path.ends_with("/secrets") {
        json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"12"},"items":[tls_secret()]}),
        )
    } else {
        response(StatusCode::NOT_FOUND, "not found")
    }
}

/// Like `Delete`, but the first Ingress watch delivers a change immediately
/// while every status patch stalls.
fn handle_stall_status(path: &str, query: &str, state: &ApiState) -> Response<Full<Bytes>> {
    if query.contains("watch=true")
        && path.ends_with("/ingresses")
        && state.ingress_watches.fetch_add(1, Ordering::SeqCst) == 0
    {
        return stream(vec![event(
            "MODIFIED",
            ingress_in(
                "blue",
                "main",
                "21",
                "api.example.test",
                &["/", "/v2"],
                Some("api-tls"),
            ),
        )]);
    }
    handle_delete(path, query, state)
}

fn handle_relist(path: &str, query: &str, state: &ApiState) -> Response<Full<Bytes>> {
    if query.contains("watch=true") {
        if path.ends_with("/ingresses") && state.ingress_watches.fetch_add(1, Ordering::SeqCst) == 0
        {
            return json(
                StatusCode::OK,
                serde_json::json!({"type":"ERROR","object":{"kind":"Status","code":410,"reason":"Expired"}}),
            );
        }
        return response(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    }
    if path.ends_with("/services") {
        let attempt = state.service_lists.fetch_add(1, Ordering::SeqCst);
        if attempt == 1 {
            return response(StatusCode::INTERNAL_SERVER_ERROR, "outage");
        }
        let items = if attempt == 0 {
            vec![service()]
        } else {
            Vec::new()
        };
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":format!("{}", 20 + attempt)},"items":items}),
        );
    }
    if path.ends_with("/ingresses") {
        let items = if state.service_lists.load(Ordering::SeqCst) <= 1 {
            vec![ingress()]
        } else {
            Vec::new()
        };
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"30"},"items":items}),
        );
    }
    response(StatusCode::NOT_FOUND, "not found")
}

fn handle_cross_namespace(path: &str, query: &str, state: &ApiState) -> Response<Full<Bytes>> {
    // The victim was created first; the attacker's objects are younger.
    let victim = |rv: &str, paths: &[&str]| {
        aged(
            ingress_in(
                "zulu",
                "app",
                rv,
                "api.example.test",
                paths,
                Some("api-tls"),
            ),
            "2026-01-01T00:00:00Z",
            "victim",
        )
    };
    if query.contains("watch=true") {
        if path.ends_with("/ingresses") && state.ingress_watches.fetch_add(1, Ordering::SeqCst) == 0
        {
            return stream(vec![
                event(
                    "ADDED",
                    aged(
                        ingress_in("alpha", "app", "20", "api.example.test", &["/"], None),
                        "2026-02-01T00:00:00Z",
                        "attacker",
                    ),
                ),
                event("MODIFIED", victim("21", &["/", "/v2"])),
                event(
                    "ADDED",
                    aged(
                        ingress_in(
                            "alpha",
                            "late",
                            "22",
                            "api.example.test",
                            &["/"],
                            Some("api-tls"),
                        ),
                        "2026-02-02T00:00:00Z",
                        "late",
                    ),
                ),
                event("MODIFIED", victim("23", &["/", "/v2", "/v3"])),
            ]);
        }
        return response(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    }
    if path.ends_with("/services") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"10"},"items":[service_in("alpha"), service_in("zulu")]}),
        );
    }
    if path.ends_with("/ingresses") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"11"},"items":[victim("11", &["/"])]}),
        );
    }
    if path.ends_with("/secrets") {
        let items: Vec<serde_json::Value> = state
            .material
            .lock()
            .unwrap()
            .iter()
            .map(|(namespace, name, cert, key)| secret_in(namespace, name, cert, key))
            .collect();
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"12"},"items":items}),
        );
    }
    response(StatusCode::NOT_FOUND, "not found")
}

/// `blue` created its Ingress before `red`. The default token sees only `red`
/// in its list and `blue` arriving on the watch; `token-cold` lists both.
fn handle_histories(
    path: &str,
    query: &str,
    authorization: &str,
    state: &ApiState,
) -> Response<Full<Bytes>> {
    let blue = aged(
        ingress_in("blue", "app", "20", "api.example.test", &["/"], None),
        "2026-01-01T00:00:00Z",
        "aaaa",
    );
    let red = aged(
        ingress_in("red", "app", "11", "api.example.test", &["/"], None),
        "2026-01-02T00:00:00Z",
        "bbbb",
    );
    let cold = authorization == "Bearer token-cold";
    if query.contains("watch=true") {
        if !cold
            && path.ends_with("/ingresses")
            && state.ingress_watches.fetch_add(1, Ordering::SeqCst) == 0
        {
            return stream(vec![event("ADDED", blue)]);
        }
        return response(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    }
    if path.ends_with("/services") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"10"},"items":[service_in("blue"), service_in("red")]}),
        );
    }
    if path.ends_with("/ingresses") {
        let items = if cold { vec![blue, red] } else { vec![red] };
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":if cold {"20"} else {"11"}},"items":items}),
        );
    }
    response(StatusCode::NOT_FOUND, "not found")
}

fn handle_stale(path: &str, query: &str, state: &ApiState) -> Response<Full<Bytes>> {
    if query.contains("watch=true") {
        if state.resume.load(Ordering::SeqCst) {
            // Accepted and closed at once: the kind is confirmed current.
            return response(StatusCode::OK, "");
        }
        return response(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    }
    if path.ends_with("/services") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"10"},"items":[service()]}),
        );
    }
    if path.ends_with("/ingresses") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"11"},"items":[ingress()]}),
        );
    }
    response(StatusCode::NOT_FOUND, "not found")
}

fn merge_document(state: &ApiState) -> serde_json::Value {
    let (rv, list) = state.status.lock().unwrap().clone();
    let mut object = ingress_at(&rv.to_string(), None);
    object["status"] = serde_json::json!({"loadBalancer":{"ingress":list}});
    object
}
fn handle_merge(path: &str, query: &str, state: &ApiState) -> Response<Full<Bytes>> {
    if query.contains("watch=true") {
        return response(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    }
    if path.ends_with("/services") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"10"},"items":[service()]}),
        );
    }
    if path.ends_with("/ingresses") {
        let document = merge_document(state);
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":document["metadata"]["resourceVersion"]},"items":[document]}),
        );
    }
    if path.ends_with("/ingresses/main") {
        state.gets.fetch_add(1, Ordering::SeqCst);
        return json(StatusCode::OK, merge_document(state));
    }
    response(StatusCode::NOT_FOUND, "not found")
}
/// A real optimistic-concurrency status endpoint: the patch must carry the
/// current resourceVersion, and the list it sends replaces the stored one.
fn handle_merge_patch(patch: &serde_json::Value, state: &ApiState) -> Response<Full<Bytes>> {
    let mut status = state.status.lock().unwrap();
    if patch["metadata"]["resourceVersion"].as_str() != Some(&status.0.to_string()) {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({"kind":"Status","code":409,"reason":"Conflict"}),
        );
    }
    status.1 = patch["status"]["loadBalancer"]["ingress"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    status.0 += 1;
    drop(status);
    json(StatusCode::OK, merge_document(state))
}

fn handle_withdrawn(path: &str, query: &str) -> Response<Full<Bytes>> {
    if query.contains("watch=true") {
        return response(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    }
    if path.ends_with("/services") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"10"},"items":[service_in("blue"), service_in("red")]}),
        );
    }
    if path.ends_with("/ingresses") {
        let older = aged(
            ingress_in("blue", "app", "11", "api.example.test", &["/"], None),
            "2026-01-01T00:00:00Z",
            "older",
        );
        let mut younger = aged(
            ingress_in("red", "app", "12", "api.example.test", &["/"], None),
            "2026-02-01T00:00:00Z",
            "younger",
        );
        younger["status"] = serde_json::json!({"loadBalancer":{"ingress":[{"ip":"192.0.2.1"}]}});
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"12"},"items":[older, younger]}),
        );
    }
    response(StatusCode::NOT_FOUND, "not found")
}

fn handle_storm(path: &str, query: &str, state: &ApiState) -> Response<Full<Bytes>> {
    if query.contains("watch=true") {
        if path.ends_with("/ingresses") {
            state.ingress_watches.fetch_add(1, Ordering::SeqCst);
            return json(
                StatusCode::OK,
                serde_json::json!({"type":"ERROR","object":{"kind":"Status","code":410,"reason":"Expired"}}),
            );
        }
        return response(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    }
    if path.ends_with("/services") {
        state.service_lists.fetch_add(1, Ordering::SeqCst);
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"10"},"items":[service()]}),
        );
    }
    if path.ends_with("/ingresses") {
        let attempt = state.ingress_lists.fetch_add(1, Ordering::SeqCst);
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":format!("{}", 11 + attempt)},"items":[ingress()]}),
        );
    }
    response(StatusCode::NOT_FOUND, "not found")
}

fn handle_large_secrets(path: &str, query: &str, state: &ApiState) -> Response<Full<Bytes>> {
    if query.contains("watch=true") {
        return response(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    }
    if path.ends_with("/services") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"10"},"items":[service()]}),
        );
    }
    if path.ends_with("/ingresses") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"11"},"items":[ingress()]}),
        );
    }
    if path.ends_with("/secrets") {
        state.secret_queries.lock().unwrap().push(query.to_owned());
        if limit_of(query) >= 3 {
            // Unrelated Secrets in the namespace make any page of three or
            // more objects exceed the controller's 8 MiB response bound.
            let body = state
                .oversized
                .get_or_init(|| {
                    let mut bytes =
                        br#"{"metadata":{"resourceVersion":"12"},"items":[],"pad":""#.to_vec();
                    bytes.resize(bytes.len() + 9 * 1024 * 1024, b'x');
                    bytes.extend_from_slice(br#""}"#);
                    Bytes::from(bytes)
                })
                .clone();
            return Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(body))
                .unwrap();
        }
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"12"},"items":[tls_secret()]}),
        );
    }
    response(StatusCode::NOT_FOUND, "not found")
}

fn handle_capacity(path: &str, query: &str, state: &ApiState) -> Response<Full<Bytes>> {
    let second = ingress_in("blue", "second", "40", "second.example.test", &["/"], None);
    let third = ingress_in("blue", "third", "42", "third.example.test", &["/"], None);
    let stuck = matches!(state.mode, Mode::CapacityStuck);
    if query.contains("watch=true") {
        if path.ends_with("/ingresses") {
            let attempt = state.ingress_watches.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                return stream(vec![
                    event("ADDED", second),
                    event("DELETED", ingress_at("41", None)),
                ]);
            }
            if stuck && attempt == 1 {
                // Resumes from the last observed version (41), so the
                // controller must not have thrown its cache away.
                assert!(query.contains("resourceVersion=41"), "{query}");
                return stream(vec![event("ADDED", third)]);
            }
        }
        return response(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    }
    if path.ends_with("/services") {
        state.service_lists.fetch_add(1, Ordering::SeqCst);
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"10"},"items":[service()]}),
        );
    }
    if path.ends_with("/ingresses") {
        let attempt = state.ingress_lists.fetch_add(1, Ordering::SeqCst);
        let items = if attempt == 0 {
            vec![ingress()]
        } else if stuck {
            // Still over the object cap: every recovery relist fails.
            vec![second, third]
        } else {
            vec![second]
        };
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":format!("{}", 11 + attempt * 40)},"items":items}),
        );
    }
    response(StatusCode::NOT_FOUND, "not found")
}

fn handle_full_channel(path: &str, query: &str, state: &ApiState) -> Response<Full<Bytes>> {
    if query.contains("watch=true") {
        if path.ends_with("/services") {
            if state.service_watches.fetch_add(1, Ordering::SeqCst) == 0 {
                let events: Vec<serde_json::Value> = (0..300)
                    .map(|index| {
                        let mut object = service();
                        object["metadata"]["resourceVersion"] = format!("{}", 100 + index).into();
                        object["spec"]["ports"][0]["port"] = 8081.into();
                        event("MODIFIED", object)
                    })
                    .collect();
                return stream(events);
            }
            return response(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
        }
        state.ingress_watches.fetch_add(1, Ordering::SeqCst);
        return response(StatusCode::OK, "");
    }
    if path.ends_with("/services") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"10"},"items":[service()]}),
        );
    }
    if path.ends_with("/ingresses") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"11"},"items":[ingress()]}),
        );
    }
    response(StatusCode::NOT_FOUND, "not found")
}

fn handle_conflict(path: &str, query: &str, state: &ApiState) -> Response<Full<Bytes>> {
    if query.contains("watch=true") {
        if path.ends_with("/ingresses") {
            state.ingress_watches.fetch_add(1, Ordering::SeqCst);
            return response(StatusCode::OK, "");
        }
        return response(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    }
    if path.ends_with("/services") {
        state.service_lists.fetch_add(1, Ordering::SeqCst);
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"10"},"items":[service()]}),
        );
    }
    if path.ends_with("/ingresses") {
        return json(
            StatusCode::OK,
            serde_json::json!({"metadata":{"resourceVersion":"11"},"items":[ingress()]}),
        );
    }
    response(StatusCode::NOT_FOUND, "not found")
}

/// The observed `resourceVersion` 11 is stale (another writer moved the
/// object to 12); a patch against the refreshed version succeeds.
fn handle_conflict_patch(body: &[u8]) -> Response<Full<Bytes>> {
    let patch: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    match patch["metadata"]["resourceVersion"].as_str() {
        Some("11") => json(
            StatusCode::CONFLICT,
            serde_json::json!({"kind":"Status","code":409,"reason":"Conflict"}),
        ),
        Some("12") => json(
            StatusCode::OK,
            ingress_at("13", Some(serde_json::json!({"ip":"192.0.2.1"}))),
        ),
        _ => response(StatusCode::INTERNAL_SERVER_ERROR, "unexpected patch"),
    }
}

fn response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
        .unwrap()
}
fn json(status: StatusCode, body: serde_json::Value) -> Response<Full<Bytes>> {
    response(status, &format!("{}\n", body))
}
fn stream(events: Vec<serde_json::Value>) -> Response<Full<Bytes>> {
    let mut body = String::new();
    for event in events {
        body.push_str(&event.to_string());
        body.push('\n');
    }
    response(StatusCode::OK, &body)
}
fn event(action: &str, object: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"type":action,"object":object})
}
fn service() -> serde_json::Value {
    service_in("blue")
}
fn service_in(namespace: &str) -> serde_json::Value {
    serde_json::json!({"apiVersion":"v1","kind":"Service","metadata":{"name":"api","namespace":namespace,"resourceVersion":"10"},"spec":{"ports":[{"name":"web","port":8080}]}})
}
fn ingress() -> serde_json::Value {
    ingress_at("11", None)
}
fn ingress_at(rv: &str, status: Option<serde_json::Value>) -> serde_json::Value {
    let mut object = ingress_in(
        "blue",
        "main",
        rv,
        "api.example.test",
        &["/"],
        Some("api-tls"),
    );
    if let Some(address) = status {
        object["status"] = serde_json::json!({"loadBalancer":{"ingress":[address]}});
    }
    object
}
/// Stamp the API-server facts that decide hostname ownership.
fn aged(mut object: serde_json::Value, created: &str, uid: &str) -> serde_json::Value {
    object["metadata"]["creationTimestamp"] = created.into();
    object["metadata"]["uid"] = uid.into();
    object
}
/// Stamp the API-server facts that identify one incarnation of an object.
fn identified(mut object: serde_json::Value, uid: &str, generation: u64) -> serde_json::Value {
    object["metadata"]["uid"] = uid.into();
    object["metadata"]["generation"] = generation.into();
    object
}
fn ingress_in(
    namespace: &str,
    name: &str,
    rv: &str,
    host: &str,
    paths: &[&str],
    tls_secret: Option<&str>,
) -> serde_json::Value {
    let paths: Vec<serde_json::Value> = paths
        .iter()
        .map(|path| serde_json::json!({"path":path,"pathType":"Prefix","backend":{"service":{"name":"api","port":{"name":"web"}}}}))
        .collect();
    let mut object = serde_json::json!({"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"name":name,"namespace":namespace,"resourceVersion":rv},"spec":{"ingressClassName":"hangang","rules":[{"host":host,"http":{"paths":paths}}]}});
    if let Some(secret) = tls_secret {
        object["spec"]["tls"] = serde_json::json!([{"hosts":[host],"secretName":secret}]);
    }
    object
}
fn tls_secret() -> serde_json::Value {
    let pair = rcgen::generate_simple_self_signed(vec!["api.example.test".into()]).unwrap();
    secret_in(
        "blue",
        "api-tls",
        &pair.cert.pem(),
        &pair.signing_key.serialize_pem(),
    )
}
fn secret_in(namespace: &str, name: &str, cert_pem: &str, key_pem: &str) -> serde_json::Value {
    use base64::Engine as _;
    serde_json::json!({"apiVersion":"v1","kind":"Secret","type":"kubernetes.io/tls","metadata":{"name":name,"namespace":namespace,"resourceVersion":"12"},"data":{"tls.crt":base64::engine::general_purpose::STANDARD.encode(cert_pem),"tls.key":base64::engine::general_purpose::STANDARD.encode(key_pem)}})
}
