//! Request-path cost of decision capture.
//!
//! A counting global allocator proves the capture/finish path allocates
//! nothing, both when decision events are off and when they are on (kept,
//! sampled out, bucket-suppressed or dropped on a full ring). The timing test
//! prints per-request overhead; debug builds overstate it, so its bound is
//! only a regression guard. Run with `--nocapture` to see the numbers.

use hangang::decision::{self, Capture, Emitter, Reason, Stage};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

struct Counting;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACKING.with(Cell::get) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if TRACKING.with(Cell::get) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocations(f: impl FnOnce()) -> usize {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    TRACKING.with(|t| t.set(true));
    f();
    TRACKING.with(|t| t.set(false));
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

fn runtime(id: &str) -> Arc<hangang::config::HttpRuntime> {
    let config: hangang::config::Config = serde_json::from_value(serde_json::json!({
        "revision": 3,
        "http": [{"id": id, "hosts": ["app.example.test"], "path_prefix": "/",
                  "backends": ["http://127.0.0.1:9"]}]
    }))
    .unwrap();
    hangang::config::Snapshot::new(config).unwrap().http[0].clone()
}

fn emitter(dir: &tempfile::TempDir, extra: serde_json::Value) -> Arc<Emitter> {
    let mut config = serde_json::json!({
        "profile": "standard",
        "exporter_socket": dir.path().join("ingest.sock"),
        "key_file": dir.path().join("keys.json"),
        "manage_keys": true,
        "rings": {"shards": 1, "deny_slots": 64, "allow_slots": 64},
    });
    for (key, value) in extra.as_object().unwrap() {
        config[key] = value.clone();
    }
    Emitter::new(serde_json::from_value(config).unwrap())
        .unwrap()
        .unwrap()
}

/// The stage writes a protected request performs in the proxy.
fn record(capture: &mut Capture, route: &Arc<hangang::config::HttpRuntime>, deny: bool) {
    capture.client("198.51.100.7".parse().unwrap());
    capture.country(Some("KR"));
    capture.route(route);
    let started = capture.clock();
    capture.identity(decision::Identity {
        authority: decision::IdentityAuthority::Hopae,
        verdict: decision::IdentityVerdict::Authenticated,
        principal: decision::Principal::Human,
        aal: Some(2),
        factor: decision::FactorKind::Federated,
        subject: capture
            .active()
            .then(|| decision::Subject::new(b"u_example_subject")),
        latency_us: decision::elapsed_us(started),
        transport: decision::Transport::Hop1,
    });
    capture.authorization(
        if deny {
            decision::Authorization::ClassDenied
        } else {
            decision::Authorization::Allow
        },
        Some(77),
        started,
        decision::Transport::Grpc,
    );
    if deny {
        capture.refuse(
            Stage::Authorization,
            Reason::Pumgye(decision::Authorization::ClassDenied),
        );
    } else {
        capture.forwarded();
    }
}

#[test]
fn request_path_never_allocates_disabled_or_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let route = runtime("app");
    // Off: no emitter exists; the proxy uses an inactive capture.
    let off = allocations(|| {
        for _ in 0..1000 {
            let mut capture = Capture::disabled();
            record(&mut capture, &route, true);
            std::hint::black_box(&capture);
        }
    });
    assert_eq!(off, 0, "disabled capture allocated");

    // On: kept denies, bucket-suppressed denies, kept and sampled-out allows,
    // and drops on a full ring. All allocation-free and non-blocking.
    let on = emitter(
        &dir,
        serde_json::json!({"deny_bucket": {"burst": 10, "refill_per_second": 1.0, "window_seconds": 60}}),
    );
    // Warm thread-local shard selection outside the measurement.
    on.finish(Capture::disabled(), 200);
    let enabled = allocations(|| {
        for i in 0..2000 {
            let mut capture = on.capture(&hyper::Method::GET, 3);
            record(&mut capture, &route, i % 2 == 0);
            on.finish(capture, if i % 2 == 0 { 403 } else { 200 });
        }
    });
    assert_eq!(enabled, 0, "enabled capture/finish allocated");
    let c = &on.counters;
    assert_eq!(c.kept_deny.load(Ordering::Relaxed), 10);
    assert_eq!(c.suppressed.load(Ordering::Relaxed), 990);
    assert_eq!(
        c.kept_allow.load(Ordering::Relaxed) + c.sampled_out.load(Ordering::Relaxed),
        1000
    );

    // Full rings drop and count without allocating or waiting.
    let full = emitter(
        &tempfile::tempdir().unwrap(),
        serde_json::json!({
            "allow_sample_percent": 100.0,
            "rings": {"shards": 1, "deny_slots": 1, "allow_slots": 1}
        }),
    );
    full.finish(Capture::disabled(), 200);
    let dropped = allocations(|| {
        for _ in 0..500 {
            let mut capture = full.capture(&hyper::Method::GET, 3);
            record(&mut capture, &route, false);
            full.finish(capture, 200);
        }
    });
    assert_eq!(dropped, 0);
    assert_eq!(
        full.counters.dropped_ring_allow.load(Ordering::Relaxed),
        499
    );
}

#[test]
fn per_request_overhead_is_bounded() {
    const N: u32 = 200_000;
    let dir = tempfile::tempdir().unwrap();
    let route = runtime("app");
    let measure = |label: &str, f: &mut dyn FnMut(u32)| {
        for i in 0..1000 {
            f(i);
        }
        let started = Instant::now();
        for i in 0..N {
            f(i);
        }
        let ns = started.elapsed().as_nanos() as f64 / f64::from(N);
        // Per-call distribution (includes ~20 ns of clock reads).
        let mut samples = Vec::with_capacity(20_000);
        for i in 0..20_000 {
            let t = Instant::now();
            f(i);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        samples.sort_unstable();
        let p50 = samples[samples.len() / 2];
        let p99 = samples[samples.len() * 99 / 100];
        println!("decision overhead {label}: {ns:.0} ns/request mean, p50 {p50} ns, p99 {p99} ns");
        ns
    };
    let off = measure("off (inactive capture)", &mut |_| {
        let mut capture = Capture::disabled();
        record(&mut capture, &route, true);
        std::hint::black_box(capture);
    });
    let on = emitter(
        &dir,
        serde_json::json!({"rings": {"shards": 1, "deny_slots": 8192, "allow_slots": 4096}}),
    );
    let allow = measure("on, allow at 1% sampling", &mut |_| {
        let mut capture = on.capture(&hyper::Method::GET, 3);
        record(&mut capture, &route, false);
        on.finish(capture, 200);
    });
    let mut sink = Vec::new();
    let suppressed = measure("on, deny suppressed by bucket", &mut |_| {
        let mut capture = on.capture(&hyper::Method::GET, 3);
        record(&mut capture, &route, true);
        on.finish(capture, 403);
    });
    let kept_dir = tempfile::tempdir().unwrap();
    let kept = emitter(
        &kept_dir,
        serde_json::json!({
            "rings": {"shards": 1, "deny_slots": 8192, "allow_slots": 4096},
            "deny_bucket": {"burst": 10000, "refill_per_second": 10000.0, "window_seconds": 60}
        }),
    );
    let deny = measure("on, deny kept (bucket + ring push)", &mut |i| {
        let mut capture = kept.capture(&hyper::Method::GET, 3);
        record(&mut capture, &route, true);
        kept.finish(capture, 403);
        if i % 4096 == 0 {
            sink.clear();
            kept.rings.pop_batch(usize::MAX, &mut sink);
        }
    });
    // Drain-side cost per kept event (pseudonymize, seal, encode): off the
    // request path, but part of the CPU budget.
    let rng = ring::rand::SystemRandom::new();
    decision::drain::KeyKeeper::new().tick(&kept, &rng, true);
    let keys = kept.keys.load_full();
    let cx = decision::drain::Context {
        keys: &keys,
        profile: kept.profile(),
        instance: "gw-a",
        build: "0.3.11",
        rng: &rng,
    };
    sink.clear();
    kept.rings.pop_batch(usize::MAX, &mut sink);
    for _ in 0..4096 {
        let mut capture = kept.capture(&hyper::Method::GET, 3);
        record(&mut capture, &route, true);
        kept.finish(capture, 403);
    }
    sink.clear();
    kept.rings.pop_batch(usize::MAX, &mut sink);
    assert!(!sink.is_empty());
    let started = Instant::now();
    let mut bytes = 0usize;
    for record in &sink {
        bytes += decision::drain::encode(record, &cx).unwrap().len();
    }
    let encode = started.elapsed().as_nanos() as f64 / sink.len() as f64;
    println!(
        "decision drain encode (standard profile): {encode:.0} ns/event, {} bytes/event",
        bytes / sink.len()
    );
    assert!(suppressed < 20_000.0, "suppressed path {suppressed} ns");
    // Regression guard only: unoptimized builds are several times slower
    // than release, and the budget (<=5 us p99 added) is for release.
    assert!(off < 2_000.0, "off path {off} ns");
    assert!(allow < 20_000.0, "allow path {allow} ns");
    assert!(deny < 20_000.0, "deny path {deny} ns");
}
