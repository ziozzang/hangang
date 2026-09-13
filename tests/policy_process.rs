use hangang::country_observation::{Observation, State};
use hangang::policy::{
    Decision, PolicyInput, PolicyPool, TransformInput, WorkerCapacityUnavailable,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

// Rust runs these test functions in parallel. One function can fork a worker
// while another still has its newly written interpreter script open for write;
// the forked process briefly inherits that descriptor and a concurrent exec
// of the script fails with ETXTBSY. Keep the fixture's fork/write lifetimes
// sequential; each test still exercises its own concurrent worker requests.
static FIXTURE_FORK_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hangang"))
}

fn input(script: &str) -> PolicyInput {
    PolicyInput {
        script: script.to_owned(),
        method: "GET".to_owned(),
        path: "/resource".to_owned(),
        headers: BTreeMap::from([("x-tenant".to_owned(), "blue".to_owned())]),
        geoip: Observation::default(),
    }
}

fn transform_input(script: &str, body: impl Into<Vec<u8>>, phase: &str) -> TransformInput {
    TransformInput {
        script: script.to_owned(),
        body: body.into(),
        phase: phase.to_owned(),
        geoip: Observation::default(),
    }
}

#[tokio::test]
async fn real_worker_transforms_binary_bodies_and_exposes_phase() -> anyhow::Result<()> {
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    let pool = PolicyPool::new(binary(), 1);
    let body = vec![0, 0xff, b'a'];
    let output = pool
        .transform(transform_input(
            r#"
                assert(hangang.phase() == "request")
                local body = hangang.body()
                assert(#body == 3 and string.byte(body, 1) == 0)
                hangang.set_body(body .. string.char(0, 254))
            "#,
            body.clone(),
            "request",
        ))
        .await?;
    assert_eq!(output, [body, vec![0, 0xfe]].concat());

    let output = pool
        .transform(transform_input(
            "hangang.set_body('ignored'); return hangang.body() .. '-response'",
            b"value".to_vec(),
            "response",
        ))
        .await?;
    assert_eq!(output, b"value-response");
    pool.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn real_worker_json_helpers_preserve_unicode_null_and_empty_arrays() -> anyhow::Result<()> {
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    let pool = PolicyPool::new(binary(), 1);
    let output = pool
        .transform(transform_input(
            r#"
                local value = hangang.json_decode(hangang.body())
                assert(value.missing == hangang.null)
                value.name = "한강"
                value.missing = hangang.null
                value.empty = hangang.array()
                value.items[2] = hangang.null
                return hangang.json_encode(value)
            "#,
            br#"{"missing":null,"items":[1,2]}"#.to_vec(),
            "response",
        ))
        .await?;
    let value: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        value,
        serde_json::json!({
            "empty": [],
            "items": [1, null],
            "missing": null,
            "name": "한강"
        })
    );

    assert_eq!(
        pool.transform(transform_input(
            "return hangang.json_encode(hangang.array())",
            Vec::new(),
            "request",
        ))
        .await?,
        b"[]"
    );
    assert_eq!(
        pool.transform(transform_input(
            "return hangang.json_encode(hangang.null)",
            Vec::new(),
            "request",
        ))
        .await?,
        b"null"
    );
    pool.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn transform_rejects_invalid_types_cycles_depth_and_limits() {
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    let pool = PolicyPool::new(binary(), 1);
    for script in [
        "return {}",
        "return hangang.json_encode(function() end)",
        "local t = {}; t.self = t; return hangang.json_encode(t)",
        "return hangang.json_encode(0 / 0)",
        "return hangang.json_encode(setmetatable({}, {}))",
        "return hangang.json_encode({value = string.rep('x', 16385)})",
        r#"
            local root, current = {}, {}
            root.child = current
            for i = 1, 70 do
                local next = {}
                current.child = next
                current = next
            end
            return hangang.json_encode(root)
        "#,
        "return string.rep('x', 16385)",
        "return hangang.json_encode(hangang.json_decode('{'))",
    ] {
        assert!(
            pool.transform(transform_input(script, Vec::new(), "request"))
                .await
                .is_err(),
            "script unexpectedly succeeded: {script}"
        );
    }
    assert!(
        pool.transform(transform_input(
            "return hangang.body()",
            vec![0; 16 * 1024 + 1],
            "request",
        ))
        .await
        .is_err()
    );
    assert!(
        pool.transform(transform_input(
            "return hangang.body()",
            Vec::new(),
            "upstream",
        ))
        .await
        .is_err()
    );
    pool.shutdown().await;
}

#[tokio::test]
async fn transform_vm_state_does_not_leak_and_failures_recover() -> anyhow::Result<()> {
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    let pool = PolicyPool::new(binary(), 1);
    assert_eq!(
        pool.transform(transform_input(
            "leaked = 'secret'; return hangang.body()",
            b"first".to_vec(),
            "request",
        ))
        .await?,
        b"first"
    );
    assert_eq!(
        pool.transform(transform_input(
            "assert(leaked == nil); return hangang.body()",
            b"second".to_vec(),
            "request",
        ))
        .await?,
        b"second"
    );

    assert!(
        pool.transform(transform_input("while true do end", Vec::new(), "request"))
            .await
            .is_err()
    );
    assert!(
        pool.transform(transform_input(
            "return string.rep('x', 10 * 1024 * 1024)",
            Vec::new(),
            "request",
        ))
        .await
        .is_err()
    );
    assert_eq!(
        pool.transform(transform_input(
            "return hangang.body() .. '-ok'",
            b"recovered".to_vec(),
            "response",
        ))
        .await?,
        b"recovered-ok"
    );
    pool.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn transform_maximum_binary_body_and_escape_heavy_script_fit_ipc_frame() -> anyhow::Result<()>
{
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    let pool = PolicyPool::new(binary(), 1);
    let prefix = "--[=[";
    let suffix = "]=]\nreturn hangang.body()";
    let script = format!(
        "{prefix}{}{suffix}",
        "\u{1}".repeat(16 * 1024 - prefix.len() - suffix.len())
    );
    assert_eq!(script.len(), 16 * 1024);
    let body: Vec<u8> = (0..16 * 1024).map(|n| (n % 256) as u8).collect();
    assert_eq!(
        pool.transform(transform_input(&script, body.clone(), "request"))
            .await?,
        body
    );
    pool.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn real_worker_evaluates_policy_and_is_reused() -> anyhow::Result<()> {
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    let pool = PolicyPool::new(binary(), 1);
    let script = r#"
        assert(hangang.method() == "GET")
        assert(hangang.path() == "/resource")
        assert(hangang.header("X-Tenant") == "blue")
        hangang.select_backend("primary")
        hangang.set_header("x-policy", "applied")
        hangang.reject(429)
    "#;

    let want = Decision {
        backend: Some("primary".to_owned()),
        member_id: None,
        headers: BTreeMap::from([("x-policy".to_owned(), "applied".to_owned())]),
        reject: Some(429),
    };
    assert_eq!(pool.evaluate(input(script)).await?, want);
    assert_eq!(
        pool.evaluate(input("return 'secondary'")).await?.backend,
        Some("secondary".to_owned())
    );
    pool.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn validation_compiles_without_executing() -> anyhow::Result<()> {
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    let pool = PolicyPool::new(binary(), 1);
    pool.validate("error('must not run during validation')")
        .await?;
    assert!(pool.validate("this is not lua (").await.is_err());
    assert!(
        pool.evaluate(input("return os.execute('id')"))
            .await
            .is_err()
    );
    pool.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn callback_arguments_and_source_size_are_checked() {
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    let pool = PolicyPool::new(binary(), 1);
    assert!(pool.evaluate(input("hangang.reject(200)")).await.is_err());
    assert!(
        pool.evaluate(input("hangang.set_header('bad header', 'x')"))
            .await
            .is_err()
    );
    assert!(pool.validate(&" ".repeat(16 * 1024 + 1)).await.is_err());
    pool.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn a_busy_single_worker_rejects_instead_of_queueing() -> anyhow::Result<()> {
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    let temp = tempfile::tempdir()?;
    let marker = temp.path().join("first-process");
    let ready = temp.path().join("request-started");
    let executable = delayed_worker(temp.path(), &marker, &ready, 0.12)?;
    let pool = Arc::new(PolicyPool::new(executable, 1));

    let occupied = {
        let pool = Arc::clone(&pool);
        tokio::spawn(async move { pool.evaluate(input("return 'occupied'")).await })
    };
    wait_for_file(&ready).await?;

    let started = Instant::now();
    let error = pool.evaluate(input("return 'queued'")).await.unwrap_err();
    assert!(error.is::<WorkerCapacityUnavailable>());
    assert!(started.elapsed() < Duration::from_millis(100));
    assert_eq!(occupied.await??.backend.as_deref(), Some("stale"));
    pool.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn cancelled_request_cannot_leave_a_stale_response() -> anyhow::Result<()> {
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    let temp = tempfile::tempdir()?;
    let marker = temp.path().join("first-process");
    let ready = temp.path().join("request-started");
    let executable = delayed_worker(temp.path(), &marker, &ready, 0.12)?;
    let pool = Arc::new(PolicyPool::new(executable, 1));

    let cancelled = {
        let pool = Arc::clone(&pool);
        tokio::spawn(async move { pool.evaluate(input("return 'cancelled'")).await })
    };
    wait_for_file(&ready).await?;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());

    tokio::time::sleep(Duration::from_millis(40)).await;
    let decision = pool.evaluate(input("return 'current'")).await?;
    assert_eq!(decision.backend.as_deref(), Some("fresh"));
    pool.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn cancelled_transform_cannot_leave_a_stale_response() -> anyhow::Result<()> {
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    let temp = tempfile::tempdir()?;
    let marker = temp.path().join("first-transform-process");
    let ready = temp.path().join("transform-started");
    let executable = delayed_worker(temp.path(), &marker, &ready, 0.12)?;
    let pool = Arc::new(PolicyPool::new(executable, 1));

    let cancelled = {
        let pool = Arc::clone(&pool);
        tokio::spawn(async move {
            pool.transform(transform_input(
                "return hangang.body()",
                b"cancelled".to_vec(),
                "request",
            ))
            .await
        })
    };
    wait_for_file(&ready).await?;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());

    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(
        pool.transform(transform_input(
            "return hangang.body()",
            b"current".to_vec(),
            "request",
        ))
        .await?,
        b"fresh"
    );
    pool.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn wrong_response_kind_retires_the_protocol_peer() -> anyhow::Result<()> {
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    let temp = tempfile::tempdir()?;
    let marker = temp.path().join("wrong-kind-sent");
    let executable = wrong_kind_worker(temp.path(), &marker, &binary())?;
    let pool = PolicyPool::new(executable, 1);

    let error = pool.evaluate(input("return 'ignored'")).await.unwrap_err();
    assert!(
        error.to_string().contains("wrong response kind"),
        "{error:#}"
    );

    tokio::time::sleep(Duration::from_millis(40)).await;
    let decision = pool.evaluate(input("return 'recovered'")).await?;
    assert_eq!(decision.backend.as_deref(), Some("recovered"));
    pool.shutdown().await;
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn killed_worker_is_restarted_for_a_later_request() -> anyhow::Result<()> {
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    use std::{fs, os::unix::fs::PermissionsExt};
    let temp = tempfile::tempdir()?;
    let wrapper = temp.path().join("owned-worker.sh");
    let marker = temp.path().join("owned-worker.pid");
    // Record this pool's own child. Searching all children of the test runner
    // can accidentally kill a different test's worker when tests run in parallel.
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nprintf '%s' \"$$\" > {}\nexec {} --lua-worker\n",
            shell_quote(&marker),
            shell_quote(&binary())
        ),
    )?;
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;
    let pool = PolicyPool::new(wrapper, 1);
    pool.evaluate(input("return 'before'")).await?;
    let child: u32 = fs::read_to_string(&marker)?.parse()?;
    let status = fs::read_to_string(format!("/proc/{child}/status"))?;
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
    assert!(status.lines().any(|line| line == "Seccomp:\t2"));
    // SAFETY: `child` is this test's live owned worker; kill takes no pointers.
    assert_eq!(
        unsafe { libc::kill(child as libc::pid_t, libc::SIGKILL) },
        0
    );
    tokio::time::sleep(Duration::from_millis(30)).await;

    assert_eq!(
        pool.evaluate(input("return 'after'")).await?.backend,
        Some("after".to_owned())
    );
    pool.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn parent_timeout_reaps_child_and_the_slot_recovers() -> anyhow::Result<()> {
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    use std::{fs, os::unix::fs::PermissionsExt};

    let temp = tempfile::tempdir()?;
    let wrapper = temp.path().join("worker-wrapper.sh");
    let marker = temp.path().join("first-run");
    let script = format!(
        "#!/bin/sh\nif [ ! -e {} ]; then\n  : > {}\n  exec /bin/sleep 5\nfi\nexec {} --lua-worker\n",
        shell_quote(&marker),
        shell_quote(&marker),
        shell_quote(&binary()),
    );
    fs::write(&wrapper, script)?;
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;

    let pool = PolicyPool::new(wrapper, 1);
    let started = Instant::now();
    assert!(pool.evaluate(input("return 'late'")).await.is_err());
    assert!(started.elapsed() < Duration::from_secs(2));

    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(
        pool.evaluate(input("return 'recovered'")).await?.backend,
        Some("recovered".to_owned())
    );
    pool.shutdown().await;
    Ok(())
}

#[cfg(unix)]
fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

#[cfg(unix)]
fn delayed_worker(
    directory: &Path,
    marker: &Path,
    ready: &Path,
    delay_seconds: f64,
) -> anyhow::Result<PathBuf> {
    use std::{fs, os::unix::fs::PermissionsExt};

    let executable = directory.join("delayed-worker.py");
    let marker = serde_json::to_string(&marker.display().to_string())?;
    let ready = serde_json::to_string(&ready.display().to_string())?;
    let source = format!(
        r#"#!/usr/bin/python3
import base64, json, os, struct, sys, time
marker = {marker}
ready = {ready}
first = not os.path.exists(marker)
if first:
    open(marker, "wb").close()
while True:
    size = sys.stdin.buffer.read(4)
    if not size:
        break
    length = struct.unpack(">I", size)[0]
    request = json.loads(sys.stdin.buffer.read(length))
    if request["op"] == "shutdown":
        response = {{"status": "validated"}}
    else:
        if first:
            open(ready, "wb").close()
            time.sleep({delay_seconds})
            first = False
            backend = "stale"
        else:
            backend = "fresh"
        if request["op"] == "transform":
            response = {{"status": "transformed", "data": base64.b64encode(backend.encode()).decode()}}
        else:
            response = {{"status": "decision", "data": {{"backend": backend, "headers": {{}}, "reject": None}}}}
    payload = json.dumps(response).encode()
    sys.stdout.buffer.write(struct.pack(">I", len(payload)) + payload)
    sys.stdout.buffer.flush()
    if request["op"] == "shutdown":
        break
"#
    );
    fs::write(&executable, source)?;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
    Ok(executable)
}

#[cfg(unix)]
fn wrong_kind_worker(directory: &Path, marker: &Path, real: &Path) -> anyhow::Result<PathBuf> {
    use std::{fs, os::unix::fs::PermissionsExt};

    let executable = directory.join("wrong-kind-worker.py");
    let marker = serde_json::to_string(&marker.display().to_string())?;
    let real = serde_json::to_string(&real.display().to_string())?;
    let source = format!(
        r#"#!/usr/bin/python3
import json, os, struct, sys, time
marker = {marker}
if os.path.exists(marker):
    os.execv({real}, [{real}, "--lua-worker"])
open(marker, "wb").close()
size = sys.stdin.buffer.read(4)
if size:
    length = struct.unpack(">I", size)[0]
    sys.stdin.buffer.read(length)
    payload = json.dumps({{"status": "validated"}}).encode()
    sys.stdout.buffer.write(struct.pack(">I", len(payload)) + payload)
    sys.stdout.buffer.flush()
    time.sleep(5)
"#
    );
    fs::write(&executable, source)?;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
    Ok(executable)
}

#[cfg(unix)]
async fn wait_for_file(path: &Path) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(1), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out waiting for delayed worker"))
}

#[tokio::test]
async fn shutdown_prevents_new_work() {
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    let pool = PolicyPool::new(binary(), 1);
    pool.shutdown().await;
    assert!(pool.evaluate(input("return 'no'")).await.is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn worker_syscall_policy_denies_files_network_and_executable_memory() {
    let _fixture = FIXTURE_FORK_LOCK.blocking_lock();
    let output = std::process::Command::new(binary())
        .arg("--lua-sandbox-check")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("worker syscall restrictions verified")
    );
}

#[tokio::test]
async fn member_selection_worker_is_bounded_and_last_selection_wins() -> anyhow::Result<()> {
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    let pool = PolicyPool::new(binary(), 1);
    for (script, member, backend) in [
        ("hangang.select_member('Blue-1')", Some("Blue-1"), None),
        (
            "hangang.select_backend('old'); hangang.select_member('green')",
            Some("green"),
            None,
        ),
        (
            "hangang.select_member('green'); hangang.select_backend('new')",
            None,
            Some("new"),
        ),
        (
            "hangang.select_member('green'); return 'returned'",
            None,
            Some("returned"),
        ),
        ("return nil", None, None),
    ] {
        let decision = pool.evaluate(input(script)).await?;
        assert_eq!(decision.member_id.as_deref(), member);
        assert_eq!(decision.backend.as_deref(), backend);
    }
    for id in [
        "",
        "_bad",
        "contains space",
        "한강",
        "a/b",
        "a\n",
        &"a".repeat(65),
    ] {
        let script = format!("hangang.select_member({})", serde_json::to_string(id)?);
        assert!(
            pool.evaluate(input(&script)).await.is_err(),
            "accepted invalid ID"
        );
        assert_eq!(
            pool.evaluate(input("hangang.select_member('recovered')"))
                .await?
                .member_id
                .as_deref(),
            Some("recovered")
        );
    }
    pool.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn geoip_userdata_is_read_only_and_identical_in_policy_and_body_workers() -> anyhow::Result<()>
{
    let _fixture = FIXTURE_FORK_LOCK.lock().await;
    let pool = PolicyPool::new(binary(), 1);
    let digest = "a".repeat(64);
    let known = Observation {
        state: State::Known,
        country: Some("GB".to_owned()),
        generation_sha256: Some(digest.clone()),
        error_code: None,
    };
    let mut request = input(
        r#"
            local geo = hangang.geoip()
            assert(geo.state == "known" and geo.country == "GB")
            assert(#geo.generation_sha256 == 64 and geo.error_code == nil)
            assert(hangang.header("x-client-country") == "ZZ")
            hangang.set_header("x-observed-country", geo.country)
        "#,
    );
    request
        .headers
        .insert("x-client-country".into(), "ZZ".into());
    request.geoip = known.clone();
    let decision = pool.evaluate(request.clone()).await?;
    assert_eq!(
        decision
            .headers
            .get("x-observed-country")
            .map(String::as_str),
        Some("GB")
    );

    for field in ["state", "country", "generation_sha256", "error_code"] {
        request.script = format!("hangang.geoip().{field} = 'spoofed'");
        assert!(
            pool.evaluate(request.clone()).await.is_err(),
            "{field} was writable"
        );
    }
    request.script = "assert(hangang.geoip().country == 'GB')".into();
    pool.evaluate(request).await?;

    for phase in ["request", "response"] {
        let mut transformed = transform_input(
            "local geo = hangang.geoip(); assert(geo.state == 'known'); return geo.country .. ':' .. hangang.phase() .. ':' .. hangang.body()",
            b"body".to_vec(),
            phase,
        );
        transformed.geoip = known.clone();
        assert_eq!(
            pool.transform(transformed).await?,
            format!("GB:{phase}:body").as_bytes()
        );
    }

    let unknown = Observation {
        state: State::Unknown,
        country: None,
        generation_sha256: Some(digest.clone()),
        error_code: None,
    };
    let mut request = input(
        "local geo = hangang.geoip(); assert(geo.state == 'unknown' and geo.country == nil and geo.generation_sha256 ~= nil)",
    );
    request.geoip = unknown;
    pool.evaluate(request).await?;
    let unavailable = Observation {
        state: State::Unavailable,
        country: None,
        generation_sha256: Some(digest),
        error_code: Some("invalid_record".to_owned()),
    };
    let mut request = input(
        "local geo = hangang.geoip(); assert(geo.state == 'unavailable' and geo.country == nil and geo.error_code == 'invalid_record')",
    );
    request.geoip = unavailable;
    pool.evaluate(request).await?;

    let malformed = Observation {
        state: State::Known,
        country: Some("ZZ".to_owned()),
        generation_sha256: None,
        error_code: None,
    };
    let mut request = input("return nil");
    request.geoip = malformed;
    assert!(pool.evaluate(request).await.is_err());
    assert!(
        serde_json::from_value::<Observation>(serde_json::json!({
            "state":"known", "country":"ZZ"
        }))
        .is_err()
    );
    pool.shutdown().await;
    Ok(())
}
