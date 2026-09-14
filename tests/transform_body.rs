use bytes::Bytes;
use hangang::{
    metrics::Metrics,
    policy::{PolicyPool, TransformInput},
    proxy::Body,
    transform::BodyTransform,
    transform_body::{TransformError, transform},
};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use serde_json::json;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Semaphore;

fn config(value: serde_json::Value) -> Arc<BodyTransform> {
    let config: BodyTransform = serde_json::from_value(value).unwrap();
    config.validate().unwrap();
    Arc::new(config)
}
fn chunks(parts: Vec<Vec<u8>>) -> Body {
    StreamBody::new(futures_util::stream::iter(parts.into_iter().map(|part| {
        Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from(part)))
    })))
    .map_err(|never| match never {})
    .boxed_unsync()
}
fn pool() -> Arc<PolicyPool> {
    Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1))
}
async fn run(parts: Vec<Vec<u8>>, cfg: Arc<BodyTransform>) -> anyhow::Result<Vec<u8>> {
    let policy = pool();
    let limit = Arc::new(Semaphore::new(1));
    let body = transform(
        chunks(parts),
        cfg,
        policy.clone(),
        "response",
        Arc::new(limit.clone().acquire_owned().await?),
        Arc::new(Metrics::default()),
    )
    .await?;
    let result = body.collect().await.map(|v| v.to_bytes().to_vec());
    policy.shutdown().await;
    assert_eq!(limit.available_permits(), 1);
    Ok(result?)
}

#[tokio::test]
async fn ndjson_every_byte_boundary_utf8_crlf_and_final_record() {
    let input = "{\"secret\":\"비밀\",\"n\":1}\r\n{\"secret\":\"x\",\"n\":2}".as_bytes();
    let cfg = config(
        json!({"mode":"ndjson","operations":[{"op":"json_remove","pointer":"/secret"},{"op":"json_set","pointer":"/ok","value":true}]}),
    );
    for split in 0..=input.len() {
        let output = run(
            vec![input[..split].to_vec(), input[split..].to_vec()],
            cfg.clone(),
        )
        .await
        .unwrap();
        let values: Vec<serde_json::Value> = output
            .split(|b| *b == b'\n')
            .map(|v| serde_json::from_slice(v).unwrap())
            .collect();
        assert_eq!(
            values,
            vec![json!({"n":1,"ok":true}), json!({"n":2,"ok":true})]
        );
    }
}

#[tokio::test]
async fn sse_every_byte_boundary_cr_lf_multiline_comments_and_bom() {
    let input="\u{feff}: heartbeat\r\nid: 7\revent: update\r\ndata: {\"message\":\"한강\",\r\ndata: \"secret\":true}\r\n\r\n: keepalive\n\n".as_bytes();
    let cfg = config(json!({"mode":"sse","operations":[{"op":"json_remove","pointer":"/secret"}]}));
    for split in 0..=input.len() {
        let output = run(
            vec![input[..split].to_vec(), input[split..].to_vec()],
            cfg.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            ": heartbeat\nid: 7\nevent: update\ndata: {\"message\":\"한강\"}\n\n: keepalive\n\n"
        );
    }
}

#[tokio::test]
async fn line_replacement_crosses_chunks_without_joining_records() {
    let output = run(
        vec![b"sec".to_vec(), b"ret\r".to_vec(), b"\nsecret".to_vec()],
        config(
            json!({"mode":"lines","operations":[{"op":"replace","from":"secret","to":"redacted"}]}),
        ),
    )
    .await
    .unwrap();
    assert_eq!(output, b"redacted\nredacted");
}

#[tokio::test]
async fn input_output_limits_malformed_records_and_incomplete_sse_fail() {
    for (input, cfg) in [
        (
            b"12345\n".to_vec(),
            json!({"mode":"lines","max_buffer_bytes":4}),
        ),
        (b"12345".to_vec(), json!({"max_buffer_bytes":4})),
        (
            b"x".to_vec(),
            json!({"max_output_bytes":4,"operations":[{"op":"replace","from":"x","to":"12345"}]}),
        ),
        (b"{}\ninvalid\n".to_vec(), json!({"mode":"ndjson"})),
        (b"data: incomplete\n".to_vec(), json!({"mode":"sse"})),
        (b"data: incomplete".to_vec(), json!({"mode":"sse"})),
        (b"data: \xff\n\n".to_vec(), json!({"mode":"sse"})),
    ] {
        assert!(run(vec![input], config(cfg)).await.is_err());
    }
    assert_eq!(
        run(
            vec![b"1234\n".to_vec()],
            config(json!({"mode":"lines","max_buffer_bytes":4}))
        )
        .await
        .unwrap(),
        b"1234\n"
    );
}

#[tokio::test]
async fn bounded_record_timeout_and_drop_release_capacity() {
    for mode in ["buffered", "lines", "sse"] {
        let limit = Arc::new(Semaphore::new(1));
        let policy = pool();
        let metrics = Arc::new(Metrics::default());
        let body = StreamBody::new(futures_util::stream::pending::<
            Result<Frame<Bytes>, std::convert::Infallible>,
        >())
        .map_err(|never| match never {})
        .boxed_unsync();
        let result = transform(
            body,
            config(json!({"mode":mode,"timeout_ms":20})),
            policy.clone(),
            "response",
            Arc::new(limit.clone().acquire_owned().await.unwrap()),
            metrics.clone(),
        )
        .await;
        match result {
            Ok(body) => assert!(
                tokio::time::timeout(Duration::from_secs(1), body.collect())
                    .await
                    .unwrap()
                    .is_err()
            ),
            Err(error) => assert_eq!(error.status(false), 504),
        }
        assert_eq!(limit.available_permits(), 1);
        assert_eq!(metrics.body_transform_errors.load(Ordering::Relaxed), 1);
        policy.shutdown().await;
    }
}

#[tokio::test]
async fn demand_driven_stream_does_not_poll_ahead_and_drop_releases_permit() {
    let polls = Arc::new(AtomicUsize::new(0));
    let counted = polls.clone();
    let stream = futures_util::stream::iter((0..10000).map(move |_| {
        counted.fetch_add(1, Ordering::Relaxed);
        Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from_static(b"record\n")))
    }));
    let source = StreamBody::new(stream)
        .map_err(|never| match never {})
        .boxed_unsync();
    let limit = Arc::new(Semaphore::new(1));
    let policy = pool();
    let mut body = transform(
        source,
        config(json!({"mode":"lines"})),
        policy.clone(),
        "response",
        Arc::new(limit.clone().acquire_owned().await.unwrap()),
        Arc::new(Metrics::default()),
    )
    .await
    .unwrap();
    assert_eq!(polls.load(Ordering::Relaxed), 0);
    assert_eq!(
        body.frame().await.unwrap().unwrap().into_data().unwrap(),
        b"record\n"[..]
    );
    assert_eq!(polls.load(Ordering::Relaxed), 1);
    assert_eq!(limit.available_permits(), 0);
    drop(body);
    assert_eq!(limit.available_permits(), 1);
    policy.shutdown().await;
}

#[tokio::test]
async fn transformed_trailers_are_dropped() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("digest", "obsolete".parse().unwrap());
    let frames = vec![
        Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from_static(b"test\n"))),
        Ok(Frame::trailers(headers)),
    ];
    let body = StreamBody::new(futures_util::stream::iter(frames))
        .map_err(|never| match never {})
        .boxed_unsync();
    let policy = pool();
    let limit = Arc::new(Semaphore::new(1));
    let body = transform(
        body,
        config(json!({"mode":"lines"})),
        policy.clone(),
        "response",
        Arc::new(limit.acquire_owned().await.unwrap()),
        Arc::new(Metrics::default()),
    )
    .await
    .unwrap();
    let collected = body.collect().await.unwrap();
    assert!(collected.trailers().is_none());
    assert_eq!(collected.to_bytes(), b"test\n"[..]);
    policy.shutdown().await;
}

#[tokio::test]
async fn lua_json_and_sse_sentinel_transform_in_actual_workers() {
    let lua = "if hangang.body() == '[DONE]' then return '[DONE]' end; local value = hangang.json_decode(hangang.body()); value.secret = nil; value.phase = hangang.phase(); return hangang.json_encode(value)";
    let output = run(
        vec![b"data: {\"secret\":true}\n\ndata: [DONE]\n\n".to_vec()],
        config(json!({"mode":"sse","lua":lua,"max_buffer_bytes":16384,"max_output_bytes":16384})),
    )
    .await
    .unwrap();
    assert_eq!(
        output,
        b"data: {\"phase\":\"response\"}\n\ndata: [DONE]\n\n"
    );
}

#[tokio::test]
async fn large_stream_exceeds_buffer_limit_overall_but_each_record_stays_bounded() {
    const RECORDS: usize = 21000;
    let input = format!("{{\"payload\":\"{}\",\"secret\":true}}\n", "x".repeat(1024));
    let source = Bytes::from(input);
    let frames =
        (0..RECORDS).map(move |_| Ok::<_, std::convert::Infallible>(Frame::data(source.clone())));
    let body = StreamBody::new(futures_util::stream::iter(frames))
        .map_err(|never| match never {})
        .boxed_unsync();
    let policy = pool();
    let limit = Arc::new(Semaphore::new(1));
    let mut output = transform(body,config(json!({"mode":"ndjson","max_buffer_bytes":2048,"max_output_bytes":2048,"operations":[{"op":"json_remove","pointer":"/secret"}]})),policy.clone(),"response",Arc::new(limit.clone().acquire_owned().await.unwrap()),Arc::new(Metrics::default())).await.unwrap();
    let mut records = 0;
    let mut bytes = 0;
    while let Some(frame) = output.frame().await {
        let data = frame.unwrap().into_data().unwrap();
        assert!(data.len() <= 2049);
        let value: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert!(value.get("secret").is_none());
        records += 1;
        bytes += data.len();
    }
    assert_eq!(records, RECORDS);
    assert!(bytes > 20 * 1024 * 1024);
    drop(output);
    assert_eq!(limit.available_permits(), 1);
    policy.shutdown().await;
}

#[tokio::test]
async fn lua_can_shrink_a_large_input_to_a_smaller_output_budget() {
    let output = run(
        vec![vec![b'x'; 4096]],
        config(json!({"lua":"return 'ok'","max_buffer_bytes":16384,"max_output_bytes":2})),
    )
    .await
    .unwrap();
    assert_eq!(output, b"ok");
}

#[tokio::test]
async fn sse_field_count_and_metadata_expansion_are_bounded() {
    let many_lines = format!("{}\n", ":\n".repeat(1025));
    assert!(
        run(vec![many_lines.into_bytes()], config(json!({"mode":"sse"})))
            .await
            .is_err()
    );
    assert!(
        run(
            vec![b"id: 1\ndata: x\n\n".to_vec()],
            config(json!({"mode":"sse","max_output_bytes":8}))
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn exact_limit_crlf_records_allow_the_delimiter_across_all_splits() {
    for split in 0..=6 {
        let output = run(
            vec![b"1234\r\n"[..split].to_vec(), b"1234\r\n"[split..].to_vec()],
            config(json!({"mode":"lines","max_buffer_bytes":4})),
        )
        .await
        .unwrap();
        assert_eq!(output, b"1234\n");
    }
    assert!(
        run(
            vec![b"1234\r".to_vec()],
            config(json!({"mode":"lines","max_buffer_bytes":4}))
        )
        .await
        .is_err()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn buffered_deadline_includes_worker_execution_and_cancels_it() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let executable = dir.path().join("worker");
    std::fs::write(&executable,"#!/usr/bin/python3\nimport sys,struct,time,json\nn=struct.unpack('!I',sys.stdin.buffer.read(4))[0]\nsys.stdin.buffer.read(n)\ntime.sleep(0.1)\nb=json.dumps({'status':'transformed','data':'b2s='}).encode()\nsys.stdout.buffer.write(struct.pack('!I',len(b))+b)\nsys.stdout.buffer.flush()\n").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let policy = Arc::new(PolicyPool::new(executable, 1));
    let limit = Arc::new(Semaphore::new(1));
    let outcome=transform(chunks(vec![b"x".to_vec()]),config(json!({"lua":"return 'ok'","max_buffer_bytes":16384,"max_output_bytes":16384,"timeout_ms":20})),policy.clone(),"request",Arc::new(limit.clone().acquire_owned().await.unwrap()),Arc::new(Metrics::default())).await;
    assert!(matches!(
        outcome,
        Err(hangang::transform_body::TransformError::Timeout)
    ));
    assert_eq!(limit.available_permits(), 1);
    policy.shutdown().await;
}

#[tokio::test]
async fn midstream_errors_count_in_both_transform_and_general_metrics() {
    let metrics = Arc::new(Metrics::default());
    let policy = pool();
    let limit = Arc::new(Semaphore::new(1));
    let mut body = transform(
        chunks(vec![b"{}\nnot-json\n".to_vec()]),
        config(json!({"mode":"ndjson"})),
        policy.clone(),
        "response",
        Arc::new(limit.acquire_owned().await.unwrap()),
        metrics.clone(),
    )
    .await
    .unwrap();
    assert!(body.frame().await.unwrap().is_ok());
    assert!(body.frame().await.unwrap().is_err());
    assert_eq!(metrics.body_transform_errors.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.errors.load(Ordering::Relaxed), 1);
    policy.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn saturated_lua_transform_is_503_then_recovers_without_hiding_script_errors()
-> anyhow::Result<()> {
    use std::{os::unix::fs::PermissionsExt, path::Path};
    fn quote(path: &Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
    }
    let directory = tempfile::tempdir()?;
    let executable = directory.path().join("delayed-worker.sh");
    let marker = directory.path().join("first-worker");
    let ready = directory.path().join("first-worker-started");
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\nif [ ! -e {marker} ]; then\n  : > {marker}\n  : > {ready}\n  sleep 0.08\nfi\nexec {binary} --lua-worker\n",
            marker = quote(&marker),
            ready = quote(&ready),
            binary = quote(&std::path::PathBuf::from(env!("CARGO_BIN_EXE_hangang"))),
        ),
    )?;
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))?;
    let policy = Arc::new(PolicyPool::new(executable, 1));
    let occupied = {
        let policy = policy.clone();
        tokio::spawn(async move {
            policy
                .transform(TransformInput {
                    geoip: Default::default(),
                    script: "return 'held'".into(),
                    body: b"x".to_vec(),
                    phase: "response".into(),
                })
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await?;
    let budget = Arc::new(Semaphore::new(1));
    let lua = |script: &str| {
        config(json!({"lua":script,"max_buffer_bytes":16384,"max_output_bytes":16384}))
    };
    let overloaded = transform(
        chunks(vec![b"x".to_vec()]),
        lua("return 'ok'"),
        policy.clone(),
        "response",
        Arc::new(budget.clone().acquire_owned().await?),
        Arc::new(Metrics::default()),
    )
    .await
    .unwrap_err();
    assert!(matches!(overloaded, TransformError::PolicyBusy));
    assert_eq!(overloaded.status(false), 503);
    assert_eq!(budget.available_permits(), 1);
    assert_eq!(occupied.await??, b"held");

    let script_error = transform(
        chunks(vec![b"x".to_vec()]),
        lua("return 123"),
        policy.clone(),
        "response",
        Arc::new(budget.clone().acquire_owned().await?),
        Arc::new(Metrics::default()),
    )
    .await
    .unwrap_err();
    assert!(matches!(script_error, TransformError::Policy));
    assert_eq!(script_error.status(false), 502);

    let recovered = transform(
        chunks(vec![b"x".to_vec()]),
        lua("return 'ok'"),
        policy.clone(),
        "response",
        Arc::new(budget.clone().acquire_owned().await?),
        Arc::new(Metrics::default()),
    )
    .await?;
    assert_eq!(recovered.collect().await?.to_bytes(), b"ok".as_slice());
    policy.shutdown().await;
    Ok(())
}
