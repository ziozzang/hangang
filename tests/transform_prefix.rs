use bytes::Bytes;
use hangang::{
    proxy::Body,
    transform::BodyTransform,
    transform_body::{TransformError, probe_prefix},
};
use http_body_util::{BodyExt, StreamBody};
use hyper::{HeaderMap, body::Frame};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Semaphore;
fn config(prefix: &str) -> BodyTransform {
    serde_json::from_value(
        json!({"when_prefix":prefix,"max_buffer_bytes":16,"max_output_bytes":16,"timeout_ms":100}),
    )
    .unwrap()
}
fn body(frames: Vec<Frame<Bytes>>) -> Body {
    StreamBody::new(futures_util::stream::iter(
        frames.into_iter().map(Ok::<_, std::convert::Infallible>),
    ))
    .map_err(|never| match never {})
    .boxed_unsync()
}
#[test]
fn generic_prefix_is_literal_bounded_and_buffered_only() {
    for value in [
        json!({"when_prefix":""}),
        json!({"when_prefix":"x".repeat(1025)}),
        json!({"when_prefix":"x","mode":"ndjson"}),
    ] {
        let cfg: BodyTransform = serde_json::from_value(value).unwrap();
        assert!(cfg.validate().is_err());
    }
    config(" \n\0 ").validate().unwrap();
    assert!(
        serde_json::to_value(BodyTransform::default())
            .unwrap()
            .get("when_prefix")
            .is_none()
    );
}
#[tokio::test]
async fn prefix_fragmentation_and_trailers_are_preserved_on_match_and_mismatch() {
    for (prefix, matched) in [("abcdef", true), ("abcxyz", false), ("abcdef-more", false)] {
        let limit = Arc::new(Semaphore::new(1));
        let mut trailer = HeaderMap::new();
        trailer.insert("x-fixture", "safe".parse().unwrap());
        let mut frames: Vec<_> = b"abcdef"
            .iter()
            .map(|b| Frame::data(Bytes::copy_from_slice(&[*b])))
            .collect();
        frames.push(Frame::trailers(trailer));
        let (output, actual) = probe_prefix(
            body(frames),
            &config(prefix),
            Arc::new(limit.clone().acquire_owned().await.unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(actual, matched);
        let output = output.collect().await.unwrap();
        assert_eq!(output.trailers().unwrap()["x-fixture"], "safe");
        assert_eq!(output.to_bytes(), b"abcdef"[..]);
        assert_eq!(limit.available_permits(), 1);
    }
}
#[tokio::test]
async fn unrelated_large_response_probes_one_frame_and_streams_without_buffer_limit() {
    let polled = Arc::new(AtomicUsize::new(0));
    let counter = polled.clone();
    let chunk = Bytes::from(vec![b'x'; 1024 * 1024]);
    let input = chunk.clone();
    let stream = futures_util::stream::iter((0..3).map(move |_| {
        counter.fetch_add(1, Ordering::Relaxed);
        Ok::<_, std::convert::Infallible>(Frame::data(input.clone()))
    }));
    let limit = Arc::new(Semaphore::new(1));
    let source = StreamBody::new(stream)
        .map_err(|never| match never {})
        .boxed_unsync();
    let (mut output, matched) = probe_prefix(
        source,
        &config("selected"),
        Arc::new(limit.clone().acquire_owned().await.unwrap()),
    )
    .await
    .unwrap();
    assert!(!matched);
    assert_eq!(polled.load(Ordering::Relaxed), 1);
    let mut total = 0;
    while let Some(frame) = output.frame().await {
        let data = frame.unwrap().into_data().unwrap();
        assert_eq!(data, chunk);
        total += data.len();
    }
    assert_eq!(total, 3 * 1024 * 1024);
    drop(output);
    assert_eq!(limit.available_permits(), 1);
}
#[tokio::test]
async fn stalled_or_empty_frame_flood_cannot_escape_prefix_deadline() {
    for empty in [false, true] {
        let source: Body = if empty {
            StreamBody::new(futures_util::stream::repeat_with(|| {
                Ok::<_, std::convert::Infallible>(Frame::data(Bytes::new()))
            }))
            .map_err(|never| match never {})
            .boxed_unsync()
        } else {
            StreamBody::new(futures_util::stream::pending::<
                Result<Frame<Bytes>, std::convert::Infallible>,
            >())
            .map_err(|never| match never {})
            .boxed_unsync()
        };
        let limit = Arc::new(Semaphore::new(1));
        let mut cfg = config("selected");
        cfg.timeout_ms = 20;
        assert!(matches!(
            probe_prefix(
                source,
                &cfg,
                Arc::new(limit.clone().acquire_owned().await.unwrap())
            )
            .await,
            Err(TransformError::Timeout)
        ));
        assert_eq!(limit.available_permits(), 1);
    }
}
#[tokio::test]
async fn dropping_probed_body_releases_budget_without_background_tasks() {
    let limit = Arc::new(Semaphore::new(1));
    let (output, matched) = probe_prefix(
        body(vec![Frame::data(Bytes::from_static(b"selected-body"))]),
        &config("selected"),
        Arc::new(limit.clone().acquire_owned().await.unwrap()),
    )
    .await
    .unwrap();
    assert!(matched);
    assert_eq!(limit.available_permits(), 0);
    drop(output);
    assert_eq!(limit.available_permits(), 1);
}
