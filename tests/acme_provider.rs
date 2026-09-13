use anyhow::Result;
use bytes::Bytes;
use hangang::acme::{CloudflareDnsProvider, DnsProvider, DohTxtResolver, TxtResolver};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct State {
    value: Mutex<String>,
    deletes: AtomicUsize,
    lists: AtomicUsize,
    fail_delete: AtomicBool,
    oversized: AtomicBool,
    /// Delay before a presentation is committed and answered, so a client
    /// can give up while the remote side still creates the record.
    delay_present_ms: AtomicUsize,
}
async fn fixture() -> Result<(String, Arc<State>, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let state = Arc::new(State::default());
    let server = state.clone();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let state = server.clone();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |request| handle(request, state.clone())),
                    )
                    .await;
            });
        }
    });
    Ok((url, state, task))
}
async fn handle(
    request: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if request.uri().path() == "/dns-query" {
        if state.oversized.load(Ordering::Relaxed) {
            return Ok(Response::builder()
                .header("transfer-encoding", "chunked")
                .body(Full::new(Bytes::from(vec![b' '; 1024 * 1024 + 1])))
                .unwrap());
        }
        return Ok(Response::new(Full::new(Bytes::from(serde_json::json!({"Answer":[{"type":16,"data":"\"proof\""},{"type":1,"data":"127.0.0.1"}]}).to_string()))));
    }
    assert_eq!(
        request.headers().get("authorization").unwrap(),
        "Bearer fixture-only-token"
    );
    let method = request.method().clone();
    assert!(request.uri().path().starts_with("/zones/abc/dns_records"));
    let query = request.uri().query().map(str::to_owned);
    if method == hyper::Method::POST {
        let value: serde_json::Value =
            serde_json::from_slice(&request.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(value["type"], "TXT");
        assert_eq!(value["ttl"], 60);
        let delay = state.delay_present_ms.load(Ordering::Relaxed);
        let content = value["content"].as_str().unwrap().to_owned();
        if delay > 0 {
            // Commit independently of this connection: a client that gives up
            // early must not stop the remote side from creating the record.
            let committed = state.clone();
            let deferred = content.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay as u64)).await;
                *committed.value.lock().unwrap() = deferred;
            });
            tokio::time::sleep(Duration::from_millis(delay as u64)).await;
        } else {
            *state.value.lock().unwrap() = content;
        }
    }
    let response = if method == hyper::Method::DELETE {
        state.deletes.fetch_add(1, Ordering::Relaxed);
        serde_json::json!({"success":!state.fail_delete.load(Ordering::Relaxed),"result":{"id":"owned"}})
    } else if method == hyper::Method::GET
        && let Some(query) = query
    {
        // Listing filtered by name/content, as used for reconciliation.
        state.lists.fetch_add(1, Ordering::Relaxed);
        let wanted = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("content="))
            .unwrap_or("");
        let current = state.value.lock().unwrap().clone();
        let result = if !current.is_empty() && current == wanted {
            serde_json::json!([{"id":"owned","name":"_acme-challenge.example.test","content":current}])
        } else {
            serde_json::json!([])
        };
        serde_json::json!({"success":true,"result":result})
    } else {
        serde_json::json!({"success":true,"result":{"id":"owned","name":"_acme-challenge.example.test","content":state.value.lock().unwrap().clone()}})
    };
    Ok(Response::new(Full::new(Bytes::from(response.to_string()))))
}
#[tokio::test]
async fn cloudflare_cleanup_checks_remote_ownership_and_retains_failed_receipts() -> Result<()> {
    let (url, state, task) = fixture().await?;
    let resolver = Arc::new(DohTxtResolver::new(format!("{url}/dns-query")));
    let provider = CloudflareDnsProvider::with_resolver("abc", "fixture-only-token", resolver)
        .with_endpoint(url);
    let owned = provider
        .present("_acme-challenge.example.test", "proof")
        .await?;
    provider
        .wait_for_propagation(
            &owned.name,
            &owned.value,
            Duration::from_secs(1),
            Duration::from_millis(10),
            &CancellationToken::new(),
        )
        .await?;
    *state.value.lock().unwrap() = "changed-by-another-writer".into();
    assert!(provider.cleanup(owned.clone()).await.is_err());
    assert_eq!(state.deletes.load(Ordering::Relaxed), 0);
    *state.value.lock().unwrap() = "proof".into();
    state.fail_delete.store(true, Ordering::Relaxed);
    assert!(provider.cleanup(owned.clone()).await.is_err());
    state.fail_delete.store(false, Ordering::Relaxed);
    provider.cleanup(owned.clone()).await?;
    assert_eq!(state.deletes.load(Ordering::Relaxed), 2);
    assert!(provider.cleanup(owned).await.is_err());
    assert_eq!(state.deletes.load(Ordering::Relaxed), 2);
    task.abort();
    Ok(())
}
#[tokio::test]
async fn doh_answers_are_parsed_and_oversized_responses_are_rejected() -> Result<()> {
    let (url, state, task) = fixture().await?;
    let resolver = DohTxtResolver::new(format!("{url}/dns-query"));
    assert_eq!(
        resolver.txt_values("_acme-challenge.example.test").await?,
        vec!["proof"]
    );
    state.oversized.store(true, Ordering::Relaxed);
    assert!(
        resolver
            .txt_values("_acme-challenge.example.test")
            .await
            .is_err()
    );
    task.abort();
    Ok(())
}

#[tokio::test]
async fn deferred_cleanup_is_retried_with_bounded_backoff() -> Result<()> {
    let (url, state, task) = fixture().await?;
    let resolver = Arc::new(DohTxtResolver::new(format!("{url}/dns-query")));
    let provider = CloudflareDnsProvider::with_resolver("abc", "fixture-only-token", resolver)
        .with_endpoint(url)
        .with_cleanup_retry_backoff(Duration::from_millis(300));
    let cancel = CancellationToken::new();
    let owned = provider
        .present("_acme-challenge.example.test", "proof")
        .await?;
    // The engine's single cleanup attempt fails and queues the receipt.
    state.fail_delete.store(true, Ordering::Relaxed);
    assert!(provider.cleanup(owned.clone()).await.is_err());
    assert_eq!(state.deletes.load(Ordering::Relaxed), 1);
    provider.defer_cleanup(owned.clone()).await;
    // First retry runs immediately and fails again.
    provider.retry_deferred_cleanups(&cancel).await;
    assert_eq!(state.deletes.load(Ordering::Relaxed), 2);
    // Inside the backoff window nothing is retried.
    provider.retry_deferred_cleanups(&cancel).await;
    assert_eq!(state.deletes.load(Ordering::Relaxed), 2);
    // After the backoff the retry succeeds and releases the receipt.
    state.fail_delete.store(false, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(700)).await;
    provider.retry_deferred_cleanups(&cancel).await;
    assert_eq!(state.deletes.load(Ordering::Relaxed), 3);
    assert!(
        provider.cleanup(owned).await.is_err(),
        "receipt must be released after a successful retry"
    );
    provider.retry_deferred_cleanups(&cancel).await;
    assert_eq!(state.deletes.load(Ordering::Relaxed), 3);
    task.abort();
    Ok(())
}

#[tokio::test]
async fn dropped_presentation_is_reconciled_and_cleaned_on_retry() -> Result<()> {
    let (url, state, task) = fixture().await?;
    let resolver = Arc::new(DohTxtResolver::new(format!("{url}/dns-query")));
    let provider = CloudflareDnsProvider::with_resolver("abc", "fixture-only-token", resolver)
        .with_endpoint(url)
        .with_cleanup_retry_backoff(Duration::ZERO);
    let cancel = CancellationToken::new();
    // The request is dropped before its response is processed (as
    // cancellation does) while the remote side still commits the record.
    state.delay_present_ms.store(400, Ordering::Relaxed);
    let dropped = tokio::time::timeout(
        Duration::from_millis(50),
        provider.present("_acme-challenge.example.test", "proof"),
    )
    .await;
    assert!(dropped.is_err());
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(*state.value.lock().unwrap(), "proof");
    state.delay_present_ms.store(0, Ordering::Relaxed);
    // Reconciliation finds the orphaned record by name/value and deletes it.
    provider.retry_deferred_cleanups(&cancel).await;
    assert_eq!(state.lists.load(Ordering::Relaxed), 1);
    assert_eq!(state.deletes.load(Ordering::Relaxed), 1);
    // Bookkeeping is clean afterwards: presenting and cleaning up work.
    let owned = provider
        .present("_acme-challenge.example.test", "proof")
        .await?;
    provider.cleanup(owned).await?;
    assert_eq!(state.deletes.load(Ordering::Relaxed), 2);
    provider.retry_deferred_cleanups(&cancel).await;
    assert_eq!(state.lists.load(Ordering::Relaxed), 1);
    assert_eq!(state.deletes.load(Ordering::Relaxed), 2);
    task.abort();
    Ok(())
}
