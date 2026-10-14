use arc_swap::ArcSwap;
use bytes::Bytes;
use hangang::{config::Snapshot, ingress, metrics::Metrics, policy::PolicyPool, proxy::Proxy};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use std::{convert::Infallible, sync::Arc};
use tokio::net::TcpListener;

#[tokio::test]
async fn ingress_rules_and_default_backend_forward_original_host() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        loop {
            let (stream, _) = origin.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(|request: Request<Incoming>| async move {
                    let host = request.headers()["host"].to_str().unwrap().to_owned();
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(host))))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let document = serde_json::json!({"items": [
        {"kind": "Service", "metadata": {"name": "echo", "namespace": "demo"},
         "spec": {"ports": [{"port": 80}]}},
        {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
         "metadata": {"name": "echo", "namespace": "demo"},
         "spec": {"ingressClassName": "hangang", "rules": [
             {"host": "app.example.test", "http": {"paths": [{"path": "/api", "pathType": "Prefix",
               "backend": {"service": {"name": "echo", "port": {"number": 80}}}}]}},
             {"host": "*.example.test", "http": {"paths": [{"path": "/api", "pathType": "Prefix",
               "backend": {"service": {"name": "echo", "port": {"number": 80}}}}]}}
         ], "defaultBackend": {"service": {"name": "echo", "port": {"number": 80}}}}}
    ]});
    // The live controller uses the same tolerant conversion. Replace only the
    // Service's network destination so this regression runs without cluster DNS.
    let mut config = ingress::import_tolerant(&document, "hangang").unwrap();
    for route in &mut config.http {
        route.backends =
            serde_json::from_value(serde_json::json!([format!("http://{origin_address}")]))
                .unwrap();
    }
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let policy = Arc::new(PolicyPool::new(std::env::current_exe().unwrap(), 1));
    let proxy = Proxy::new(active, policy.clone(), Arc::new(Metrics::default()));
    let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_address = front.local_addr().unwrap();
    let front_task = tokio::spawn(async move {
        loop {
            let (stream, peer) = front.accept().await.unwrap();
            let proxy = proxy.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let proxy = proxy.clone();
                    async move { proxy.handle(request, peer).await }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    for (host, path) in [
        ("app.example.test:8443", "/api/check"),
        ("other.example.test", "/api/check"),
        ("fallback.example.invalid:8080", "/not-a-rule"),
    ] {
        let request = Request::builder()
            .uri(format!("http://{front_address}{path}"))
            .header("host", host)
            .body(Full::new(Bytes::new()))
            .unwrap();
        let response = client.request(request).await.unwrap();
        assert_eq!(response.status(), 200);
        let received = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            received.as_ref(),
            host.as_bytes(),
            "Ingress rewrote the client's Host"
        );
    }
    front_task.abort();
    origin_task.abort();
    policy.shutdown().await;
}
