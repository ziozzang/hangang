//! Serve the current native console and trusted extensions over an existing
//! Hangang admin authority. The authority still owns accounts/configuration.
#[path = "../console_sso.rs"]
mod sso;
use anyhow::{Result, ensure};
use bytes::Bytes;
use clap::Parser;
use futures_util::StreamExt;
use hangang::{
    admin_plugins::{Authority, Registry},
    admin_users::{Role, User},
    proxy::Body,
};
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::{
    Request, Response, StatusCode,
    body::{Frame, Incoming},
    header,
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{convert::Infallible, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore};
#[derive(Parser)]
#[command(
    version,
    about = "Hangang console with trusted plugins and delegated native administration"
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:19080")]
    listen: SocketAddr,
    #[arg(long)]
    upstream: String,
    #[arg(long)]
    plugins: PathBuf,
    #[arg(long)]
    hopae_sso: Option<PathBuf>,
    /// Refuse the break-glass local administrator login (and local
    /// sessions); only Hopae console SSO remains. Requires --hopae-sso.
    #[arg(long)]
    disable_local_login: bool,
    /// Append console audit records (JSON lines) here; stderr otherwise.
    #[arg(long)]
    audit_log: Option<PathBuf>,
    #[arg(long)]
    allow_insecure_public: bool,
    #[arg(long)]
    check: bool,
}
struct State {
    sso: Option<sso::Sso>,
    local_login: bool,
    audit: Audit,
    origin: reqwest::Url,
    client: reqwest::Client,
    plugins: Registry,
    requests: Arc<Semaphore>,
    public: Arc<Semaphore>,
    login: Arc<Semaphore>,
    streams: Arc<Semaphore>,
}
/// Console audit records (JSON lines): SSO sign-in with the operator's
/// assurance, step-up refusals, and every break-glass local sign-in and
/// local-session change.
struct Audit {
    file: Option<std::sync::Mutex<std::fs::File>>,
}
impl Audit {
    fn open(path: Option<&std::path::Path>) -> Result<Self> {
        let file = match path {
            None => None,
            Some(p) => {
                use std::os::unix::fs::OpenOptionsExt;
                Some(std::sync::Mutex::new(
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .mode(0o600)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(p)?,
                ))
            }
        };
        Ok(Self { file })
    }
    fn record(&self, mut value: serde_json::Value) {
        use std::io::Write;
        value["time_unix_ms"] = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64)
            .into();
        let mut line = value.to_string();
        line.truncate(4096);
        line.push('\n');
        match &self.file {
            Some(f) => {
                let _ = f
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .write_all(line.as_bytes());
            }
            None => eprint!("console-audit {line}"),
        }
    }
}
fn step_up_response(e: &sso::StepUp) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(body(
            serde_json::json!({"error":e.code,"step_up_url":e.step_up_url}).to_string(),
        ))
        .unwrap()
}
fn body(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}
fn error(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(body(serde_json::json!({"error":message}).to_string()))
        .unwrap()
}
fn bearer(req: &Request<Incoming>) -> Option<reqwest::header::HeaderValue> {
    let mut values = req.headers().get_all(header::AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some()
        || value.as_bytes().len() > 4096
        || !value.as_bytes().starts_with(b"Bearer ")
    {
        return None;
    }
    let mut value = value.clone();
    value.set_sensitive(true);
    Some(value)
}
async fn actor(state: &State, authorization: &reqwest::header::HeaderValue) -> Result<User> {
    let mut response = state
        .client
        .get(state.origin.join("v1/auth/me")?)
        .header(header::AUTHORIZATION, authorization.clone())
        .timeout(Duration::from_secs(3))
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK,
        "invalid administrator identity"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 16384,
            "authority response too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    #[derive(serde::Deserialize)]
    struct Me {
        user: User,
    }
    let me: Me = serde_json::from_slice(&bytes)?;
    ensure!(
        me.user.enabled && me.user.username.len() <= 64,
        "invalid administrator identity"
    );
    Ok(me.user)
}
async fn handle(
    mut req: Request<Incoming>,
    state: Arc<State>,
    peer: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path();
    let public = path == "/" || path.starts_with("/ui/");
    let login = matches!(
        path,
        "/v1/auth/login"
            | "/v1/auth/setup"
            | "/v1/auth/bootstrap"
            | "/v1/auth/sso/config"
            | "/v1/auth/sso/exchange"
    );
    let events = path == "/v1/events";
    match hangang::admin_plugins::client_context(&req, peer.ip()) {
        Ok(context) => {
            req.extensions_mut().insert(context);
        }
        Err(_) => return Ok(error(StatusCode::BAD_REQUEST, "invalid client context")),
    };
    let Ok(permit) = (if public {
        state.public.clone()
    } else if login {
        state.login.clone()
    } else if events {
        state.streams.clone()
    } else {
        state.requests.clone()
    })
    .try_acquire_owned() else {
        return Ok(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "console capacity reached",
        ));
    };
    if req.method() == hyper::Method::CONNECT
        || req.uri().scheme().is_some()
        || req.uri().authority().is_some()
    {
        return Ok(error(StatusCode::BAD_REQUEST, "invalid request target"));
    }
    if req
        .headers()
        .get_all(header::AUTHORIZATION)
        .iter()
        .nth(1)
        .is_some()
    {
        return Ok(error(StatusCode::BAD_REQUEST, "ambiguous authorization"));
    }
    if req.uri().path() == "/" {
        return Ok(Response::builder()
            .status(303)
            .header(header::LOCATION, "/ui/")
            .body(body(""))
            .unwrap());
    }
    // The step-up landing (Hopae ADR-0021): reaching it through the gateway
    // means Hopae's step-up rule passed; go back inside the console.
    if let Some(policy) = state.sso.as_ref().and_then(|s| s.policy())
        && req.method() == hyper::Method::GET
        && req.uri().path() == policy.step_up_path
    {
        let back = req
            .uri()
            .query()
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("return=")))
            .map(percent_decode)
            .filter(|b| b.starts_with("/ui/") && !b.contains("//") && !b.contains('\\'))
            .unwrap_or_else(|| "/ui/".into());
        // The step-up rotated the Hopae handle: the console signs in again
        // (`sso=hopae`) and returns to the view.
        let (path, fragment) = back.split_once('#').unwrap_or((back.as_str(), ""));
        let path = path.split('?').next().unwrap_or("/ui/");
        let back = if fragment.is_empty() {
            format!("{path}?sso=hopae")
        } else {
            format!("{path}?sso=hopae#{fragment}")
        };
        return Ok(Response::builder()
            .status(303)
            .header(header::LOCATION, back)
            .header(header::CACHE_CONTROL, "no-store")
            .body(body(""))
            .unwrap());
    }
    if let Some(response) = state
        .plugins
        .asset(&req)
        .or_else(|| hangang::ui::serve(&req))
    {
        return Ok(hangang::proxy::retain_request_permit(response, permit));
    }
    if req.uri().path() == "/v1/auth/sso-lease" {
        return Ok(error(StatusCode::NOT_FOUND, "unknown console endpoint"));
    }
    let req_ip = req
        .extensions()
        .get::<hangang::admin_plugins::ClientContext>()
        .map(|c| c.ip.to_string())
        .unwrap_or_default();
    // The break-glass local administrator sign-in: audited, and refused when
    // disabled.
    if req.uri().path() == "/v1/auth/login" {
        if !state.local_login {
            state.audit.record(serde_json::json!({"event":"console.break_glass_login","outcome":"disabled","client_ip":req_ip}));
            return Ok(error(StatusCode::FORBIDDEN, "local_login_disabled"));
        }
        state.audit.record(serde_json::json!({"event":"console.break_glass_login","outcome":"attempt","client_ip":req_ip}));
    }
    // The operator's session and assurance, for the console header.
    if req.uri().path() == "/v1/auth/sso/session" && req.method() == hyper::Method::GET {
        let token = bearer(&req).and_then(|v| v.to_str().ok().map(str::to_owned));
        let info = match (
            token.as_deref().and_then(|t| t.strip_prefix("Bearer ")),
            &state.sso,
        ) {
            (Some(t), Some(sso)) if t.starts_with("hsso_") => match sso.session_info(t) {
                Some((account, assurance)) => serde_json::json!({
                    "method": "hopae",
                    "account": account,
                    "assurance": assurance,
                    "policy": sso.policy().map(|p| serde_json::json!({"minimum_aal": p.minimum_aal, "require_factor": if p.require_webauthn {"webauthn"} else {"any"}, "sensitive_max_age_seconds": p.max_age, "step_up_url": p.step_up_url("/ui/")})),
                }),
                None => return Ok(error(StatusCode::UNAUTHORIZED, "SSO session expired")),
            },
            (Some(_), _) => {
                serde_json::json!({"method":"local","break_glass": state.sso.is_some(), "local_login": state.local_login})
            }
            (None, _) => return Ok(error(StatusCode::UNAUTHORIZED, "identity required")),
        };
        return Ok(Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CACHE_CONTROL, "no-store")
            .body(body(info.to_string()))
            .unwrap());
    }
    if matches!(
        req.uri().path(),
        "/v1/auth/sso/config" | "/v1/auth/sso/exchange"
    ) {
        if req.uri().query().is_some() {
            return Ok(error(StatusCode::BAD_REQUEST, "SSO queries unsupported"));
        }
        let Some(sso) = &state.sso else {
            return Ok(error(StatusCode::NOT_FOUND, "SSO unavailable"));
        };
        let result = if req.uri().path().ends_with("/config") && req.method() == hyper::Method::GET
        {
            Ok(sso.discovery())
        } else if req.uri().path().ends_with("/exchange") && req.method() == hyper::Method::POST {
            let headers = req.headers().clone();
            let context = req
                .extensions()
                .get::<hangang::admin_plugins::ClientContext>()
                .unwrap()
                .clone();
            if !sso.exchange_allowed(&headers) {
                return Ok(error(
                    StatusCode::FORBIDDEN,
                    "same-origin SSO exchange required",
                ));
            }
            let bytes = match tokio::time::timeout(
                Duration::from_secs(2),
                Limited::new(req.into_body(), 1024).collect(),
            )
            .await
            {
                Ok(Ok(b)) => b.to_bytes(),
                _ => return Ok(error(StatusCode::BAD_REQUEST, "invalid SSO body")),
            };
            if bytes.as_ref() != b"{}" {
                return Ok(error(
                    StatusCode::BAD_REQUEST,
                    "SSO body must be empty object",
                ));
            }
            sso.exchange(&headers, &context, &state.client, &state.origin)
                .await
        } else {
            return Ok(error(StatusCode::METHOD_NOT_ALLOWED, "invalid SSO method"));
        };
        let ip = req_ip.clone();
        return Ok(match result {
            Ok(value) => {
                if value.get("token").is_some() {
                    state.audit.record(serde_json::json!({"event":"console.sso_login","outcome":"success","account":value["user"]["username"],"assurance":value["assurance"],"client_ip":ip}));
                }
                Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CACHE_CONTROL, "no-store")
                    .body(body(value.to_string()))
                    .unwrap()
            }
            Err(e) => match e.downcast_ref::<sso::StepUp>() {
                Some(step) => {
                    state.audit.record(serde_json::json!({"event":"console.sso_login","outcome":"step_up_required","reason":step.code,"client_ip":ip}));
                    step_up_response(step)
                }
                None => {
                    state.audit.record(serde_json::json!({"event":"console.sso_login","outcome":"refused","client_ip":ip}));
                    error(
                        StatusCode::UNAUTHORIZED,
                        "SSO login or account mapping unavailable",
                    )
                }
            },
        });
    }
    let mut sso_session = false;
    if let Some(token) = bearer(&req).and_then(|v| {
        v.to_str()
            .ok()
            .and_then(|v| v.strip_prefix("Bearer hsso_"))
            .map(|v| format!("hsso_{v}"))
    }) {
        let Some(sso) = &state.sso else {
            return Ok(error(StatusCode::UNAUTHORIZED, "SSO unavailable"));
        };
        let context = req
            .extensions()
            .get::<hangang::admin_plugins::ClientContext>()
            .unwrap();
        let authorization = match sso
            .authorization(
                &token,
                req.headers(),
                context,
                &state.client,
                &state.origin,
                req.method(),
                req.uri().path(),
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                if let Some(step) = e.downcast_ref::<sso::StepUp>() {
                    state.audit.record(serde_json::json!({"event":"console.step_up_required","reason":step.code,"method":req.method().as_str(),"path":req.uri().path(),"client_ip":req_ip}));
                    return Ok(step_up_response(step));
                }
                return Ok(error(StatusCode::UNAUTHORIZED, "SSO session rejected"));
            }
        };
        if sso::OperatorPolicy::is_mutation(req.method(), req.uri().path())
            && let Some((account, assurance)) = sso.session_info(&token)
        {
            state.audit.record(serde_json::json!({"event":"console.change","method":req.method().as_str(),"path":req.uri().path(),"account":account,"aal":assurance.as_ref().map(|a| a.aal),"factor":assurance.as_ref().and_then(|a| a.factor.clone()),"client_ip":req_ip}));
        }
        if req.uri().path() == "/v1/auth/logout" && req.method() == hyper::Method::POST {
            sso.logout(&token);
        }
        req.headers_mut()
            .insert(header::AUTHORIZATION, authorization);
        sso_session = true;
    }
    if req.uri().path() == "/v1/plugins" || req.uri().path().starts_with("/v1/plugins/") {
        let Some(authorization) = bearer(&req) else {
            return Ok(error(
                StatusCode::UNAUTHORIZED,
                "administrator identity required",
            ));
        };
        let user = match actor(&state, &authorization).await {
            Ok(u) if u.role == Role::Admin => u,
            Ok(_) => return Ok(error(StatusCode::FORBIDDEN, "administrator role required")),
            Err(_) => {
                return Ok(error(
                    StatusCode::UNAUTHORIZED,
                    "administrator identity unavailable",
                ));
            }
        };
        let authority = Authority::Remote {
            client: state.client.clone(),
            endpoint: state.origin.join("v1/auth/me").unwrap(),
            authorization,
            actor_id: user.id,
        };
        let response = state.plugins.handle(req, authority, user).await;
        return Ok(hangang::proxy::retain_request_permit(response, permit));
    }
    let path = req.uri().path();
    if !(path.starts_with("/v1/") || matches!(path, "/healthz" | "/metrics" | "/openapi.json"))
        || !matches!(
            *req.method(),
            hyper::Method::GET
                | hyper::Method::HEAD
                | hyper::Method::POST
                | hyper::Method::PUT
                | hyper::Method::DELETE
        )
    {
        return Ok(error(StatusCode::NOT_FOUND, "unknown console endpoint"));
    }
    if !login {
        let Some(authorization) = bearer(&req) else {
            return Ok(error(StatusCode::UNAUTHORIZED, "identity required"));
        };
        let user = match actor(&state, &authorization).await {
            Ok(u) => u,
            Err(_) => return Ok(error(StatusCode::UNAUTHORIZED, "identity unavailable")),
        };
        // A local (non-SSO) session is the break-glass path when SSO is configured.
        let local = !authorization.as_bytes().starts_with(b"Bearer hsso_") && !sso_session;
        if local && state.sso.is_some() {
            if !state.local_login {
                return Ok(error(StatusCode::UNAUTHORIZED, "local_sessions_disabled"));
            }
            if sso::OperatorPolicy::is_mutation(req.method(), req.uri().path()) {
                state.audit.record(serde_json::json!({"event":"console.break_glass_change","method":req.method().as_str(),"path":req.uri().path(),"account":user.username,"client_ip":req_ip}));
            }
        }
    }
    let path = req.uri().path_and_query().unwrap().as_str().to_owned();
    let (parts, incoming) = req.into_parts();
    let bytes = match tokio::time::timeout(
        Duration::from_secs(5),
        Limited::new(incoming, if login { 8192 } else { 1024 * 1024 }).collect(),
    )
    .await
    {
        Ok(Ok(b)) => b.to_bytes(),
        _ => {
            return Ok(error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "console request body exceeded limit/deadline",
            ));
        }
    };
    // Build the fixed upstream origin ourselves; URI joins must never replace its authority.
    let mut target = state.origin.clone();
    let (path, query) = path
        .split_once('?')
        .map_or((path.as_str(), None), |(p, q)| (p, Some(q)));
    target.set_path(path);
    target.set_query(query);
    let mut request = state.client.request(parts.method, target).body(bytes);
    for name in [
        header::AUTHORIZATION,
        header::CONTENT_TYPE,
        header::IF_MATCH,
        header::IF_NONE_MATCH,
        header::ACCEPT,
    ] {
        if let Some(value) = parts.headers.get(&name) {
            let mut value = value.clone();
            if name == header::AUTHORIZATION {
                value.set_sensitive(true);
            }
            request = request.header(name, value);
        }
    }
    let response = match request.send().await {
        Ok(r) => r,
        Err(_) => {
            return Ok(error(
                StatusCode::BAD_GATEWAY,
                "Hangang administration unavailable",
            ));
        }
    };
    let mut builder = Response::builder().status(response.status());
    for name in [
        header::CONTENT_TYPE,
        header::CACHE_CONTROL,
        header::ETAG,
        header::WWW_AUTHENTICATE,
        header::ALLOW,
        header::CONTENT_SECURITY_POLICY,
        header::X_CONTENT_TYPE_OPTIONS,
    ] {
        if let Some(value) = response.headers().get(&name) {
            builder = builder.header(name, value);
        }
    }
    // SSE is intentionally streamed. Hold its separate admission until body drop.
    let stream = response.bytes_stream().map(|chunk| {
        chunk
            .map(Frame::data)
            .map_err(hangang::proxy::BodyError::from)
    });
    let stream_body = StreamBody::new(stream).boxed_unsync();
    let stream_body = if events {
        stream_body
    } else {
        Limited::new(stream_body, 4 * 1024 * 1024)
            .map_err(|_| {
                hangang::proxy::BodyError::from_error(std::io::Error::other(
                    "console response exceeded limit",
                ))
            })
            .boxed_unsync()
    };
    let response = builder.body(stream_body).unwrap();
    Ok(hangang::proxy::retain_request_permit(response, permit))
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        args.listen.ip().is_loopback() || args.allow_insecure_public,
        "public plaintext console requires --allow-insecure-public"
    );
    let origin = reqwest::Url::parse(&args.upstream)?;
    ensure!(
        origin.username().is_empty()
            && origin.password().is_none()
            && origin.path() == "/"
            && origin.query().is_none()
            && origin.fragment().is_none(),
        "upstream must be an origin"
    );
    let local = origin
        .host_str()
        .and_then(|h| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    ensure!(
        origin.scheme() == "https" || (origin.scheme() == "http" && local),
        "upstream requires HTTPS or literal loopback HTTP"
    );
    let plugins = Registry::load(&args.plugins)?;
    let sso = args.hopae_sso.as_deref().map(sso::Sso::load).transpose()?;
    ensure!(
        !args.disable_local_login || sso.is_some(),
        "--disable-local-login requires --hopae-sso"
    );
    let audit = Audit::open(args.audit_log.as_deref())?;
    if args.check {
        println!("console plugin configuration is valid");
        return Ok(());
    }
    let state = Arc::new(State {
        sso,
        local_login: !args.disable_local_login,
        audit,
        origin,
        plugins,
        client: reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .read_timeout(Duration::from_secs(20))
            .build()?,
        requests: Arc::new(Semaphore::new(40)),
        public: Arc::new(Semaphore::new(16)),
        login: Arc::new(Semaphore::new(8)),
        streams: Arc::new(Semaphore::new(8)),
    });
    let listener = TcpListener::bind(args.listen).await?;
    let connections = Arc::new(Semaphore::new(128));
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut tasks = tokio::task::JoinSet::new();
    eprintln!("Hangang console listening on {}", listener.local_addr()?);
    loop {
        tokio::select! {
            _=term.recv()=>break,
            _=tokio::signal::ctrl_c()=>break,
            Some(_)=tasks.join_next()=>{},
            accepted=listener.accept()=>{let(stream,peer)=accepted?;let Ok(permit)=connections.clone().try_acquire_owned() else{continue;};stream.set_nodelay(true)?;let state=state.clone();tasks.spawn(async move {let _permit=permit;let service=service_fn(move|r|handle(r,state.clone(),peer));let (stream, idle)=hangang::idle::IdleIo::new(stream,Duration::from_secs(60));let connection=http1::Builder::new().timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10)).max_buf_size(32*1024).serve_connection(TokioIo::new(stream),service);tokio::select!{_=idle.expired()=>{},_=connection=>{}};});}
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) =
                u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16)
        {
            out.push(v);
            i += 3;
        } else {
            out.push(if b[i] == b'+' { b' ' } else { b[i] });
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| "/ui/".into())
}
