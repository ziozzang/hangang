//! Opt-in, instance-local observations of an explicit HTTPS peer inventory.
use anyhow::{Result, ensure};
use arc_swap::ArcSwap;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{task::JoinSet, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;

const INVENTORY_MAX: usize = 128 * 1024;
const CA_MAX: usize = 128 * 1024;
const BODY_MAX: usize = 16 * 1024;
const STALE: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryFile {
    peers: Vec<PeerFile>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerFile {
    node_id: String,
    group_id: Option<String>,
    role: Option<String>,
    endpoint: String,
    token_file: PathBuf,
    ca_file: Option<PathBuf>,
}

#[derive(Clone, PartialEq, Eq)]
struct Spec {
    node_id: String,
    group_id: Option<String>,
    role: Option<String>,
    endpoint: String,
    token: Vec<u8>,
    ca: Option<Vec<u8>>,
}
struct Peer {
    spec: Spec,
    client: reqwest::Client,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireObservation {
    pub schema_version: u8,
    pub node_id: String,
    pub observer_generation: String,
    pub instance_id: String,
    pub configuration_source: String,
    pub revision: String,
    pub config_digest: String,
    pub ready: bool,
    #[serde(deserialize_with = "required_nullable_epoch")]
    pub store_epoch: Option<String>,
}

fn required_nullable_epoch<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

struct Seen {
    last_attempt: Option<Instant>,
    last_success: Option<Instant>,
    observation: Option<WireObservation>,
    condition: &'static str,
    last_error: Option<&'static str>,
}
impl Default for Seen {
    fn default() -> Self {
        Self {
            last_attempt: None,
            last_success: None,
            observation: None,
            condition: "unknown",
            last_error: None,
        }
    }
}
struct Generation {
    number: u64,
    available: bool,
    exhausted: bool,
    cancel: CancellationToken,
    peers: Vec<Peer>,
    seen: Mutex<Vec<Seen>>,
}
pub struct Runtime {
    path: PathBuf,
    forbidden_admin_digest: Option<[u8; 32]>,
    state: ArcSwap<Generation>,
    watching: AtomicBool,
}

fn load(path: &Path, forbidden: Option<[u8; 32]>) -> Result<Vec<Spec>> {
    let raw = crate::fleet_observer::secure_read(path, INVENTORY_MAX)?;
    let file: InventoryFile =
        serde_json::from_slice(&raw).map_err(|_| anyhow::anyhow!("invalid fleet inventory"))?;
    ensure!(file.peers.len() <= 64, "too many fleet peers");
    let mut ids = HashSet::new();
    let mut origins = HashSet::new();
    let mut specs = Vec::with_capacity(file.peers.len());
    for peer in file.peers {
        ensure!(
            crate::fleet_observer::valid_node_id(&peer.node_id),
            "invalid fleet node id"
        );
        ensure!(
            peer.group_id
                .as_deref()
                .is_none_or(crate::fleet_observer::valid_node_id)
                && peer
                    .role
                    .as_deref()
                    .is_none_or(crate::fleet_observer::valid_node_id),
            "invalid fleet group or role"
        );
        ensure!(peer.endpoint.len() <= 2048, "fleet endpoint too long");
        let url = reqwest::Url::parse(&peer.endpoint)
            .map_err(|_| anyhow::anyhow!("invalid fleet endpoint"))?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none(),
            "fleet endpoint must be an HTTPS origin"
        );
        let endpoint = url.origin().ascii_serialization();
        ensure!(
            ids.insert(peer.node_id.clone()) && origins.insert(endpoint.clone()),
            "duplicate fleet node or endpoint"
        );
        let token = crate::fleet_observer::parse_token(crate::fleet_observer::secure_read(
            &peer.token_file,
            crate::fleet_observer::TOKEN_MAX,
        )?)?;
        ensure!(
            forbidden
                .as_ref()
                .is_none_or(|digest| Sha256::digest(&token).as_slice() != digest),
            "fleet peer token must differ from admin token"
        );
        let ca = peer
            .ca_file
            .as_ref()
            .map(|path| crate::fleet_observer::secure_read(path, CA_MAX))
            .transpose()?;
        specs.push(Spec {
            node_id: peer.node_id,
            group_id: peer.group_id,
            role: peer.role,
            endpoint,
            token,
            ca,
        });
    }
    Ok(specs)
}

fn prepare(specs: Vec<Spec>, number: u64) -> Result<Generation> {
    let mut peers = Vec::with_capacity(specs.len());
    for spec in specs {
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3));
        if let Some(bytes) = &spec.ca {
            builder = builder.tls_built_in_root_certs(false);
            for certificate in parse_ca_bundle(bytes)? {
                builder = builder.add_root_certificate(certificate);
            }
        }
        peers.push(Peer {
            spec,
            client: builder.build()?,
        });
    }
    let seen = (0..peers.len()).map(|_| Seen::default()).collect();
    Ok(Generation {
        number,
        available: true,
        exhausted: false,
        cancel: CancellationToken::new(),
        peers,
        seen: Mutex::new(seen),
    })
}

fn parse_ca_bundle(bytes: &[u8]) -> Result<Vec<reqwest::Certificate>> {
    let mut rest = std::str::from_utf8(bytes).map_err(|_| anyhow::anyhow!("invalid fleet CA"))?;
    let mut certificates = Vec::new();
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_ascii_whitespace());
        if rest.is_empty() {
            break;
        }
        ensure!(
            rest.starts_with(BEGIN) && certificates.len() < 32,
            "invalid fleet CA"
        );
        let end = rest
            .find(END)
            .ok_or_else(|| anyhow::anyhow!("invalid fleet CA"))?
            + END.len();
        let (pem, tail) = rest.split_at(end);
        let body = &pem[BEGIN.len()..pem.len() - END.len()];
        let compact: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(compact)
            .map_err(|_| anyhow::anyhow!("invalid fleet CA"))?;
        let (remainder, _) = x509_parser::parse_x509_certificate(&der)
            .map_err(|_| anyhow::anyhow!("invalid fleet CA"))?;
        ensure!(remainder.is_empty(), "invalid fleet CA");
        certificates.push(
            reqwest::Certificate::from_der(&der)
                .map_err(|_| anyhow::anyhow!("invalid fleet CA"))?,
        );
        rest = tail;
    }
    ensure!(!certificates.is_empty(), "invalid fleet CA");
    Ok(certificates)
}

fn valid_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<u64>().is_ok()
}
fn valid_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn due_indices(seen: &mut [Seen], now: Instant, capacity: usize) -> Vec<usize> {
    let mut eligible: Vec<_> = seen
        .iter()
        .enumerate()
        .filter_map(|(index, row)| {
            row.last_attempt
                .is_none_or(|at| now.saturating_duration_since(at) >= POLL)
                .then_some((row.last_attempt, index))
        })
        .collect();
    eligible.sort_by_key(|(last, index)| (*last, *index));
    let result: Vec<_> = eligible
        .into_iter()
        .take(capacity)
        .map(|(_, index)| index)
        .collect();
    for index in &result {
        seen[*index].last_attempt = Some(now);
    }
    result
}
fn validate_wire(value: &WireObservation, expected_id: &str) -> &'static str {
    if value.schema_version != 1
        || !crate::fleet_observer::valid_node_id(&value.node_id)
        || value.node_id != expected_id
    {
        return "identity_mismatch";
    }
    if !valid_decimal(&value.observer_generation)
        || !valid_decimal(&value.revision)
        || !valid_hex(&value.instance_id, 16)
        || !valid_hex(&value.config_digest, 16)
        || !matches!(
            value.configuration_source.as_str(),
            "file" | "shared" | "kubernetes"
        )
        || value.store_epoch.as_ref().is_some_and(|s| {
            s.is_empty() || s.len() > 128 || !s.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        })
    {
        return "invalid_observation";
    }
    "ok"
}

async fn poll(peer: Peer) -> std::result::Result<WireObservation, &'static str> {
    let url = format!("{}/v1/fleet/observation", peer.spec.endpoint);
    let response = peer
        .client
        .get(url)
        .bearer_auth(String::from_utf8_lossy(&peer.spec.token).as_ref())
        .send()
        .await
        .map_err(|_| "transport")?;
    if response.status() != reqwest::StatusCode::OK {
        return Err("http_status");
    }
    if response
        .content_length()
        .is_some_and(|n| n > BODY_MAX as u64)
    {
        return Err("body_too_large");
    }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "transport")? {
        if bytes.len().saturating_add(chunk.len()) > BODY_MAX {
            return Err("body_too_large");
        }
        bytes.extend_from_slice(&chunk);
    }
    let value: WireObservation =
        serde_json::from_slice(&bytes).map_err(|_| "invalid_observation")?;
    match validate_wire(&value, &peer.spec.node_id) {
        "ok" => Ok(value),
        code => Err(code),
    }
}

async fn poll_guarded<F>(cancel: CancellationToken, future: F) -> Option<F::Output>
where
    F: std::future::Future,
{
    tokio::select! { biased;
        _ = cancel.cancelled() => None,
        result = future => Some(result),
    }
}

fn publish_result(
    generation: &Generation,
    index: usize,
    completed: Instant,
    result: std::result::Result<WireObservation, &'static str>,
) {
    let mut rows = generation
        .seen
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let row = &mut rows[index];
    match result {
        Ok(observation) => {
            row.last_success = Some(completed);
            row.observation = Some(observation);
            row.condition = "fresh";
            row.last_error = None;
        }
        Err(code) => {
            row.condition = if code == "identity_mismatch" {
                "identity_mismatch"
            } else {
                "unavailable"
            };
            row.last_error = Some(code);
        }
    }
}

impl Runtime {
    pub async fn open(path: PathBuf, forbidden_admin_token: Option<&str>) -> Result<Arc<Self>> {
        let forbidden_admin_digest =
            forbidden_admin_token.map(|s| Sha256::digest(s.as_bytes()).into());
        let copy = path.clone();
        let specs =
            tokio::task::spawn_blocking(move || load(&copy, forbidden_admin_digest)).await??;
        Ok(Arc::new(Self {
            path,
            forbidden_admin_digest,
            state: ArcSwap::from(Arc::new(prepare(specs, 1)?)),
            watching: AtomicBool::new(false),
        }))
    }

    async fn refresh(&self) {
        let path = self.path.clone();
        let forbidden = self.forbidden_admin_digest;
        let loaded = tokio::task::spawn_blocking(move || load(&path, forbidden))
            .await
            .ok()
            .and_then(Result::ok);
        let old = self.state.load_full();
        if old.exhausted {
            return;
        }
        if let Some(specs) = &loaded {
            if old.available && old.peers.iter().map(|p| &p.spec).eq(specs.iter()) {
                return;
            }
        } else if !old.available {
            return;
        }
        if old.number == u64::MAX {
            old.cancel.cancel();
            self.state.store(Arc::new(Generation {
                number: old.number,
                available: false,
                exhausted: true,
                cancel: CancellationToken::new(),
                peers: Vec::new(),
                seen: Mutex::new(Vec::new()),
            }));
            return;
        }
        let next = loaded
            .and_then(|specs| prepare(specs, old.number + 1).ok())
            .unwrap_or_else(|| Generation {
                number: old.number + 1,
                available: false,
                exhausted: false,
                cancel: CancellationToken::new(),
                peers: Vec::new(),
                seen: Mutex::new(Vec::new()),
            });
        old.cancel.cancel();
        self.state.store(Arc::new(next));
    }

    pub fn status(&self) -> serde_json::Value {
        let state = self.state.load();
        let now = Instant::now();
        let seen = state
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut fresh_nodes = 0;
        let nodes: Vec<_> = state
            .peers
            .iter()
            .zip(seen.iter())
            .map(|(peer, row)| {
                let age = row
                    .last_success
                    .map(|at| now.saturating_duration_since(at).as_secs());
                let condition =
                    if row.condition == "fresh" && age.is_some_and(|s| s >= STALE.as_secs()) {
                        "stale"
                    } else {
                        row.condition
                    };
                if condition == "fresh" {
                    fresh_nodes += 1;
                }
                serde_json::json!({"node_id":peer.spec.node_id,
                "group_id":peer.spec.group_id,"role":peer.spec.role,
                "endpoint":peer.spec.endpoint,
                "condition":condition,"last_error":row.last_error,"age_seconds":age,
                "observation":row.observation})
            })
            .collect();
        serde_json::json!({"configured":true,"available":state.available,
            "generation":state.number.to_string(),
            "expected_nodes":state.available.then_some(state.peers.len()),
            "fresh_nodes":state.available.then_some(fresh_nodes),
            "stale_after_seconds":60,"nodes":nodes})
    }

    pub async fn watch(self: Arc<Self>, cancel: CancellationToken) {
        if self.watching.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = ticker.tick() => {
                    self.refresh().await;
                    let state = self.state.load_full();
                    if !state.available { continue; }
                    let now = Instant::now();
                    let mut seen = state.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    for index in due_indices(&mut seen, now, 4usize.saturating_sub(tasks.len())) {
                        let peer = &state.peers[index];
                        let peer = Peer { spec: peer.spec.clone(), client: peer.client.clone() };
                        let generation = state.clone();
                        tasks.spawn(async move {
                            let result = poll_guarded(generation.cancel.clone(), poll(peer)).await;
                            (generation, index, Instant::now(), result)
                        });
                    }
                }
                Some(done) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Ok((generation, index, completed, result)) = done {
                        if !Arc::ptr_eq(&generation, &self.state.load_full()) { continue; }
                        if let Some(result) = result { publish_result(&generation, index, completed, result); }
                    }
                }
            }
        }
        self.state.load().cancel.cancel();
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        self.watching.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    fn fixture(peers: serde_json::Value) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fleet.json");
        fs::write(&path, serde_json::json!({"peers":peers}).to_string()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        (dir, path)
    }
    fn token(dir: &Path) -> PathBuf {
        let path = dir.join("token");
        fs::write(&path, "A".repeat(48)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
    fn wire(id: &str) -> WireObservation {
        WireObservation {
            schema_version: 1,
            node_id: id.into(),
            observer_generation: "1".into(),
            instance_id: "a".repeat(16),
            configuration_source: "file".into(),
            revision: "0".into(),
            config_digest: "b".repeat(16),
            ready: true,
            store_epoch: None,
        }
    }

    #[test]
    fn strict_origin_and_wire_validation() {
        let (dir, path) = fixture(serde_json::json!([]));
        let secret = token(dir.path());
        for bad in [
            "http://localhost:9000",
            "https://localhost:9000/path",
            "https://user@localhost:9000",
            "https://localhost:9000/?q=1",
            "https://localhost:9000/#frag",
        ] {
            fs::write(
                &path,
                serde_json::json!({"peers":[{"node_id":"one","endpoint":bad,"token_file":secret}]})
                    .to_string(),
            )
            .unwrap();
            assert!(load(&path, None).is_err(), "accepted {bad}");
        }
        fs::write(
            &path,
            serde_json::json!({"peers":[{"node_id":"one",
            "endpoint":format!("https://{}", "a".repeat(2049)),"token_file":secret}]})
            .to_string(),
        )
        .unwrap();
        assert!(load(&path, None).is_err());
        fs::write(
            &path,
            serde_json::json!({"peers":[
                {"node_id":"one","endpoint":"https://localhost:9000/","token_file":secret},
                {"node_id":"two","endpoint":"https://localhost:9000","token_file":secret}
            ]})
            .to_string(),
        )
        .unwrap();
        assert!(load(&path, None).is_err());
        assert_eq!(validate_wire(&wire("one"), "one"), "ok");
        assert_eq!(validate_wire(&wire("other"), "one"), "identity_mismatch");
        let mut bad = wire("one");
        bad.revision = "01".into();
        assert_eq!(validate_wire(&bad, "one"), "invalid_observation");
        for epoch in ["", "with space", "tab\there", "line\nhere", "\u{7f}", "é"] {
            let mut bad = wire("one");
            bad.store_epoch = Some(epoch.into());
            assert_eq!(validate_wire(&bad, "one"), "invalid_observation");
        }
        let mut valid_epoch = wire("one");
        valid_epoch.store_epoch = Some("a-f_123".into());
        assert_eq!(validate_wire(&valid_epoch, "one"), "ok");
        let mut missing = serde_json::to_value(wire("one")).unwrap();
        missing.as_object_mut().unwrap().remove("store_epoch");
        assert!(serde_json::from_value::<WireObservation>(missing).is_err());
        assert!(
            serde_json::from_value::<WireObservation>(serde_json::to_value(wire("one")).unwrap())
                .is_ok()
        );
        assert!(
            parse_ca_bundle(b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----")
                .is_err()
        );
        assert!(parse_ca_bundle(b"not a certificate").is_err());
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .unwrap()
            .cert
            .pem();
        assert_eq!(
            parse_ca_bundle(format!("{cert}\n{cert}").as_bytes())
                .unwrap()
                .len(),
            2
        );
        assert!(parse_ca_bundle(format!("{cert}\nnot-pem").as_bytes()).is_err());
    }

    #[tokio::test]
    async fn initial_unknown_then_historical_failure_and_stale() {
        let (dir, path) = fixture(serde_json::json!([]));
        let secret = token(dir.path());
        fs::write(&path, serde_json::json!({"peers":[{"node_id":"one","endpoint":"https://localhost:9000","token_file":secret}]}).to_string()).unwrap();
        let runtime = Runtime::open(path, None).await.unwrap();
        let first = runtime.status();
        assert_eq!(first["nodes"][0]["condition"], "unknown");
        assert!(first["nodes"][0]["group_id"].is_null());
        assert!(first["nodes"][0]["role"].is_null());
        assert_eq!(first["fresh_nodes"], 0);
        let state = runtime.state.load_full();
        {
            let mut rows = state.seen.lock().unwrap();
            rows[0].last_success = Some(Instant::now());
            rows[0].observation = Some(wire("one"));
            rows[0].condition = "fresh";
        }
        assert_eq!(runtime.status()["fresh_nodes"], 1);
        {
            let mut rows = state.seen.lock().unwrap();
            rows[0].observation.as_mut().unwrap().ready = false;
        }
        assert_eq!(
            runtime.status()["fresh_nodes"],
            1,
            "fresh_nodes counts observed peers, including unready peers"
        );
        {
            let mut rows = state.seen.lock().unwrap();
            rows[0].condition = "unavailable";
            rows[0].last_error = Some("transport");
        }
        assert_eq!(runtime.status()["nodes"][0]["condition"], "unavailable");
        assert_eq!(
            runtime.status()["nodes"][0]["observation"]["node_id"],
            "one"
        );
        {
            let mut rows = state.seen.lock().unwrap();
            rows[0].last_success = Some(Instant::now() - Duration::from_secs(61));
        }
        assert_eq!(
            runtime.status()["nodes"][0]["condition"],
            "unavailable",
            "an explicit failure remains visible even when historical success ages"
        );
        assert_eq!(runtime.status()["fresh_nodes"], 0);
        {
            let mut rows = state.seen.lock().unwrap();
            rows[0].condition = "fresh";
        }
        assert_eq!(runtime.status()["nodes"][0]["condition"], "stale");
        // A completed network response harvested after a long watcher stall
        // must carry its completion time rather than its publication time.
        publish_result(
            &state,
            0,
            Instant::now() - Duration::from_secs(61),
            Ok(wire("one")),
        );
        assert_eq!(runtime.status()["nodes"][0]["condition"], "stale");
    }

    #[tokio::test]
    async fn invalid_reload_fences_prior_generation_and_recovers() {
        let (dir, path) = fixture(serde_json::json!([]));
        let secret = token(dir.path());
        let valid = serde_json::json!({"peers":[{"node_id":"one","endpoint":"https://localhost:9000","token_file":secret}]}).to_string();
        fs::write(&path, &valid).unwrap();
        let runtime = Runtime::open(path.clone(), None).await.unwrap();
        let old = runtime.state.load_full();
        runtime.refresh().await;
        assert!(Arc::ptr_eq(&old, &runtime.state.load_full()));
        fs::write(&path, b"invalid").unwrap();
        runtime.refresh().await;
        assert!(!runtime.status()["available"].as_bool().unwrap());
        assert!(old.cancel.is_cancelled());
        assert_eq!(runtime.status()["generation"], "2");
        assert!(runtime.status()["expected_nodes"].is_null());
        assert!(runtime.status()["fresh_nodes"].is_null());
        assert_eq!(runtime.status()["nodes"], serde_json::json!([]));
        assert!(!Arc::ptr_eq(&old, &runtime.state.load_full()));
        fs::write(&path, valid).unwrap();
        runtime.refresh().await;
        assert_eq!(runtime.status()["generation"], "3");
        assert_eq!(runtime.status()["nodes"][0]["condition"], "unknown");
    }

    #[tokio::test]
    async fn metadata_is_validated_and_retires_prior_samples_on_change() {
        let (dir, path) = fixture(serde_json::json!([]));
        let secret = token(dir.path());
        let entry = serde_json::json!({"node_id":"one","endpoint":"https://localhost:9000",
            "token_file":secret,"group_id":"east.1","role":"edge_proxy"});
        fs::write(
            &path,
            serde_json::json!({"peers":[entry.clone()]}).to_string(),
        )
        .unwrap();
        let runtime = Runtime::open(path.clone(), None).await.unwrap();
        assert_eq!(runtime.status()["nodes"][0]["group_id"], "east.1");
        assert_eq!(runtime.status()["nodes"][0]["role"], "edge_proxy");
        let old = runtime.state.load_full();
        publish_result(&old, 0, Instant::now(), Ok(wire("one")));
        assert_eq!(runtime.status()["fresh_nodes"], 1);
        runtime.refresh().await;
        assert!(Arc::ptr_eq(&old, &runtime.state.load_full()));
        let mut changed = entry.clone();
        changed["role"] = serde_json::json!("origin");
        fs::write(&path, serde_json::json!({"peers":[changed]}).to_string()).unwrap();
        runtime.refresh().await;
        assert!(old.cancel.is_cancelled());
        assert_eq!(runtime.status()["generation"], "2");
        assert_eq!(runtime.status()["nodes"][0]["role"], "origin");
        assert_eq!(runtime.status()["nodes"][0]["condition"], "unknown");
        assert_eq!(runtime.status()["fresh_nodes"], 0);
        for invalid in [
            "".to_owned(),
            "bad name".to_owned(),
            "x".repeat(65),
            "é".to_owned(),
        ] {
            let mut candidate = entry.clone();
            candidate["group_id"] = serde_json::json!(invalid);
            fs::write(&path, serde_json::json!({"peers":[candidate]}).to_string()).unwrap();
            assert!(load(&path, None).is_err());
            let mut candidate = entry.clone();
            candidate["role"] = serde_json::json!(invalid);
            fs::write(&path, serde_json::json!({"peers":[candidate]}).to_string()).unwrap();
            assert!(load(&path, None).is_err());
        }
        let mut malformed = entry;
        malformed["role"] = serde_json::json!(42);
        fs::write(&path, serde_json::json!({"peers":[malformed]}).to_string()).unwrap();
        assert!(load(&path, None).is_err());
    }

    #[test]
    fn scheduling_is_bounded_and_fair() {
        let mut rows: Vec<_> = (0..64).map(|_| Seen::default()).collect();
        let now = Instant::now();
        let mut selected = Vec::new();
        for _ in 0..16 {
            let batch = due_indices(&mut rows, now, 4);
            assert!(batch.len() <= 4);
            selected.extend(batch);
        }
        assert_eq!(selected, (0..64).collect::<Vec<_>>());
        assert!(due_indices(&mut rows, now, 4).is_empty());
        let mut waiting: Vec<_> = (0..8).map(|_| Seen::default()).collect();
        assert_eq!(due_indices(&mut waiting, now, 4), vec![0, 1, 2, 3]);
        // Once the first four become eligible again, never-attempted peers
        // must still go first; a fixed index scan would starve them.
        assert_eq!(due_indices(&mut waiting, now + POLL, 4), vec![4, 5, 6, 7]);
    }

    #[tokio::test]
    async fn cancelled_generation_never_starts_poll_and_releases_budget() {
        use std::sync::atomic::AtomicUsize;
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let contacted = Arc::new(AtomicUsize::new(0));
        let marker = contacted.clone();
        let result = poll_guarded(cancelled, async move {
            marker.fetch_add(1, Ordering::SeqCst);
        })
        .await;
        assert!(result.is_none());
        assert_eq!(contacted.load(Ordering::SeqCst), 0);

        let (dir, path) = fixture(serde_json::json!([]));
        let secret = token(dir.path());
        fs::write(&path, serde_json::json!({"peers":[{"node_id":"one","endpoint":"https://localhost:9000","token_file":secret}]}).to_string()).unwrap();
        let runtime = Runtime::open(path.clone(), None).await.unwrap();
        let old = runtime.state.load_full();
        let mut tasks = JoinSet::new();
        for _ in 0..4 {
            let cancellation = old.cancel.clone();
            tasks.spawn(
                async move { poll_guarded(cancellation, std::future::pending::<()>()).await },
            );
        }
        tokio::task::yield_now().await;
        fs::write(path, b"invalid").unwrap();
        runtime.refresh().await;
        assert!(old.cancel.is_cancelled());
        for _ in 0..4 {
            assert!(
                tokio::time::timeout(Duration::from_secs(1), tasks.join_next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()
                    .is_none()
            );
        }
        assert!(tasks.is_empty());
    }
}
