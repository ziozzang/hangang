//! Bounded request-scoped route references. This is not authorization or replay
//! consumption. A future authenticated RPC must preserve these owner checks.
use crate::{
    config::{HttpRuntime, Snapshot},
    projection_entity::Prepared,
};
use arc_swap::ArcSwap;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const SHARDS: usize = 16;
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refused;
struct Entry {
    runtime: Arc<HttpRuntime>,
    client_ip: IpAddr,
    snapshot: Arc<Snapshot>,
    digest: [u8; 32],
    uri: hyper::Uri,
    method: hyper::Method,
    destination_sha256: [u8; 32],
    lifetime: Mutex<Lifetime>,
}
enum SourceStamp {
    #[cfg(target_os = "linux")]
    Boottime(hangang_runtime::time::ElapsedStamp),
    #[cfg(not(target_os = "linux"))]
    LegacyStrict(std::time::Instant),
}
impl SourceStamp {
    fn new(_observed: bool) -> Result<Self, Refused> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self::Boottime(
                hangang_runtime::time::ElapsedStamp::now().map_err(|_| Refused)?,
            ))
        }
        #[cfg(not(target_os = "linux"))]
        {
            if _observed {
                return Err(Refused);
            }
            Ok(Self::LegacyStrict(std::time::Instant::now()))
        }
    }
    fn elapsed(&self) -> Result<Duration, Refused> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Boottime(stamp) => stamp.elapsed().map_err(|_| Refused),
            #[cfg(not(target_os = "linux"))]
            Self::LegacyStrict(stamp) => Ok(stamp.elapsed()),
        }
    }
}
struct Lifetime {
    started: SourceStamp,
    last: Duration,
    failed: bool,
}
impl Entry {
    fn remaining(&self) -> Option<Duration> {
        let mut lifetime = self.lifetime.lock().ok()?;
        if lifetime.failed {
            return None;
        }
        let elapsed = match lifetime.started.elapsed() {
            Ok(elapsed) => elapsed,
            Err(_) => {
                lifetime.failed = true;
                return None;
            }
        };
        if elapsed < lifetime.last || elapsed >= Duration::from_secs(1) {
            lifetime.failed = true;
            return None;
        }
        lifetime.last = elapsed;
        Duration::from_secs(1).checked_sub(elapsed)
    }
}
pub(crate) struct Registry {
    active: Arc<ArcSwap<Snapshot>>,
    entries: [Mutex<HashMap<[u8; 32], Arc<Entry>>>; SHARDS],
    capacity: Arc<Semaphore>,
    random: &'static dyn rustls::crypto::SecureRandom,
}
/// No Clone, Debug or serialization. Dropping the native owner removes its
/// reference, including cancellation before a decision arrives.
pub(crate) struct Capture {
    registry: Arc<Registry>,
    reference: [u8; 32],
    entry: Arc<Entry>,
    _capacity: OwnedSemaphorePermit,
}
fn destination_digest(uri: &hyper::Uri) -> [u8; 32] {
    use sha2::Digest;
    struct Writer(sha2::Sha256);
    impl std::fmt::Write for Writer {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            self.0.update(value.as_bytes());
            Ok(())
        }
    }
    let mut writer = Writer(sha2::Sha256::new());
    std::fmt::write(&mut writer, format_args!("{uri}")).expect("digest writer is infallible");
    writer.0.finalize().into()
}
impl Registry {
    #[cfg(test)]
    pub(crate) fn active_for_test(&self) -> &Arc<ArcSwap<Snapshot>> {
        &self.active
    }
    pub(crate) fn new(
        active: Arc<ArcSwap<Snapshot>>,
        capacity: usize,
    ) -> Result<Arc<Self>, Refused> {
        if !(1..=4096).contains(&capacity) {
            return Err(Refused);
        }
        Ok(Arc::new(Self {
            active,
            entries: std::array::from_fn(|_| Mutex::new(HashMap::new())),
            capacity: Arc::new(Semaphore::new(capacity)),
            random: rustls::crypto::ring::default_provider().secure_random,
        }))
    }
    fn shard(reference: &[u8; 32]) -> usize {
        usize::from(reference[0]) % SHARDS
    }
    pub(crate) fn capture(
        self: &Arc<Self>,
        snapshot: &Arc<Snapshot>,
        runtime: &Arc<HttpRuntime>,
        prepared: &Prepared,
        client_ip: IpAddr,
    ) -> Result<Capture, Refused> {
        if !runtime.route.enabled
            || !Arc::ptr_eq(&self.active.load(), snapshot)
            || snapshot
                .http_route_indices
                .get(&runtime.route.id)
                .and_then(|index| snapshot.http.get(*index))
                .is_none_or(|owner| !Arc::ptr_eq(owner, runtime))
            || runtime
                .native_resource
                .as_ref()
                .is_none_or(|binding| !binding.owns(prepared))
        {
            return Err(Refused);
        }
        let capacity = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| Refused)?;
        let mut reference = [0; 32];
        self.random.fill(&mut reference).map_err(|_| Refused)?;
        let entry = Arc::new(Entry {
            runtime: runtime.clone(),
            client_ip,
            snapshot: snapshot.clone(),
            digest: prepared.digest(),
            uri: prepared.request().uri().clone(),
            method: prepared.request().method().clone(),
            destination_sha256: prepared.human_scope().map_or_else(
                || destination_digest(prepared.request().uri()),
                |scope| scope.destination_sha256,
            ),
            lifetime: Mutex::new(Lifetime {
                started: SourceStamp::new(
                    runtime
                        .native_resource
                        .as_ref()
                        .is_some_and(|binding| binding.observed_mode()),
                )?,
                last: Duration::ZERO,
                failed: false,
            }),
        });
        let mut shard = self.entries[Self::shard(&reference)]
            .lock()
            .map_err(|_| Refused)?;
        if shard.contains_key(&reference) || !Arc::ptr_eq(&self.active.load(), snapshot) {
            return Err(Refused);
        }
        shard.try_reserve(1).map_err(|_| Refused)?;
        shard.insert(reference, entry.clone());
        drop(shard);
        Ok(Capture {
            registry: self.clone(),
            reference,
            entry,
            _capacity: capacity,
        })
    }
    /// Server-only owner observation. Caller role/mTLS must be checked before
    /// lookup. Response fields come exclusively from retained native state.
    pub(crate) fn observe(
        &self,
        reference: &[u8; 32],
        request_sha256: &[u8; 32],
        destination_sha256: &[u8; 32],
        request_id: u64,
    ) -> Option<hangang_route_grpc::v1::RouteReply> {
        let shard = self.entries[Self::shard(reference)].lock().ok()?;
        let entry = shard.get(reference)?;
        if entry.digest != *request_sha256
            || entry.destination_sha256 != *destination_sha256
            || !entry.runtime.route.enabled
            || !Arc::ptr_eq(&self.active.load(), &entry.snapshot)
        {
            return None;
        }
        let binding = entry.runtime.native_resource.as_ref()?;
        let scope = binding.owner_scope(&entry.method)?;
        if [
            &entry.runtime.route.id,
            scope.service,
            scope.audience,
            scope.resource,
            scope.action,
        ]
        .iter()
        .any(|value| value.is_empty() || value.len() > 128)
        {
            return None;
        }
        let client_ip = match entry.client_ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let remaining_ms = u32::try_from(entry.remaining()?.as_millis()).ok()?;
        if !(1..=1000).contains(&remaining_ms) {
            return None;
        }
        let reply = hangang_route_grpc::v1::RouteReply {
            request_id,
            configuration_revision: entry.snapshot.config.revision,
            route_id: entry.runtime.route.id.clone(),
            service: scope.service.into(),
            audience: scope.audience.into(),
            resource: scope.resource.into(),
            action: scope.action.into(),
            client_ip,
            request_sha256: entry.digest.to_vec(),
            destination_sha256: entry.destination_sha256.to_vec(),
            remaining_ms,
        };
        if entry.remaining().is_none() || !Arc::ptr_eq(&self.active.load(), &entry.snapshot) {
            return None;
        }
        Some(reply)
    }
    fn check(
        &self,
        reference: &[u8; 32],
        digest: &[u8; 32],
        uri: &hyper::Uri,
        method: &hyper::Method,
    ) -> bool {
        let Ok(shard) = self.entries[Self::shard(reference)].lock() else {
            return false;
        };
        let Some(entry) = shard.get(reference) else {
            return false;
        };
        entry.runtime.route.enabled
            && entry.digest == *digest
            && entry.uri == *uri
            && entry.method == *method
            && entry.remaining().is_some()
            && Arc::ptr_eq(&self.active.load(), &entry.snapshot)
    }
}
impl Capture {
    pub(crate) fn wire(&self) -> pumgye_grpc::v1::NativeRouteReference {
        pumgye_grpc::v1::NativeRouteReference {
            reference: self.reference.to_vec(),
            destination_sha256: self.entry.destination_sha256.to_vec(),
        }
    }
    #[cfg(test)]
    pub(crate) fn request(&self, request_id: u64) -> hangang_route_grpc::v1::RouteRequest {
        hangang_route_grpc::v1::RouteRequest {
            request_id,
            reference: self.reference.to_vec(),
            request_sha256: self.entry.digest.to_vec(),
            destination_sha256: self.entry.destination_sha256.to_vec(),
        }
    }
    pub(crate) fn current_for(&self, client_ip: IpAddr) -> bool {
        self.entry.client_ip == client_ip && self.current()
    }
    pub(crate) fn current(&self) -> bool {
        self.registry.check(
            &self.reference,
            &self.entry.digest,
            &self.entry.uri,
            &self.entry.method,
        )
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        // Even a poisoned shard must not retain cancelled requests indefinitely.
        let mut shard = self.registry.entries[Registry::shard(&self.reference)]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        shard.remove(&self.reference);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        config::Config, native_resource::Binding, projection_receipt::IssuerPin,
        pumgye::ResourceGate,
    };
    use http_body_util::{BodyExt, Full};
    fn ip() -> IpAddr {
        "192.0.2.9".parse().unwrap()
    }
    pub(crate) async fn fixture(
        capacity: usize,
    ) -> (Arc<Registry>, Arc<Snapshot>, Arc<HttpRuntime>, Prepared) {
        let config: Config = serde_json::from_value(serde_json::json!({"revision":7,"http":[{
            "id":"orders","host":"orders.example.test","path_prefix":"/",
            "backends":["http://127.0.0.1:9090"]
        }]}))
        .unwrap();
        let mut snapshot = Snapshot::new(config).unwrap();
        let binding = Arc::new(
            Binding::new(
                ResourceGate {
                    service_id: "orders".into(),
                    resource: "db:orders".into(),
                    actions: std::collections::BTreeMap::from([("GET".into(), "select".into())]),
                },
                "orders-api".into(),
                IssuerPin::new(
                    "owned".into(),
                    1,
                    ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                        .verifying_key()
                        .to_bytes(),
                )
                .unwrap(),
            )
            .unwrap(),
        );
        // Keep fixture identity and transport setup separate; only a compiled
        // native binding is installed into the real snapshot runtime here.
        Arc::get_mut(&mut snapshot.http[0]).unwrap().native_resource = Some(binding.clone());
        let runtime = snapshot.http[0].clone();
        let snapshot = Arc::new(snapshot);
        let registry = Registry::new(Arc::new(ArcSwap::from(snapshot.clone())), capacity).unwrap();
        let request = hyper::Request::builder()
            .uri("https://orders.example.test/api/secure?x=1")
            .body(
                Full::new(bytes::Bytes::from_static(b"owned final entity"))
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let prepared = binding
            .prepare(request, Arc::new(Semaphore::new(1)))
            .await
            .unwrap();
        (registry, snapshot, runtime, prepared)
    }
    #[tokio::test]
    async fn route_clock_reversal_irreversibly_retires_the_original_capture() {
        let (registry, snapshot, runtime, prepared) = fixture(2).await;
        let capture = registry
            .capture(&snapshot, &runtime, &prepared, ip())
            .unwrap();
        assert!(capture.current());
        capture.entry.lifetime.lock().unwrap().last = Duration::from_secs(2);
        assert!(!capture.current());
        capture.entry.lifetime.lock().unwrap().last = Duration::ZERO;
        assert!(
            !capture.current(),
            "a later good clock read resurrected a refused capture"
        );
        let wire = capture.request(7);
        assert!(
            registry
                .observe(
                    &capture.reference,
                    &prepared.digest(),
                    &wire.destination_sha256.as_slice().try_into().unwrap(),
                    7
                )
                .is_none()
        );
    }
    #[test]
    fn final_absolute_uri_digest_matches_an_independent_vector() {
        assert_eq!(
            destination_digest(
                &"https://orders.example.test/api/secure?x=1"
                    .parse()
                    .unwrap()
            ),
            [
                67, 50, 122, 47, 193, 210, 120, 71, 252, 126, 87, 81, 59, 31, 86, 200, 179, 217,
                238, 123, 41, 122, 0, 91, 61, 147, 2, 208, 163, 82, 180, 197
            ]
        );
    }
    #[tokio::test]
    async fn reference_binds_final_request_and_cancellation_removes_it() {
        let (registry, snapshot, runtime, prepared) = fixture(1).await;
        let capture = registry
            .capture(&snapshot, &runtime, &prepared, ip())
            .unwrap();
        assert!(capture.current());
        assert!(capture.current_for(ip()));
        assert!(!capture.current_for("192.0.2.10".parse().unwrap()));
        assert!(Arc::ptr_eq(&capture.entry.runtime, &runtime));
        let reference = capture.reference;
        let digest = prepared.digest();
        let uri = prepared.request().uri();
        let method = prepared.request().method();
        assert!(registry.check(&reference, &digest, uri, method));
        let mut changed = digest;
        changed[0] ^= 1;
        assert!(!registry.check(&reference, &changed, uri, method));
        assert!(!registry.check(
            &reference,
            &digest,
            &"https://other.example.test/api/secure?x=1".parse().unwrap(),
            method
        ));
        assert!(
            !registry.check(
                &reference,
                &digest,
                &"https://orders.example.test/api/secure?x=2"
                    .parse()
                    .unwrap(),
                method
            )
        );
        assert!(!registry.check(&reference, &digest, uri, &hyper::Method::POST));
        let mut wrong = reference;
        wrong[0] ^= 1;
        assert!(!registry.check(&wrong, &digest, uri, method));
        assert!(
            registry
                .capture(&snapshot, &runtime, &prepared, ip())
                .is_err()
        );
        let retained_entry = capture.entry.clone();
        drop(capture);
        assert!(!registry.check(&reference, &digest, uri, method));
        assert!(Arc::ptr_eq(&retained_entry.snapshot, &snapshot));
        assert!(
            registry
                .capture(&snapshot, &runtime, &prepared, ip())
                .unwrap()
                .current()
        );
        assert_eq!(registry.capacity.available_permits(), 1);
    }
    #[tokio::test]
    async fn cancellation_removes_the_reference_and_new_registries_never_inherit_it() {
        let (registry, snapshot, runtime, prepared) = fixture(1).await;
        assert!(Registry::new(registry.active.clone(), 0).is_err());
        assert!(Registry::new(registry.active.clone(), 4097).is_err());
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let task_registry = registry.clone();
        let task = tokio::spawn(async move {
            let capture = task_registry
                .capture(&snapshot, &runtime, &prepared, ip())
                .unwrap();
            sender
                .send((
                    capture.reference,
                    prepared.digest(),
                    prepared.request().uri().clone(),
                    prepared.request().method().clone(),
                ))
                .unwrap();
            std::future::pending::<()>().await;
            drop(capture);
        });
        let (reference, digest, uri, method) = receiver.await.unwrap();
        assert!(registry.check(&reference, &digest, &uri, &method));
        let fresh = Registry::new(registry.active.clone(), 1).unwrap();
        assert!(!fresh.check(&reference, &digest, &uri, &method));
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(!registry.check(&reference, &digest, &uri, &method));
        assert_eq!(registry.capacity.available_permits(), 1);
    }
    #[tokio::test]
    async fn changed_native_binding_or_equal_revision_replacement_refuses() {
        let (registry, snapshot, runtime, prepared) = fixture(2).await;
        let (_, _, foreign_runtime, foreign_prepared) = fixture(1).await;
        assert!(
            registry
                .capture(&snapshot, &foreign_runtime, &prepared, ip())
                .is_err()
        );
        assert!(
            registry
                .capture(&snapshot, &runtime, &foreign_prepared, ip())
                .is_err()
        );
        let capture = registry
            .capture(&snapshot, &runtime, &prepared, ip())
            .unwrap();
        registry
            .active
            .store(Arc::new(Snapshot::new(snapshot.config.clone()).unwrap()));
        assert!(!capture.current());
        assert!(
            registry
                .capture(&snapshot, &runtime, &prepared, ip())
                .is_err()
        );
    }
    #[tokio::test]
    async fn expiry_refuses_even_while_the_native_request_remains_held() {
        let (registry, snapshot, runtime, prepared) = fixture(1).await;
        let capture = registry
            .capture(&snapshot, &runtime, &prepared, ip())
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1050)).await;
        assert!(!capture.current());
        assert_eq!(registry.capacity.available_permits(), 0);
        drop(capture);
        assert_eq!(registry.capacity.available_permits(), 1);
    }
    #[tokio::test]
    async fn concurrent_references_are_globally_bounded_and_drop_reclaims_all_slots() {
        let (registry, snapshot, runtime, prepared) = fixture(8).await;
        let prepared = Arc::new(prepared);
        let barrier = Arc::new(tokio::sync::Barrier::new(33));
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let (registry, snapshot, runtime, prepared, barrier) = (
                registry.clone(),
                snapshot.clone(),
                runtime.clone(),
                prepared.clone(),
                barrier.clone(),
            );
            tasks.push(tokio::spawn(async move {
                let capture = registry.capture(&snapshot, &runtime, &prepared, ip());
                barrier.wait().await;
                capture.is_ok()
            }));
        }
        tokio::time::timeout(Duration::from_secs(2), barrier.wait())
            .await
            .unwrap();
        let mut accepted = 0;
        for task in tasks {
            accepted += usize::from(task.await.unwrap());
        }
        assert_eq!(accepted, 8);
        assert_eq!(registry.capacity.available_permits(), 8);
        assert!(
            registry
                .entries
                .iter()
                .all(|shard| shard.lock().unwrap().is_empty())
        );
    }
}
