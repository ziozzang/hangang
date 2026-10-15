//! Bounded request-scoped route references. This is not authorization or replay
//! consumption. A future authenticated RPC must preserve these owner checks.
use crate::{
    config::{HttpRuntime, Snapshot},
    projection_entity::Prepared,
};
use arc_swap::ArcSwap;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const SHARDS: usize = 16;
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refused;
struct Entry {
    snapshot: Arc<Snapshot>,
    digest: [u8; 32],
    uri: hyper::Uri,
    method: hyper::Method,
    expires: Instant,
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
impl Registry {
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
    ) -> Result<Capture, Refused> {
        if !Arc::ptr_eq(&self.active.load(), snapshot)
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
            snapshot: snapshot.clone(),
            digest: prepared.digest(),
            uri: prepared.request().uri().clone(),
            method: prepared.request().method().clone(),
            expires: Instant::now()
                .checked_add(Duration::from_secs(1))
                .ok_or(Refused)?,
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
        entry.digest == *digest
            && entry.uri == *uri
            && entry.method == *method
            && Instant::now() < entry.expires
            && Arc::ptr_eq(&self.active.load(), &entry.snapshot)
    }
}
impl Capture {
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
mod tests {
    use super::*;
    use crate::{
        config::Config, native_resource::Binding, projection_receipt::IssuerPin,
        pumgye::ResourceGate,
    };
    use http_body_util::{BodyExt, Full};
    async fn fixture(
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
    async fn reference_binds_final_request_and_cancellation_removes_it() {
        let (registry, snapshot, runtime, prepared) = fixture(1).await;
        let capture = registry.capture(&snapshot, &runtime, &prepared).unwrap();
        assert!(capture.current());
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
        assert!(registry.capture(&snapshot, &runtime, &prepared).is_err());
        let retained_entry = capture.entry.clone();
        drop(capture);
        assert!(!registry.check(&reference, &digest, uri, method));
        assert!(Arc::ptr_eq(&retained_entry.snapshot, &snapshot));
        assert!(
            registry
                .capture(&snapshot, &runtime, &prepared)
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
                .capture(&snapshot, &runtime, &prepared)
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
                .capture(&snapshot, &foreign_runtime, &prepared)
                .is_err()
        );
        assert!(
            registry
                .capture(&snapshot, &runtime, &foreign_prepared)
                .is_err()
        );
        let capture = registry.capture(&snapshot, &runtime, &prepared).unwrap();
        registry
            .active
            .store(Arc::new(Snapshot::new(snapshot.config.clone()).unwrap()));
        assert!(!capture.current());
        assert!(registry.capture(&snapshot, &runtime, &prepared).is_err());
    }
    #[tokio::test]
    async fn expiry_refuses_even_while_the_native_request_remains_held() {
        let (registry, snapshot, runtime, prepared) = fixture(1).await;
        let capture = registry.capture(&snapshot, &runtime, &prepared).unwrap();
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
                let capture = registry.capture(&snapshot, &runtime, &prepared);
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
