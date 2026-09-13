//! Dynamic Docker endpoint discovery without changing persisted routes.
use crate::{
    config::{Config, Snapshot},
    docker::{DockerResolver, Resolved},
};
use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{collections::HashMap, sync::Arc, time::Duration};

const MAX_CONCURRENT_INSPECTS: usize = 8;
const REFRESH_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Http,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DockerReference {
    pub container: String,
    pub network: String,
    pub port: u16,
}

pub fn parse_reference(value: &str) -> Result<Option<DockerReference>> {
    let Some(reference) = value.strip_prefix("docker://") else {
        return Ok(None);
    };
    let mut segments = reference.split('/');
    let container = segments.next().unwrap_or_default();
    let network = segments.next().unwrap_or_default();
    let port = segments.next().unwrap_or_default();
    ensure!(
        segments.next().is_none(),
        "Docker reference must have exactly three components"
    );
    validate_name(container, "container")?;
    validate_name(network, "network")?;
    ensure!(
        !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()),
        "Docker reference port must be decimal"
    );
    let port_number: u16 = port
        .parse()
        .context("Docker reference port is out of range")?;
    ensure!(port_number > 0, "Docker reference port must be nonzero");
    ensure!(
        port_number.to_string() == port,
        "Docker reference port must use canonical decimal form"
    );
    Ok(Some(DockerReference {
        container: container.to_owned(),
        network: network.to_owned(),
        port: port_number,
    }))
}

#[derive(Clone)]
pub struct Discovery {
    resolver: Option<Arc<DockerResolver>>,
    managed: Option<Arc<crate::docker_connections::DockerConnections>>,
    resolved: Arc<ArcSwap<ResolvedSnapshot>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub endpoint: String,
    pub epoch: u64,
}

struct ResolvedSnapshot {
    generation: u64,
    values: HashMap<String, Resolved>,
    epochs: HashMap<String, u64>,
}

impl ResolvedSnapshot {
    fn empty(generation: u64) -> Self {
        Self {
            generation,
            values: HashMap::new(),
            epochs: HashMap::new(),
        }
    }
}

impl Discovery {
    pub fn new(resolver: Option<Arc<DockerResolver>>) -> Self {
        Self {
            resolver,
            managed: None,
            resolved: Arc::new(ArcSwap::from_pointee(ResolvedSnapshot::empty(0))),
        }
    }

    pub fn managed(connections: Arc<crate::docker_connections::DockerConnections>) -> Self {
        Self {
            resolver: None,
            managed: Some(connections),
            resolved: Arc::new(ArcSwap::from_pointee(ResolvedSnapshot::empty(0))),
        }
    }

    pub fn resolve(&self, backend: &str, protocol: Protocol) -> Option<String> {
        self.resolve_with_epoch(backend, protocol)
            .map(|target| target.endpoint)
    }

    /// The epoch changes on address or managed-daemon generation changes and
    /// after removal/reappearance. Identical periodic refreshes retain it.
    pub fn resolve_with_epoch(&self, backend: &str, protocol: Protocol) -> Option<ResolvedTarget> {
        if !backend.starts_with("docker://") {
            return Some(ResolvedTarget {
                endpoint: backend.to_owned(),
                epoch: 0,
            });
        }
        let generation = self.managed.as_ref().map(|manager| manager.generation());
        let values = self.resolved.load();
        if generation.is_some_and(|generation| values.generation != generation) {
            return None;
        }
        let resolved = values.values.get(backend)?;
        let address = match protocol {
            Protocol::Http => resolved.http_backend.clone(),
            Protocol::Tcp => resolved.tcp_backend.clone(),
        };
        // The manager can disable or replace a daemon between the first
        // generation check and loading the cached address.
        if generation.is_some_and(|generation| {
            self.managed
                .as_ref()
                .is_some_and(|manager| manager.generation() != generation)
        }) {
            return None;
        }
        Some(ResolvedTarget {
            endpoint: address,
            epoch: *values.epochs.get(backend)?,
        })
    }

    fn publish(&self, generation: u64, next: HashMap<String, Resolved>) {
        static NEXT_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        self.resolved.rcu(|previous| {
            let epochs = next
                .iter()
                .map(|(name, value)| {
                    let retained = (previous.generation == generation
                        && value.identity.is_some()
                        && previous.values.get(name) == Some(value))
                    .then(|| previous.epochs.get(name).copied())
                    .flatten();
                    let epoch = retained.unwrap_or_else(|| {
                        NEXT_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    });
                    (name.clone(), epoch)
                })
                .collect();
            Arc::new(ResolvedSnapshot {
                generation,
                values: next.clone(),
                epochs,
            })
        });
    }

    /// Refresh every unique Docker reference and publish one complete map.
    /// Failed references are deliberately absent from the new map so a stopped
    /// or removed container cannot keep receiving traffic through stale data.
    pub async fn refresh(&self, config: &Config) -> Result<()> {
        match tokio::time::timeout(REFRESH_DEADLINE, self.refresh_inner(config)).await {
            Ok(result) => result,
            Err(_) => {
                // The full batch has one deadline. Clearing here is essential:
                // otherwise a large or stalled batch could preserve an address
                // after its container has disappeared.
                self.resolved.store(Arc::new(ResolvedSnapshot::empty(
                    self.managed
                        .as_ref()
                        .map_or(0, |manager| manager.generation()),
                )));
                anyhow::bail!(
                    "Docker discovery refresh exceeded {} seconds",
                    REFRESH_DEADLINE.as_secs()
                )
            }
        }
    }

    async fn refresh_inner(&self, config: &Config) -> Result<()> {
        let (generation, resolver) = self.managed.as_ref().map_or_else(
            || (0, self.resolver.clone()),
            |manager| manager.generation_resolver(),
        );
        let mut references = HashMap::<String, DockerReference>::new();
        for backend in config
            .http
            .iter()
            .filter(|route| route.enabled)
            .flat_map(|route| route.backends.iter())
            .chain(
                config
                    .tcp
                    .iter()
                    .filter(|route| route.enabled)
                    .flat_map(|route| route.backends.iter()),
            )
        {
            let backend = backend.address();
            if let Some(reference) = parse_reference(backend)? {
                references.entry(backend.to_owned()).or_insert(reference);
            }
        }
        if references.is_empty() {
            self.resolved
                .store(Arc::new(ResolvedSnapshot::empty(generation)));
            return Ok(());
        }
        let Some(resolver) = resolver else {
            self.resolved
                .store(Arc::new(ResolvedSnapshot::empty(generation)));
            anyhow::bail!(
                "Docker discovery is disabled but the configuration contains Docker references"
            );
        };

        let mut pending = references.into_iter();
        let mut inspections = FuturesUnordered::new();
        for _ in 0..MAX_CONCURRENT_INSPECTS {
            if let Some((source, reference)) = pending.next() {
                inspections.push(inspect(resolver.clone(), source, reference));
            }
        }
        let mut next = HashMap::new();
        let mut errors = Vec::new();
        while let Some((source, result)) = inspections.next().await {
            match result {
                Ok(resolved) => {
                    next.insert(source, resolved);
                }
                Err(error) => errors.push(format!("{source}: {error}")),
            }
            if let Some((source, reference)) = pending.next() {
                inspections.push(inspect(resolver.clone(), source, reference));
            }
        }
        if self
            .managed
            .as_ref()
            .is_some_and(|manager| manager.generation() != generation)
        {
            self.resolved
                .store(Arc::new(ResolvedSnapshot::empty(generation)));
            anyhow::bail!("Docker connection changed during discovery refresh");
        }
        self.publish(generation, next);
        if errors.is_empty() {
            Ok(())
        } else {
            errors.sort();
            let omitted = errors.len().saturating_sub(8);
            errors.truncate(8);
            let mut detail = errors.join("; ");
            if omitted > 0 {
                detail.push_str(&format!("; and {omitted} more"));
            }
            anyhow::bail!("one or more Docker references could not be resolved: {detail}")
        }
    }

    pub async fn watch(
        self: Arc<Self>,
        active: Arc<ArcSwap<Snapshot>>,
        cancel: tokio_util::sync::CancellationToken,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = interval.tick() => {}
            }
            let snapshot = active.load_full();
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                result = self.refresh(&snapshot.config) => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "Docker discovery refresh incomplete; failed endpoints removed");
                    }
                }
            }
        }
    }
}

async fn inspect(
    resolver: Arc<DockerResolver>,
    source: String,
    reference: DockerReference,
) -> (String, Result<Resolved>) {
    let result = resolver
        .resolve(&reference.container, &reference.network, reference.port)
        .await;
    (source, result)
}

fn validate_name(value: &str, label: &str) -> Result<()> {
    let bytes = value.as_bytes();
    ensure!(
        !bytes.is_empty()
            && bytes.len() <= 128
            && bytes[0].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(byte)),
        "invalid Docker {label} name"
    );
    Ok(())
}

#[cfg(test)]
mod epoch_tests {
    use super::*;

    fn value(address: &str, identity: Option<&str>) -> Resolved {
        Resolved {
            http_backend: format!("http://{address}"),
            tcp_backend: address.into(),
            identity: identity.map(str::to_owned),
        }
    }

    #[test]
    fn endpoint_epochs_retain_stable_identity_and_fence_address_restart_and_removal_aba() {
        let discovery = Discovery::new(None);
        let reference = "docker://app/edge/80";
        let publish = |generation, endpoint| {
            discovery.publish(
                generation,
                HashMap::from([(reference.to_owned(), endpoint)]),
            )
        };
        let target = || {
            discovery
                .resolve_with_epoch(reference, Protocol::Tcp)
                .unwrap()
        };
        publish(1, value("127.0.0.1:9001", Some("process-1")));
        let first = target();
        publish(1, value("127.0.0.1:9001", Some("process-1")));
        assert_eq!(
            target(),
            first,
            "identical refresh must not starve qualification"
        );
        publish(1, value("127.0.0.1:9001", Some("process-2")));
        let restarted = target();
        assert!(restarted.epoch > first.epoch);
        publish(1, value("127.0.0.1:9002", Some("process-2")));
        let moved = target();
        assert!(moved.epoch > restarted.epoch);
        publish(1, value("127.0.0.1:9001", Some("process-1")));
        assert!(
            target().epoch > moved.epoch,
            "address/identity ABA must not revive an old probe"
        );
        let before_remove = target();
        discovery.publish(1, HashMap::new());
        assert!(discovery.resolve(reference, Protocol::Tcp).is_none());
        publish(1, value("127.0.0.1:9001", Some("process-1")));
        assert!(target().epoch > before_remove.epoch);
        let before_daemon = target();
        publish(2, value("127.0.0.1:9001", Some("process-1")));
        assert!(target().epoch > before_daemon.epoch);
    }

    #[test]
    fn unknown_inspect_identity_does_not_reuse_qualification_across_refreshes() {
        let discovery = Discovery::new(None);
        let reference = "docker://app/edge/80";
        let publish = || {
            discovery.publish(
                0,
                HashMap::from([(reference.to_owned(), value("127.0.0.1:9001", None))]),
            )
        };
        publish();
        let first = discovery
            .resolve_with_epoch(reference, Protocol::Tcp)
            .unwrap();
        publish();
        assert!(
            discovery
                .resolve_with_epoch(reference, Protocol::Tcp)
                .unwrap()
                .epoch
                > first.epoch
        );
    }
}
