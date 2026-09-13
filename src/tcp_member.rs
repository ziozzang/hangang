//! Logical named-member established TCP stream activity, independent of health
//! generations and admission gates. This is not a drain-completion signal.
use crate::pool_member::Backend;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Debug, Default)]
pub struct StreamCounter(AtomicUsize);

impl StreamCounter {
    pub fn active(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }

    pub fn acquire(self: &Arc<Self>) -> Option<StreamLease> {
        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .ok()?;
        Some(StreamLease(Arc::clone(self)))
    }
}

/// Exactly one established stream owner. Dropping the copy future drops this
/// lease, including errors, idle expiry and cancellation.
#[derive(Debug)]
pub struct StreamLease(Arc<StreamCounter>);

impl Drop for StreamLease {
    fn drop(&mut self) {
        let previous = self.0.0.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(previous > 0, "stream lease released twice");
    }
}

#[derive(Debug)]
pub struct TcpMemberActivity {
    nodes: Vec<Option<Arc<StreamCounter>>>,
}

impl TcpMemberActivity {
    /// Reuse only continuously present named IDs within the same route. An
    /// endpoint change preserves logical activity but must not preserve health.
    pub fn new(backends: &[Backend], previous: Option<(&[Backend], &Self)>) -> Self {
        let old: HashMap<_, _> = previous
            .into_iter()
            .flat_map(|(backends, activity)| {
                backends
                    .iter()
                    .enumerate()
                    .filter_map(move |(index, backend)| {
                        Some((backend.id()?, activity.node(index)?))
                    })
            })
            .collect();
        Self {
            nodes: backends
                .iter()
                .map(|backend| {
                    backend
                        .id()
                        .map(|id| old.get(id).cloned().unwrap_or_default())
                })
                .collect(),
        }
    }

    pub fn node(&self, index: usize) -> Option<Arc<StreamCounter>> {
        self.nodes.get(index).cloned().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_is_exactly_once_and_overflow_fails_closed() {
        let counter = Arc::new(StreamCounter::default());
        let first = counter.acquire().unwrap();
        let second = counter.acquire().unwrap();
        assert_eq!(counter.active(), 2);
        drop(first);
        assert_eq!(counter.active(), 1);
        drop(second);
        assert_eq!(counter.active(), 0);
        counter.0.store(usize::MAX, Ordering::Relaxed);
        assert!(counter.acquire().is_none());
        assert_eq!(counter.active(), usize::MAX);
    }
}
