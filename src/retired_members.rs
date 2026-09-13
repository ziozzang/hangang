//! Bounded, process-local history of member generations retired at publication.
//! A reservation accounts for the worst case before a durable commit. Only
//! `Reservation::commit` closes gates; validating or abandoning a candidate is
//! observational and cannot affect traffic.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::{balance::BackendRetirement, member_admission::MemberAdmission};

pub const CAPACITY: usize = 4096;

pub(crate) enum Counter {
    Http(BackendRetirement),
    Tcp(Arc<MemberAdmission>),
}

impl Counter {
    pub(crate) fn retire(&self) {
        match self {
            Self::Http(counter) => counter.retire(),
            Self::Tcp(counter) => counter.retire(),
        }
    }

    pub(crate) fn active(&self) -> usize {
        match self {
            Self::Http(counter) => counter.active(),
            Self::Tcp(counter) => counter.active(),
        }
    }
}

pub(crate) struct Record {
    pub(crate) protocol: &'static str,
    pub(crate) route_id: String,
    pub(crate) member_id: Option<String>,
    pub(crate) address: String,
    pub(crate) counter: Counter,
}

struct Entry {
    retirement_id: u64,
    record: Record,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Observation {
    pub retirement_id: u64,
    pub protocol: &'static str,
    pub route_id: String,
    pub member_id: Option<String>,
    pub address: String,
    pub active_admissions: usize,
}

struct Inner {
    records: Vec<Entry>,
    pending: usize,
    next_id: u64,
}

pub struct Registry {
    inner: Mutex<Inner>,
    capacity: usize,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner {
                records: Vec::new(),
                pending: 0,
                next_id: 1,
            }),
            capacity: CAPACITY,
        }
    }
}

pub(crate) struct Reservation {
    registry: Arc<Registry>,
    slots: usize,
}

impl Registry {
    /// Prune completed retirements and reserve space for every possible new
    /// record. Existing active generations are never evicted to make room.
    pub(crate) fn reserve(self: &Arc<Self>, count: usize) -> Result<Reservation> {
        if count == 0 {
            return Ok(Reservation {
                registry: Arc::clone(self),
                slots: 0,
            });
        }
        let mut inner = self
            .inner
            .lock()
            .expect("retired member registry lock poisoned");
        inner
            .records
            .retain(|entry| entry.record.counter.active() > 0);
        let occupied = inner.records.len() + inner.pending;
        ensure!(
            count <= self.capacity.saturating_sub(occupied),
            "retired member registry capacity exceeded"
        );
        ensure!(
            inner
                .next_id
                .checked_add(u64::try_from(inner.pending + count)?)
                .is_some(),
            "retired member registry identifier exhausted"
        );
        // Account for every outstanding reservation. Commit happens after
        // durable publication, so it must not need to grow this vector.
        let additional = inner.pending + count;
        inner
            .records
            .try_reserve(additional)
            .context("retired member registry allocation failed")?;
        inner.pending += count;
        Ok(Reservation {
            registry: Arc::clone(self),
            slots: count,
        })
    }

    /// An active-only, point-in-time view. Pending reservations are not
    /// visible; completion is observed when the last lease has dropped.
    pub fn snapshot(&self) -> Vec<Observation> {
        let mut inner = self
            .inner
            .lock()
            .expect("retired member registry lock poisoned");
        inner
            .records
            .retain(|entry| entry.record.counter.active() > 0);
        inner
            .records
            .iter()
            .filter_map(|entry| {
                let active_admissions = entry.record.counter.active();
                (active_admissions > 0).then(|| Observation {
                    retirement_id: entry.retirement_id,
                    protocol: entry.record.protocol,
                    route_id: entry.record.route_id.clone(),
                    member_id: entry.record.member_id.clone(),
                    address: entry.record.address.clone(),
                    active_admissions,
                })
            })
            .collect()
    }
}

impl Reservation {
    /// This has no capacity failure when `records.len() <= reserved slots`.
    /// Retiring and recording happen under one lock so no reader sees a live
    /// retirement entry whose gate is still open.
    pub(crate) fn commit(mut self, records: Vec<Record>) {
        assert!(
            records.len() <= self.slots,
            "retirement exceeds reservation"
        );
        let mut inner = self
            .registry
            .inner
            .lock()
            .expect("retired member registry lock poisoned");
        inner.pending -= self.slots;
        self.slots = 0;
        for record in records {
            record.counter.retire();
            let retirement_id = inner.next_id;
            inner.next_id += 1; // reserve checked this entire identifier range
            if record.counter.active() > 0 {
                inner.records.push(Entry {
                    retirement_id,
                    record,
                });
            }
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.slots != 0 {
            let mut inner = self
                .registry
                .inner
                .lock()
                .expect("retired member registry lock poisoned");
            inner.pending -= self.slots;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    fn registry(capacity: usize) -> Arc<Registry> {
        let mut registry = Registry::default();
        registry.capacity = capacity;
        Arc::new(registry)
    }

    fn tcp_record(name: &str, gate: &Arc<MemberAdmission>) -> Record {
        Record {
            protocol: "tcp",
            route_id: "route".to_owned(),
            member_id: Some(name.to_owned()),
            address: "127.0.0.1:9000".to_owned(),
            counter: Counter::Tcp(Arc::clone(gate)),
        }
    }

    #[test]
    fn abandoned_reservations_do_not_retire_or_consume_slots() {
        let registry = registry(1);
        let gate = Arc::new(MemberAdmission::serving());
        let lease = gate.lease().unwrap();
        let reservation = registry.reserve(1).unwrap();
        assert!(registry.reserve(1).is_err());
        assert!(registry.snapshot().is_empty());
        assert!(gate.is_open());
        drop(reservation);
        assert!(registry.reserve(1).is_ok());
        assert!(lease.is_open());
    }

    #[test]
    fn live_records_block_capacity_until_last_lease_releases() {
        let registry = registry(1);
        let gate = Arc::new(MemberAdmission::serving());
        let lease = gate.lease().unwrap();
        registry
            .reserve(1)
            .unwrap()
            .commit(vec![tcp_record("first", &gate)]);
        assert!(!gate.is_open());
        assert!(gate.lease().is_none());
        assert_eq!(registry.snapshot()[0].active_admissions, 1);
        assert!(
            registry.reserve(1).is_err(),
            "active history cannot be evicted"
        );
        drop(lease);
        assert!(registry.snapshot().is_empty());

        let next = Arc::new(MemberAdmission::serving());
        registry
            .reserve(1)
            .unwrap()
            .commit(vec![tcp_record("second", &next)]);
        assert!(!next.is_open());
        assert!(
            registry.snapshot().is_empty(),
            "zero-count record is omitted"
        );
    }

    #[test]
    fn concurrent_reservations_share_one_capacity_budget() {
        let registry = registry(1);
        let barrier = Arc::new(Barrier::new(3));
        let tasks: Vec<_> = (0..2)
            .map(|_| {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let reservation = registry.reserve(1).ok();
                    barrier.wait();
                    reservation
                })
            })
            .collect();
        barrier.wait();
        barrier.wait();
        let reservations: Vec<_> = tasks
            .into_iter()
            .filter_map(|task| task.join().unwrap())
            .collect();
        assert_eq!(reservations.len(), 1);
        assert!(registry.reserve(1).is_err());
        drop(reservations);
        assert!(registry.reserve(1).is_ok());
    }

    #[test]
    fn unused_slots_return_and_retirement_ids_increase() {
        let registry = registry(2);
        let first = Arc::new(MemberAdmission::serving());
        let first_lease = first.lease().unwrap();
        registry
            .reserve(2)
            .unwrap()
            .commit(vec![tcp_record("first", &first)]);
        let first_id = registry.snapshot()[0].retirement_id;
        assert!(registry.reserve(2).is_err());

        let second = Arc::new(MemberAdmission::serving());
        let second_lease = second.lease().unwrap();
        registry
            .reserve(1)
            .unwrap()
            .commit(vec![tcp_record("second", &second)]);
        let state = registry.snapshot();
        assert_eq!(state.len(), 2);
        assert!(state[1].retirement_id > first_id);
        drop(first_lease);
        drop(second_lease);
        assert!(registry.snapshot().is_empty());
    }
}
