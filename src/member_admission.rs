//! Generation-local admission and activity count. Preparation starts closed;
//! retirement is irreversible. This primitive does not publish lifecycle intent.
use std::sync::atomic::{AtomicUsize, Ordering};

const RETIRED: usize = 1 << (usize::BITS - 1);
const PENDING: usize = 1 << (usize::BITS - 2);
const COUNT: usize = PENDING - 1;

#[derive(Debug)]
pub struct MemberAdmission(AtomicUsize);
impl Default for MemberAdmission {
    fn default() -> Self {
        Self::serving()
    }
}
impl MemberAdmission {
    pub fn prepared() -> Self {
        Self(AtomicUsize::new(PENDING))
    }
    pub fn serving() -> Self {
        Self(AtomicUsize::new(0))
    }
    /// Only a never-published generation may activate. A retired generation
    /// cannot be reopened by an old activation plan.
    pub fn activate(&self) -> bool {
        self.0
            .compare_exchange(PENDING, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
    pub fn retire(&self) {
        self.0.fetch_or(RETIRED, Ordering::AcqRel);
    }
    pub fn is_open(&self) -> bool {
        self.0.load(Ordering::Acquire) & (PENDING | RETIRED) == 0
    }
    pub fn active(&self) -> usize {
        self.0.load(Ordering::Acquire) & COUNT
    }
    /// Closure and count acquisition share one atomic linearization point.
    pub(crate) fn acquire(&self) -> bool {
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (state & (PENDING | RETIRED) == 0 && state & COUNT < COUNT).then(|| state + 1)
            })
            .is_ok()
    }
    pub(crate) fn release(&self) {
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (state & COUNT != 0).then(|| state - 1)
            })
            .expect("member admission release requires an acquired lease");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn prepared_and_retired_generations_never_admit_or_reopen() {
        let gate = MemberAdmission::prepared();
        assert!(!gate.acquire());
        assert!(gate.activate());
        assert!(gate.acquire());
        gate.retire();
        assert_eq!(gate.active(), 1);
        assert!(!gate.acquire());
        assert!(!gate.activate());
        gate.release();
        assert_eq!(gate.active(), 0);
        assert!(!gate.is_open());
        let abandoned = MemberAdmission::prepared();
        abandoned.retire();
        assert!(!abandoned.activate());
    }

    #[test]
    fn retirement_races_admission_without_losing_existing_counts() {
        for _ in 0..64 {
            let gate = Arc::new(MemberAdmission::serving());
            let start = Arc::new(Barrier::new(9));
            let workers: Vec<_> = (0..8)
                .map(|_| {
                    let gate = gate.clone();
                    let start = start.clone();
                    std::thread::spawn(move || {
                        start.wait();
                        gate.acquire()
                    })
                })
                .collect();
            start.wait();
            gate.retire();
            let acquired = workers
                .into_iter()
                .map(|worker| usize::from(worker.join().unwrap()))
                .sum::<usize>();
            assert_eq!(gate.active(), acquired);
            for _ in 0..8 {
                assert!(
                    !gate.acquire(),
                    "nothing may acquire after retirement returned"
                );
            }
            for _ in 0..acquired {
                gate.release();
            }
            assert_eq!(gate.active(), 0);
            assert!(!gate.activate());
        }
    }

    #[test]
    fn full_counter_rejects_admission_without_corrupting_flags() {
        let gate = MemberAdmission(AtomicUsize::new(COUNT));
        assert!(!gate.acquire());
        gate.retire();
        gate.release();
        assert_eq!(gate.active(), COUNT - 1);
        assert!(!gate.is_open());
    }
}
