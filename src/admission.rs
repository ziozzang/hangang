//! Per-route in-flight counts survive configuration replacement. The global
//! admission cap remains independent; no route can exceed its configured share.
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
#[derive(Clone, Debug)]
pub struct Lease {
    _inner: Arc<Inner>,
}
#[derive(Debug)]
struct Inner(Arc<AtomicUsize>);
impl Drop for Inner {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
pub fn acquire(
    counter: &Arc<AtomicUsize>,
    limit: Option<usize>,
) -> Result<Option<Lease>, &'static str> {
    let Some(limit) = limit else { return Ok(None) };
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            if count < limit { Some(count + 1) } else { None }
        })
        .map_err(|_| "route capacity exhausted")?;
    Ok(Some(Lease {
        _inner: Arc::new(Inner(counter.clone())),
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clones_hold_one_admission_until_all_stream_owners_drop() {
        let counter = Arc::new(AtomicUsize::new(0));
        let first = acquire(&counter, Some(1)).unwrap().unwrap();
        let stream = first.clone();
        drop(first);
        assert!(acquire(&counter, Some(1)).is_err());
        drop(stream);
        assert!(acquire(&counter, Some(1)).is_ok());
    }
}
