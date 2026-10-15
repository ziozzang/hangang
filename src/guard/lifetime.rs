//! Original query-relative budget; Linux suspend ages every retained capture.
use std::{sync::Mutex, time::Duration};

#[cfg(test)]
pub(super) type TestClock = std::sync::Arc<Mutex<Option<Duration>>>;

pub(super) struct Lifetime {
    source: Source,
    state: Mutex<State>,
}
struct State {
    last: Duration,
    failed: bool,
}
enum Source {
    #[cfg(target_os = "linux")]
    Boottime(hangang_runtime::time::ElapsedStamp),
    #[cfg(not(target_os = "linux"))]
    Legacy(std::time::Instant),
    #[cfg(test)]
    Manual(TestClock),
}
impl Lifetime {
    pub(super) fn start() -> anyhow::Result<Self> {
        Ok(Self {
            source: {
                #[cfg(target_os = "linux")]
                {
                    Source::Boottime(
                        hangang_runtime::time::ElapsedStamp::now()
                            .map_err(|_| anyhow::anyhow!("guard elapsed clock unavailable"))?,
                    )
                }
                #[cfg(not(target_os = "linux"))]
                {
                    Source::Legacy(std::time::Instant::now())
                }
            },
            state: Mutex::new(State {
                last: Duration::ZERO,
                failed: false,
            }),
        })
    }
    pub(super) fn remaining(&self, ttl_ms: u64) -> Option<Duration> {
        let mut state = self.state.lock().ok()?;
        if state.failed {
            return None;
        }
        let elapsed = match &self.source {
            #[cfg(target_os = "linux")]
            Source::Boottime(stamp) => stamp.elapsed().ok(),
            #[cfg(not(target_os = "linux"))]
            Source::Legacy(stamp) => Some(stamp.elapsed()),
            #[cfg(test)]
            Source::Manual(now) => *now.lock().ok()?,
        };
        let Some(elapsed) = elapsed else {
            state.failed = true;
            return None;
        };
        if elapsed < state.last {
            state.failed = true;
            return None;
        }
        state.last = elapsed;
        // The source exports whole milliseconds; one source quantum cannot be
        // counted as guaranteed remaining time. TTL zero never creates a lease.
        let remaining = Duration::from_millis(ttl_ms.checked_sub(1)?).checked_sub(elapsed)?;
        (!remaining.is_zero()).then_some(remaining)
    }
    #[cfg(test)]
    pub(super) fn manual(now: TestClock) -> Self {
        Self {
            source: Source::Manual(now),
            state: Mutex::new(State {
                last: Duration::ZERO,
                failed: false,
            }),
        }
    }
}
