//! Process-local monotonic infrastructure, not authorization or source evidence.
//! Linux BOOTTIME includes host suspend and cannot jump with the UTC wall clock.
//! No live token can be reconstructed from persisted ticks or a wire generation.
#[cfg(test)]
mod tests;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

const MAXIMUM: u64 = 9_007_199_254_740_991;
const NANOS_PER_MS: u128 = 1_000_000;

#[derive(Debug, PartialEq, Eq)]
pub enum TimeError {
    InvalidGeneration,
    UnsupportedClock,
    ClockRead,
    WrongClock,
    Retired,
    Overflow,
    InvalidBounds,
    Expired,
}

#[derive(Clone)]
enum Source {
    System,
    #[cfg(test)]
    Controlled(Arc<dyn Fn() -> Result<u128, TimeError> + Send + Sync>),
}
impl Source {
    fn now_ns(&self) -> Result<u128, TimeError> {
        match self {
            Self::System => system_ns(),
            #[cfg(test)]
            Self::Controlled(read) => read(),
        }
    }
}
#[cfg(target_os = "linux")]
fn system_ns() -> Result<u128, TimeError> {
    use rustix::time::{ClockId, DynamicClockId, clock_gettime_dynamic};
    let sample = clock_gettime_dynamic(DynamicClockId::Known(ClockId::Boottime))
        .map_err(|_| TimeError::ClockRead)?;
    let seconds = u128::try_from(sample.tv_sec).map_err(|_| TimeError::ClockRead)?;
    let nanos = u128::try_from(sample.tv_nsec)
        .ok()
        .filter(|v| *v < 1_000_000_000)
        .ok_or(TimeError::ClockRead)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(nanos))
        .ok_or(TimeError::Overflow)
}
#[cfg(not(target_os = "linux"))]
fn system_ns() -> Result<u128, TimeError> {
    Err(TimeError::UnsupportedClock)
}

fn duration(nanos: u128) -> Result<Duration, TimeError> {
    Ok(Duration::new(
        u64::try_from(nanos / 1_000_000_000).map_err(|_| TimeError::Overflow)?,
        (nanos % 1_000_000_000) as u32,
    ))
}

/// Opaque native elapsed-time sample for original proof budgets. Includes Linux
/// host suspend, with no numeric constructor, serialization or weaker fallback.
/// Short-lived process evidence only; not a persisted or remote clock capability.
pub struct ElapsedStamp {
    source: Source,
    started_ns: u128,
}
impl ElapsedStamp {
    pub fn now() -> Result<Self, TimeError> {
        Self::from_source(Source::System)
    }
    fn from_source(source: Source) -> Result<Self, TimeError> {
        let started_ns = source.now_ns()?;
        Ok(Self { source, started_ns })
    }
    pub fn elapsed(&self) -> Result<Duration, TimeError> {
        duration(
            self.source
                .now_ns()?
                .checked_sub(self.started_ns)
                .ok_or(TimeError::ClockRead)?,
        )
    }
}

struct Domain {
    generation: [u8; 16],
    origin_ns: u128,
    active: AtomicBool,
    source: Source,
}
impl Domain {
    fn sample(&self) -> Result<(u128, u64), TimeError> {
        let nanos = self
            .source
            .now_ns()?
            .checked_sub(self.origin_ns)
            .ok_or(TimeError::ClockRead)?;
        let ticks = u64::try_from(nanos / NANOS_PER_MS)
            .ok()
            .and_then(|v| v.checked_add(1))
            .filter(|v| *v <= MAXIMUM)
            .ok_or(TimeError::Overflow)?;
        Ok((nanos, ticks))
    }
    fn current(&self) -> Result<(), TimeError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(TimeError::Retired);
        }
        Ok(())
    }
}

/// Native startup supplies a fresh, nonzero CSPRNG generation. Its bytes are
/// persistence metadata only: private instance identity also binds every token.
/// No per-request heap allocation, lock, SQL, network call or wall-clock read.
pub struct ReceiverClock {
    domain: Arc<Domain>,
}
pub struct ExchangeStart {
    domain: Arc<Domain>,
    nanos: u128,
    ticks: u64,
}
pub struct ExchangeSample {
    domain: Arc<Domain>,
    before_ticks: u64,
    after_ticks: u64,
    elapsed_ms: u64,
}
/// An infrastructure lower expiry bound, never a permission capability.
pub struct LocalDeadline {
    domain: Arc<Domain>,
    ticks: u64,
}
/// A distinct infrastructure upper retention bound, never an admission deadline.
pub struct ReplayRetention {
    domain: Arc<Domain>,
    ticks: u64,
}
impl ReceiverClock {
    pub fn new(generation: [u8; 16]) -> Result<Self, TimeError> {
        Self::from_source(generation, Source::System)
    }
    fn from_source(generation: [u8; 16], source: Source) -> Result<Self, TimeError> {
        if generation == [0; 16] {
            return Err(TimeError::InvalidGeneration);
        }
        let origin_ns = source.now_ns()?;
        Ok(Self {
            domain: Arc::new(Domain {
                generation,
                origin_ns,
                active: AtomicBool::new(true),
                source,
            }),
        })
    }
    pub fn generation(&self) -> &[u8; 16] {
        &self.domain.generation
    }
    /// Retire admission only; existing retention can still be checked on this
    /// exact clock. Retirement alone does not authorize durable row deletion.
    pub fn retire(&self) {
        self.domain.active.store(false, Ordering::Release);
    }
    /// Read this active process's positive BOOTTIME ticks with one backend read.
    /// Numeric infrastructure only: not UTC, a remote observation or permission.
    /// Keep generation/owner identity separately; failures have no weaker fallback.
    pub fn sample_ticks(&self) -> Result<u64, TimeError> {
        self.domain.current()?;
        let (_, ticks) = self.domain.sample()?;
        self.domain.current()?;
        Ok(ticks)
    }
    pub fn begin_exchange(&self) -> Result<ExchangeStart, TimeError> {
        self.domain.current()?;
        let (nanos, ticks) = self.domain.sample()?;
        self.domain.current()?;
        Ok(ExchangeStart {
            domain: self.domain.clone(),
            nanos,
            ticks,
        })
    }
    pub fn finish_exchange(&self, start: ExchangeStart) -> Result<ExchangeSample, TimeError> {
        if !Arc::ptr_eq(&self.domain, &start.domain) {
            return Err(TimeError::WrongClock);
        }
        self.domain.current()?;
        let (nanos, after_ticks) = self.domain.sample()?;
        let elapsed_ms = u64::try_from(
            nanos
                .checked_sub(start.nanos)
                .ok_or(TimeError::ClockRead)?
                .div_ceil(NANOS_PER_MS),
        )
        .map_err(|_| TimeError::Overflow)?;
        self.domain.current()?;
        Ok(ExchangeSample {
            domain: self.domain.clone(),
            before_ticks: start.ticks,
            after_ticks,
            elapsed_ms,
        })
    }
}
impl ExchangeSample {
    pub fn before_ticks(&self) -> u64 {
        self.before_ticks
    }
    pub fn after_ticks(&self) -> u64 {
        self.after_ticks
    }
    pub fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms
    }
    /// Bind separately validated arithmetic results to this exchange's instance.
    /// The caller still owes authenticated source/request/client/owner evidence.
    pub fn bind_bounds(
        self,
        admission_ticks: u64,
        retention_ticks: u64,
    ) -> Result<(LocalDeadline, ReplayRetention), TimeError> {
        self.domain.current()?;
        let (_, now) = self.domain.sample()?;
        if admission_ticks <= self.after_ticks
            || admission_ticks <= now
            || retention_ticks < admission_ticks
            || retention_ticks > MAXIMUM
        {
            return Err(TimeError::InvalidBounds);
        }
        self.domain.current()?;
        Ok((
            LocalDeadline {
                domain: self.domain.clone(),
                ticks: admission_ticks,
            },
            ReplayRetention {
                domain: self.domain,
                ticks: retention_ticks,
            },
        ))
    }
}
impl LocalDeadline {
    pub fn check(&self, clock: &ReceiverClock) -> Result<(), TimeError> {
        self.remaining(clock).map(|_| ())
    }
    pub fn remaining(&self, clock: &ReceiverClock) -> Result<Duration, TimeError> {
        if !Arc::ptr_eq(&self.domain, &clock.domain) {
            return Err(TimeError::WrongClock);
        }
        self.domain.current()?;
        let (nanos, _) = self.domain.sample()?;
        let expiry_ns = u128::from(self.ticks - 1)
            .checked_mul(NANOS_PER_MS)
            .ok_or(TimeError::Overflow)?;
        let left = expiry_ns
            .checked_sub(nanos)
            .filter(|v| *v > 0)
            .ok_or(TimeError::Expired)?;
        let remaining = duration(left)?;
        self.domain.current()?;
        Ok(remaining)
    }
    pub fn restrict(self, previous: Self) -> Result<Self, TimeError> {
        if !Arc::ptr_eq(&self.domain, &previous.domain) {
            return Err(TimeError::WrongClock);
        }
        Ok(Self {
            domain: self.domain,
            ticks: self.ticks.min(previous.ticks),
        })
    }
}
impl ReplayRetention {
    pub fn elapsed(&self, clock: &ReceiverClock) -> Result<bool, TimeError> {
        if !Arc::ptr_eq(&self.domain, &clock.domain) {
            return Err(TimeError::WrongClock);
        }
        let (_, now) = self.domain.sample()?;
        Ok(now >= self.ticks)
    }
    pub fn ticks(&self) -> u64 {
        self.ticks
    }
    pub fn extend(self, previous: Self) -> Result<Self, TimeError> {
        if !Arc::ptr_eq(&self.domain, &previous.domain) {
            return Err(TimeError::WrongClock);
        }
        Ok(Self {
            domain: self.domain,
            ticks: self.ticks.max(previous.ticks),
        })
    }
}
