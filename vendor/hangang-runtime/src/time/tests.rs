use super::*;

#[cfg(target_os = "linux")]
#[test]
fn linux_native_boottime_backend_produces_instance_bound_live_tokens() {
    let clock = ReceiverClock::new([21; 16]).unwrap();
    let other = ReceiverClock::new([21; 16]).unwrap();
    let start = clock.begin_exchange().unwrap();
    let exchange = clock.finish_exchange(start).unwrap();
    assert!(exchange.before_ticks() > 0);
    assert!(exchange.after_ticks() >= exchange.before_ticks());
    let expiry = exchange.after_ticks() + 1000;
    let (deadline, retention) = exchange.bind_bounds(expiry, expiry + 1).unwrap();
    assert!(deadline.check(&clock).is_ok());
    assert_eq!(deadline.check(&other), Err(TimeError::WrongClock));
    assert_eq!(retention.elapsed(&clock), Ok(false));
    assert_eq!(retention.elapsed(&other), Err(TimeError::WrongClock));
}
use std::sync::atomic::{AtomicU64, AtomicUsize};

const ORIGIN_NS: u64 = 10_000_000;

struct Controlled {
    now: Arc<AtomicU64>,
    fail: Arc<AtomicBool>,
}

impl Controlled {
    fn new(generation: [u8; 16]) -> (Self, ReceiverClock) {
        let now = Arc::new(AtomicU64::new(ORIGIN_NS));
        let fail = Arc::new(AtomicBool::new(false));
        let read_now = now.clone();
        let read_fail = fail.clone();
        let clock = ReceiverClock::from_source(
            generation,
            Source::Controlled(Arc::new(move || {
                if read_fail.load(Ordering::Acquire) {
                    return Err(TimeError::ClockRead);
                }
                Ok(u128::from(read_now.load(Ordering::Acquire)))
            })),
        )
        .unwrap();
        (Self { now, fail }, clock)
    }

    fn elapsed_ns(&self, nanos: u64) {
        self.now.store(ORIGIN_NS + nanos, Ordering::Release);
    }

    fn failing(&self, fail: bool) {
        self.fail.store(fail, Ordering::Release);
    }
}

fn sample(clock: &ReceiverClock) -> ExchangeSample {
    clock
        .finish_exchange(clock.begin_exchange().unwrap())
        .unwrap()
}

fn bounds(clock: &ReceiverClock, admit: u64, retain: u64) -> (LocalDeadline, ReplayRetention) {
    sample(clock).bind_bounds(admit, retain).unwrap()
}

#[test]
fn elapsed_stamp_preserves_fraction_and_suspend_without_resetting_its_origin() {
    let (source, clock) = Controlled::new([23; 16]);
    let stamp = ElapsedStamp::from_source(clock.domain.source.clone()).unwrap();
    assert_eq!(stamp.elapsed(), Ok(Duration::ZERO));
    source.elapsed_ns(1);
    assert_eq!(stamp.elapsed(), Ok(Duration::from_nanos(1)));
    source.elapsed_ns(2_000_000_001);
    assert_eq!(stamp.elapsed(), Ok(Duration::from_nanos(2_000_000_001)));
    source.elapsed_ns(2_001_000_001);
    assert_eq!(stamp.elapsed(), Ok(Duration::from_nanos(2_001_000_001)));
}

#[test]
fn elapsed_stamp_refuses_failed_or_reversed_reads_without_fallback() {
    let (source, clock) = Controlled::new([24; 16]);
    let stamp = ElapsedStamp::from_source(clock.domain.source.clone()).unwrap();
    source.failing(true);
    assert_eq!(stamp.elapsed(), Err(TimeError::ClockRead));
    assert!(ElapsedStamp::from_source(clock.domain.source.clone()).is_err());
    source.failing(false);
    source.now.store(ORIGIN_NS - 1, Ordering::Release);
    assert_eq!(stamp.elapsed(), Err(TimeError::ClockRead));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_native_elapsed_stamp_reads_suspend_inclusive_backend() {
    let stamp = ElapsedStamp::now().unwrap();
    let first = stamp.elapsed().unwrap();
    let second = stamp.elapsed().unwrap();
    assert!(second >= first);
}

#[test]
fn native_generation_is_nonzero_and_invalid_generation_does_not_read_clock() {
    let reads = Arc::new(AtomicUsize::new(0));
    let counted = reads.clone();
    let result = ReceiverClock::from_source(
        [0; 16],
        Source::Controlled(Arc::new(move || {
            counted.fetch_add(1, Ordering::Relaxed);
            Ok(0)
        })),
    );
    assert_eq!(result.err(), Some(TimeError::InvalidGeneration));
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    let (_, clock) = Controlled::new([9; 16]);
    assert_eq!(clock.generation(), &[9; 16]);
}

#[test]
fn startup_backend_failure_refuses_without_a_fallback_clock() {
    for error in [TimeError::ClockRead, TimeError::UnsupportedClock] {
        let unsupported = error == TimeError::UnsupportedClock;
        let result = ReceiverClock::from_source(
            [1; 16],
            Source::Controlled(Arc::new(move || {
                Err(if unsupported {
                    TimeError::UnsupportedClock
                } else {
                    TimeError::ClockRead
                })
            })),
        );
        assert_eq!(result.err(), Some(error));
    }
}

#[test]
fn positive_fixed_origin_and_outward_exchange_rounding_are_exact() {
    let (source, clock) = Controlled::new([1; 16]);
    let zero = sample(&clock);
    assert_eq!(
        (zero.before_ticks(), zero.after_ticks(), zero.elapsed_ms()),
        (1, 1, 0)
    );

    source.elapsed_ns(250_000);
    let start = clock.begin_exchange().unwrap();
    source.elapsed_ns(250_001);
    let tiny = clock.finish_exchange(start).unwrap();
    assert_eq!(
        (tiny.before_ticks(), tiny.after_ticks(), tiny.elapsed_ms()),
        (1, 1, 1)
    );

    source.elapsed_ns(750_000);
    let start = clock.begin_exchange().unwrap();
    source.elapsed_ns(1_750_001);
    let rounded = clock.finish_exchange(start).unwrap();
    assert_eq!(
        (
            rounded.before_ticks(),
            rounded.after_ticks(),
            rounded.elapsed_ms()
        ),
        (1, 2, 2)
    );
}

#[test]
fn remaining_preserves_fractional_milliseconds_and_expires_at_exact_boundary() {
    let (source, clock) = Controlled::new([2; 16]);
    let (deadline, retention) = bounds(&clock, 4, 6);
    source.elapsed_ns(1_250_000);
    assert_eq!(
        deadline.remaining(&clock),
        Ok(Duration::from_nanos(1_750_000))
    );
    source.elapsed_ns(2_999_999);
    assert_eq!(deadline.remaining(&clock), Ok(Duration::from_nanos(1)));
    source.elapsed_ns(3_000_000);
    assert_eq!(deadline.check(&clock), Err(TimeError::Expired));
    assert_eq!(retention.elapsed(&clock), Ok(false));
    source.elapsed_ns(4_999_999);
    assert_eq!(retention.elapsed(&clock), Ok(false));
    source.elapsed_ns(5_000_000);
    assert_eq!(retention.elapsed(&clock), Ok(true));
}

#[test]
fn identical_generation_and_numeric_time_do_not_allow_cross_instance_exchange() {
    let (_, first) = Controlled::new([3; 16]);
    let (_, second) = Controlled::new([3; 16]);
    assert_eq!(first.generation(), second.generation());
    let start = first.begin_exchange().unwrap();
    assert_eq!(
        second.finish_exchange(start).err(),
        Some(TimeError::WrongClock)
    );
    let (deadline, retention) = bounds(&first, 10, 20);
    assert_eq!(deadline.remaining(&second), Err(TimeError::WrongClock));
    assert_eq!(retention.elapsed(&second), Err(TimeError::WrongClock));
    assert_eq!(deadline.check(&first), Ok(()));
    assert_eq!(retention.elapsed(&first), Ok(false));
}

#[test]
fn restriction_and_extension_reject_same_generation_from_a_different_instance() {
    let (_, first) = Controlled::new([4; 16]);
    let (_, second) = Controlled::new([4; 16]);
    let (a, ar) = bounds(&first, 10, 20);
    let (b, br) = bounds(&second, 10, 20);
    assert_eq!(a.restrict(b).err(), Some(TimeError::WrongClock));
    assert_eq!(ar.extend(br).err(), Some(TimeError::WrongClock));
}

#[test]
fn reobservation_keeps_earliest_admission_and_latest_retention_in_both_orders() {
    for reverse in [false, true] {
        let (source, clock) = Controlled::new([5; 16]);
        let (early, short) = bounds(&clock, 10, 20);
        let (late, long) = bounds(&clock, 30, 40);
        let (deadline, retention) = if reverse {
            (early.restrict(late).unwrap(), short.extend(long).unwrap())
        } else {
            (late.restrict(early).unwrap(), long.extend(short).unwrap())
        };
        assert_eq!(retention.ticks(), 40);
        source.elapsed_ns(8_999_999);
        assert_eq!(deadline.remaining(&clock), Ok(Duration::from_nanos(1)));
        source.elapsed_ns(9_000_000);
        assert_eq!(deadline.check(&clock), Err(TimeError::Expired));
        source.elapsed_ns(20_000_000);
        assert_eq!(retention.elapsed(&clock), Ok(false));
        source.elapsed_ns(39_000_000);
        assert_eq!(retention.elapsed(&clock), Ok(true));
    }
}

#[test]
fn suspend_inclusive_elapsed_progress_expires_admission_without_early_retention() {
    let (source, clock) = Controlled::new([6; 16]);
    let (deadline, retention) = bounds(&clock, 301, 902);
    // The private backend models BOOTTIME advancing while application work is suspended.
    source.elapsed_ns(500_000_000);
    assert_eq!(deadline.check(&clock), Err(TimeError::Expired));
    assert_eq!(retention.elapsed(&clock), Ok(false));
    source.elapsed_ns(901_000_000);
    assert_eq!(retention.elapsed(&clock), Ok(true));
}

#[test]
fn suspension_during_exchange_counts_in_the_exchange_budget() {
    let (source, clock) = Controlled::new([7; 16]);
    let start = clock.begin_exchange().unwrap();
    source.elapsed_ns(2_000_000_000);
    let exchange = clock.finish_exchange(start).unwrap();
    assert_eq!(
        (exchange.after_ticks(), exchange.elapsed_ms()),
        (2001, 2000)
    );
    // SDK rejects this >1s sample; even a stale earlier bound cannot bind here.
    assert_eq!(
        exchange.bind_bounds(1000, 1001).err(),
        Some(TimeError::InvalidBounds)
    );
}

#[test]
fn invalid_bounds_cannot_be_bound_even_when_exchange_is_current() {
    let (_, clock) = Controlled::new([8; 16]);
    for (admission, retention) in [
        (0, 10),
        (1, 10),
        (10, 9),
        (10, MAXIMUM + 1),
        (u64::MAX, u64::MAX),
    ] {
        assert_eq!(
            sample(&clock).bind_bounds(admission, retention).err(),
            Some(TimeError::InvalidBounds)
        );
    }
    // Equal bounds are a permitted generic infrastructure shape; receipt SDK owns
    // its stricter authenticated-report arithmetic and outward rounding.
    assert!(sample(&clock).bind_bounds(2, 2).is_ok());
}

#[test]
fn processing_delay_between_rpc_finish_and_binding_cannot_revive_a_deadline() {
    let (source, clock) = Controlled::new([9; 16]);
    let exchange = sample(&clock);
    source.elapsed_ns(4_000_000);
    assert_eq!(
        exchange.bind_bounds(5, 10).err(),
        Some(TimeError::InvalidBounds)
    );
}

#[test]
fn clock_read_failures_refuse_all_live_checks_and_never_signal_cleanup_ready() {
    let (source, clock) = Controlled::new([10; 16]);
    let (deadline, retention) = bounds(&clock, 10, 20);
    let start = clock.begin_exchange().unwrap();
    let exchange = sample(&clock);
    source.failing(true);
    assert_eq!(clock.begin_exchange().err(), Some(TimeError::ClockRead));
    assert_eq!(
        clock.finish_exchange(start).err(),
        Some(TimeError::ClockRead)
    );
    assert_eq!(
        exchange.bind_bounds(10, 20).err(),
        Some(TimeError::ClockRead)
    );
    assert_eq!(deadline.remaining(&clock), Err(TimeError::ClockRead));
    assert_eq!(retention.elapsed(&clock), Err(TimeError::ClockRead));
}

#[test]
fn source_before_origin_and_exchange_time_reversal_refuse() {
    let (source, clock) = Controlled::new([11; 16]);
    source.now.store(ORIGIN_NS - 1, Ordering::Release);
    assert_eq!(clock.begin_exchange().err(), Some(TimeError::ClockRead));
    source.elapsed_ns(10_000_000);
    let start = clock.begin_exchange().unwrap();
    source.elapsed_ns(9_999_999);
    assert_eq!(
        clock.finish_exchange(start).err(),
        Some(TimeError::ClockRead)
    );
}

#[test]
fn numeric_clock_overflow_refuses_instead_of_saturating() {
    let huge = Arc::new(AtomicBool::new(false));
    let control = huge.clone();
    let clock = ReceiverClock::from_source(
        [12; 16],
        Source::Controlled(Arc::new(move || {
            Ok(if control.load(Ordering::Acquire) {
                u128::from(MAXIMUM) * NANOS_PER_MS
            } else {
                0
            })
        })),
    )
    .unwrap();
    let (deadline, retention) = bounds(&clock, 10, 20);
    huge.store(true, Ordering::Release);
    assert_eq!(clock.begin_exchange().err(), Some(TimeError::Overflow));
    assert_eq!(deadline.remaining(&clock), Err(TimeError::Overflow));
    assert_eq!(retention.elapsed(&clock), Err(TimeError::Overflow));
}

#[test]
fn large_generic_duration_preserves_seconds_without_nanosecond_truncation() {
    let (_, clock) = Controlled::new([13; 16]);
    let (deadline, _) = bounds(&clock, MAXIMUM, MAXIMUM);
    assert_eq!(
        deadline.remaining(&clock),
        Ok(Duration::from_millis(MAXIMUM - 1))
    );
}

#[test]
fn retirement_invalidates_inflight_and_bound_admission_but_preserves_retention_clock() {
    let (source, clock) = Controlled::new([14; 16]);
    let (deadline, retention) = bounds(&clock, 10, 20);
    let start = clock.begin_exchange().unwrap();
    let exchange = sample(&clock);
    clock.retire();
    clock.retire();
    assert_eq!(clock.begin_exchange().err(), Some(TimeError::Retired));
    assert_eq!(clock.finish_exchange(start).err(), Some(TimeError::Retired));
    assert_eq!(exchange.bind_bounds(10, 20).err(), Some(TimeError::Retired));
    assert_eq!(deadline.remaining(&clock), Err(TimeError::Retired));
    assert_eq!(retention.elapsed(&clock), Ok(false));
    source.elapsed_ns(19_000_000);
    assert_eq!(retention.elapsed(&clock), Ok(true));
}

#[test]
fn restricting_retired_tokens_never_reactivates_admission() {
    let (_, clock) = Controlled::new([15; 16]);
    let (a, ar) = bounds(&clock, 10, 20);
    let (b, br) = bounds(&clock, 30, 40);
    clock.retire();
    let restricted = a.restrict(b).unwrap();
    let extended = ar.extend(br).unwrap();
    assert_eq!(restricted.check(&clock), Err(TimeError::Retired));
    assert_eq!(extended.ticks(), 40);
    assert_eq!(extended.elapsed(&clock), Ok(false));
}

#[test]
fn direct_tick_sample_preserves_floor_suspend_and_refuses_invalid_clock() {
    let (source, clock) = Controlled::new([31; 16]);
    assert_eq!(clock.sample_ticks(), Ok(1));
    source.elapsed_ns(999_999);
    assert_eq!(clock.sample_ticks(), Ok(1));
    source.elapsed_ns(1_000_000);
    assert_eq!(clock.sample_ticks(), Ok(2));
    source.elapsed_ns(2_000_000_000);
    assert_eq!(clock.sample_ticks(), Ok(2001));
    source.failing(true);
    assert_eq!(clock.sample_ticks(), Err(TimeError::ClockRead));
    source.failing(false);
    source.now.store(ORIGIN_NS - 1, Ordering::Release);
    assert_eq!(clock.sample_ticks(), Err(TimeError::ClockRead));
    clock.retire();
    assert_eq!(clock.sample_ticks(), Err(TimeError::Retired));
}

#[test]
fn direct_tick_sample_uses_one_read_and_rechecks_retirement_after_it() {
    let reads = Arc::new(AtomicUsize::new(0));
    let domain = Arc::new(std::sync::Mutex::new(None::<std::sync::Weak<Domain>>));
    let read_count = reads.clone();
    let captured = domain.clone();
    let clock = ReceiverClock::from_source(
        [32; 16],
        Source::Controlled(Arc::new(move || {
            read_count.fetch_add(1, Ordering::Relaxed);
            if let Some(d) = captured
                .lock()
                .unwrap()
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
            {
                d.active.store(false, Ordering::Release);
            }
            Ok(0)
        })),
    )
    .unwrap();
    assert_eq!(reads.load(Ordering::Relaxed), 1);
    assert_eq!(clock.sample_ticks(), Ok(1));
    assert_eq!(reads.load(Ordering::Relaxed), 2);
    *domain.lock().unwrap() = Some(Arc::downgrade(&clock.domain));
    assert_eq!(clock.sample_ticks(), Err(TimeError::Retired));
    assert_eq!(reads.load(Ordering::Relaxed), 3);
    assert_eq!(clock.sample_ticks(), Err(TimeError::Retired));
    assert_eq!(reads.load(Ordering::Relaxed), 3);
}

#[test]
fn direct_tick_sample_refuses_numeric_overflow() {
    let reads = AtomicUsize::new(0);
    let clock = ReceiverClock::from_source(
        [33; 16],
        Source::Controlled(Arc::new(move || {
            Ok(if reads.fetch_add(1, Ordering::Relaxed) == 0 {
                0
            } else {
                u128::from(MAXIMUM) * NANOS_PER_MS
            })
        })),
    )
    .unwrap();
    assert_eq!(clock.sample_ticks(), Err(TimeError::Overflow));
}
