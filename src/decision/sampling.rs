//! Head sampling and the per-(route, prefix) deny token buckets.
//!
//! Both run on the request thread and therefore allocate nothing: the bucket
//! table is a fixed array created at start-up, and a colliding key takes over
//! its slot after summarizing what the previous key suppressed.

use std::hash::{BuildHasher, Hash, Hasher};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

pub const PPM: u32 = 1_000_000;

/// SplitMix64 finalizer: a bijection, so distinct counters never collide.
pub fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Deterministic on the request ID so every stage and replica agree.
pub fn keep(request_id: u64, rate_ppm: u32) -> bool {
    rate_ppm >= PPM
        || (mix(request_id ^ 0x5a5a_5a5a_a5a5_a5a5) % u64::from(PPM)) < u64::from(rate_ppm)
}

#[derive(Clone, Debug, PartialEq)]
pub struct BucketConfig {
    pub burst: u32,
    pub refill_per_second: f64,
    pub window_ms: u64,
}

/// Summary of denies suppressed for one key during one window.
#[derive(Clone)]
pub struct Summary {
    pub route: Option<Arc<crate::config::HttpRuntime>>,
    pub prefix: Option<IpAddr>,
    pub count: u64,
    pub first_ms: u64,
    pub last_ms: u64,
    pub window_ms: u64,
}

#[derive(Default)]
struct Slot {
    key: u64,
    used: bool,
    tokens: f64,
    refilled_ms: u64,
    window_start_ms: u64,
    suppressed: u64,
    first_ms: u64,
    last_ms: u64,
    route: Option<Arc<crate::config::HttpRuntime>>,
    prefix: Option<IpAddr>,
}

impl Slot {
    fn take_summary(&mut self, window_ms: u64) -> Option<Summary> {
        (self.suppressed > 0).then(|| {
            let summary = Summary {
                route: self.route.clone(),
                prefix: self.prefix,
                count: self.suppressed,
                first_ms: self.first_ms,
                last_ms: self.last_ms,
                window_ms,
            };
            self.suppressed = 0;
            summary
        })
    }
}

pub enum Admission {
    Keep(Option<Summary>),
    Suppress(Option<Summary>),
}

pub struct Buckets {
    config: BucketConfig,
    hasher: std::collections::hash_map::RandomState,
    slots: Box<[Mutex<Slot>]>,
}

fn masked(ip: IpAddr) -> IpAddr {
    let (bytes, len) = super::keys::prefix_bytes(ip);
    if len == 4 {
        IpAddr::from([bytes[0], bytes[1], bytes[2], 0])
    } else {
        let mut octets = [0u8; 16];
        octets[..6].copy_from_slice(&bytes[..6]);
        IpAddr::from(octets)
    }
}

impl Buckets {
    pub fn new(config: BucketConfig, slots: usize) -> Self {
        Self {
            config,
            hasher: Default::default(),
            slots: (0..slots.max(1)).map(|_| Mutex::default()).collect(),
        }
    }

    pub fn slots(&self) -> usize {
        self.slots.len()
    }

    fn key(&self, route: Option<&str>, prefix: Option<IpAddr>) -> u64 {
        let mut hasher = self.hasher.build_hasher();
        route.hash(&mut hasher);
        prefix.hash(&mut hasher);
        hasher.finish()
    }

    /// One deny-class event for (route, client prefix) at `now_ms`.
    pub fn admit(
        &self,
        route: Option<&Arc<crate::config::HttpRuntime>>,
        client: Option<IpAddr>,
        now_ms: u64,
    ) -> Admission {
        let prefix = client.map(masked);
        let key = self.key(route.map(|r| r.route.id.as_str()), prefix);
        let index = (key % self.slots.len() as u64) as usize;
        let mut slot = self.slots[index]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut summary = None;
        if !slot.used || slot.key != key {
            summary = slot.take_summary(self.config.window_ms);
            *slot = Slot {
                key,
                used: true,
                tokens: f64::from(self.config.burst),
                refilled_ms: now_ms,
                window_start_ms: now_ms,
                route: route.cloned(),
                prefix,
                ..Default::default()
            };
        } else {
            if now_ms >= slot.window_start_ms + self.config.window_ms {
                summary = slot.take_summary(self.config.window_ms);
                slot.window_start_ms = now_ms;
            }
            let elapsed = now_ms.saturating_sub(slot.refilled_ms) as f64 / 1000.0;
            slot.tokens = (slot.tokens + elapsed * self.config.refill_per_second)
                .min(f64::from(self.config.burst));
            slot.refilled_ms = now_ms;
        }
        if slot.tokens >= 1.0 {
            slot.tokens -= 1.0;
            Admission::Keep(summary)
        } else {
            if slot.suppressed == 0 {
                slot.first_ms = now_ms;
            }
            slot.suppressed += 1;
            slot.last_ms = now_ms;
            Admission::Suppress(summary)
        }
    }

    /// Background sweep: summaries for windows that ended without traffic.
    pub fn sweep(&self, now_ms: u64, out: &mut Vec<Summary>) {
        for slot in self.slots.iter() {
            let Ok(mut slot) = slot.try_lock() else {
                continue;
            };
            if slot.suppressed > 0 && now_ms >= slot.window_start_ms + self.config.window_ms {
                if let Some(summary) = slot.take_summary(self.config.window_ms) {
                    out.push(summary);
                }
                slot.window_start_ms = now_ms;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_sampling_is_deterministic_and_close_to_rate() {
        let kept = (0..100_000u64).filter(|id| keep(mix(*id), 10_000)).count();
        assert!((800..1200).contains(&kept), "{kept}");
        for id in 0..1000u64 {
            assert_eq!(keep(id, 10_000), keep(id, 10_000));
            assert!(keep(id, PPM));
            assert!(!keep(id, 0));
        }
    }

    fn config() -> BucketConfig {
        BucketConfig {
            burst: 3,
            refill_per_second: 1.0,
            window_ms: 60_000,
        }
    }

    #[test]
    fn bucket_bounds_a_flood_and_summarizes_once_per_window() {
        let buckets = Buckets::new(config(), 64);
        let ip: IpAddr = "198.51.100.9".parse().unwrap();
        let mut kept = 0;
        let mut suppressed = 0;
        for i in 0..1000u64 {
            // 1000 denies within one second from one /24.
            match buckets.admit(None, Some(ip), 1_000 + i / 1000) {
                Admission::Keep(summary) => {
                    assert!(summary.is_none());
                    kept += 1;
                }
                Admission::Suppress(summary) => {
                    assert!(summary.is_none());
                    suppressed += 1;
                }
            }
        }
        assert_eq!(kept, 3);
        assert_eq!(suppressed, 997);
        // Another address in the same /24 shares the bucket; another /24 does not.
        assert!(matches!(
            buckets.admit(None, Some("198.51.100.10".parse().unwrap()), 1_500),
            Admission::Suppress(_)
        ));
        assert!(matches!(
            buckets.admit(None, Some("198.51.101.10".parse().unwrap()), 1_500),
            Admission::Keep(_)
        ));
        // Refill: one token per second.
        assert!(matches!(
            buckets.admit(None, Some(ip), 2_600),
            Admission::Keep(None)
        ));
        // The next event after the window carries the summary.
        match buckets.admit(None, Some(ip), 70_000) {
            Admission::Keep(Some(summary)) => {
                assert_eq!(summary.count, 998);
                assert_eq!(summary.first_ms, 1_000);
                assert_eq!(summary.last_ms, 1_500);
            }
            _ => panic!("expected summary"),
        }
    }

    #[test]
    fn sweep_summarizes_idle_windows_and_collisions_never_lose_counts() {
        let buckets = Buckets::new(config(), 1);
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "2001:db8::1".parse().unwrap();
        for _ in 0..10 {
            buckets.admit(None, Some(a), 0);
        }
        // Collision in a one-slot table: the previous key is summarized.
        match buckets.admit(None, Some(b), 10) {
            Admission::Keep(Some(summary)) => assert_eq!(summary.count, 7),
            _ => panic!("expected takeover summary"),
        }
        for _ in 0..5 {
            buckets.admit(None, Some(b), 20);
        }
        let mut out = Vec::new();
        buckets.sweep(30, &mut out);
        assert!(out.is_empty());
        buckets.sweep(60_010, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].count, 3);
        assert_eq!(out[0].prefix, Some("2001:db8::".parse().unwrap()));
        buckets.sweep(200_000, &mut out);
        assert_eq!(out.len(), 1);
    }
}
