//! Private, bounded security logs; no request credentials or raw URL values.
use std::{
    net::IpAddr,
    sync::{
        Mutex, OnceLock,
        mpsc::{self, SyncSender},
    },
    time::{Duration, Instant},
};

struct Budget {
    start: Instant,
    emitted: u32,
    suppressed: u64,
}
static BUDGET: OnceLock<Mutex<Budget>> = OnceLock::new();
static CONTROL_BUDGET: OnceLock<Mutex<Budget>> = OnceLock::new();
struct Event {
    event: &'static str,
    ip: IpAddr,
    status: u16,
    path: String,
    suppressed: u64,
}
struct Queues {
    requests: SyncSender<Event>,
    controls: SyncSender<Event>,
}
static QUEUES: OnceLock<Option<Queues>> = OnceLock::new();

fn queues() -> Option<&'static Queues> {
    QUEUES.get_or_init(|| {
        let (requests, input) = mpsc::sync_channel::<Event>(224);
        let (controls, control_input) = mpsc::sync_channel::<Event>(32);
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        std::thread::Builder::new().name("security-events".into()).spawn(move || {
            tracing::dispatcher::with_default(&dispatch, || loop {
                let received = control_input.try_recv().ok().or_else(|| input.recv_timeout(Duration::from_millis(100)).ok());
                if let Some(item) = received {
                    tracing::warn!(security_event = item.event, client_ip = %item.ip, status = item.status,
                        rule_path = %item.path, suppressed_events = item.suppressed, "security admission event");
                }
            });
        }).ok()?;
        Some(Queues { requests, controls })
    }).as_ref()
}

pub(crate) fn record(event: &'static str, ip: IpAddr, status: u16, rule_path: Option<&str>) {
    let now = Instant::now();
    let selected = if event == "ip_ban_released" || event == "security_release_unconfirmed" {
        &CONTROL_BUDGET
    } else {
        &BUDGET
    };
    let budget = selected.get_or_init(|| {
        Mutex::new(Budget {
            start: now,
            emitted: 0,
            suppressed: 0,
        })
    });
    let suppressed = {
        let mut state = budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if now.saturating_duration_since(state.start).as_secs() >= 1 {
            state.start = now;
            state.emitted = 0;
        }
        if state.emitted >= 10 {
            state.suppressed = state.suppressed.saturating_add(1);
            return;
        }
        state.emitted += 1;
        std::mem::take(&mut state.suppressed)
    };
    let configured_path: String = rule_path.unwrap_or("").chars().take(128).collect();
    // Never write to a potentially blocked log sink on a request worker.
    // Administrative events have reserved queue space as well as their budget.
    let sent = queues().is_some_and(|queues| {
        let sender = if std::ptr::eq(selected, &CONTROL_BUDGET) {
            &queues.controls
        } else {
            &queues.requests
        };
        sender
            .try_send(Event {
                event,
                ip,
                status,
                path: configured_path,
                suppressed,
            })
            .is_ok()
    });
    if !sent {
        let mut state = budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.suppressed = state
            .suppressed
            .saturating_add(suppressed)
            .saturating_add(1);
    }
}
