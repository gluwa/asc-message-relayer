//! Progress-aware liveness backing the `/health` endpoint.
//!
//! Previously `/health` was an unconditional `200`, so every mid-run wedge — a silently dead WS
//! provider that stops a watcher indexing, a pool that stops turning — survived indefinitely behind
//! a green check, and k8s only ever restarted the relayer on a full-process exit (which the
//! steady-state loops never produce, since they catch their own errors and retry forever). This
//! module lets each polling worker report *forward progress*; `/health` returns `503` when any
//! registered worker has gone **silent** past [`PROGRESS_DEADLINE`], so the k8s liveness probe pulls
//! the restart lever that rebuilds providers and resumes from the checkpoint.
//!
//! A worker heartbeats only on a **successful** poll iteration (an `eth_getLogs` scan that returned,
//! a pool prune tick that ran), not merely on the timer firing. A failed iteration is reported
//! separately through [`Health::error`], and that distinction is the whole point of the two-tier
//! verdict:
//!
//! * **stale** — no success *and* no error within the deadline. The loop is not turning (a hung
//!   `await` on a black-holed endpoint, a pubsub service that exited without telling anyone). Only a
//!   restart can fix this, so `/health` answers `503` and names the worker.
//! * **degraded** — no success within the deadline, but the worker is still attempting and failing
//!   (upstream `503`s, a rate limit, a chain that stopped producing blocks). The worker is alive and
//!   already retrying; each long-lived poller also rebuilds its provider after a run of failures
//!   (see `crate::rpc::Reconnecting`), so there is nothing a process restart would add — and on
//!   2026-09-17 the restart it used to trigger took the healthy Sepolia route down with the Base
//!   route whose RPC was 503ing, and forgot every in-memory delivery verdict. Degraded routes are
//!   named in the `/health` body and on `relayer_worker_degraded`, but the probe stays `200`.
//!
//! The deadline is deliberately generous relative to every worker's cadence so a healthy-but-idle
//! relayer is never restarted. Transitions between the three states are logged by [`Health::report`]
//! so a liveness kill is attributable from the pod log alone: the probe body that named the worker
//! is not something k8s keeps.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{info, warn};

/// How long a registered worker may go without reporting progress before `/health` reports the
/// process unhealthy. Generous versus every worker's poll cadence (outbox/ack/claim scan ~6s, pool
/// prune 30s) so a quiet relayer is never killed; short enough that a genuinely wedged worker (dead
/// provider → no successful poll ever again) trips a restart within a few minutes.
///
/// Must also clear the delivery worker's own worst-case *legitimate* gap between retry attempts on
/// a persistently failing message: `pool::DELIVERY_RETRY_MAX` (5 min) plus `pool::PRUNE_TICK_INTERVAL`
/// (30s, since a retry only actually goes out on the pool's own prune tick, not the instant its
/// backoff elapses) — 5.5 min, with a further 30s of margin here. Undershooting this makes a
/// still-retrying route misread as `stale` instead of `degraded` right at the tail of a max backoff
/// (see `delivery::idle_ticker_should_heartbeat`'s `error_grace_period`, which is `debug_assert`ed
/// against this constant).
pub const PROGRESS_DEADLINE: Duration = Duration::from_secs(6 * 60);

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// One registered worker's reporting history, in unix millis.
#[derive(Debug, Clone, Copy, Default)]
struct Component {
    /// Last successful poll iteration (or the registration call).
    last_ok: u64,
    /// Last iteration that ran and failed; `0` until the first failure.
    last_err: u64,
}

/// The `/health` verdict, sorted by worker name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    /// Silent past the deadline: no success and no error. The liveness failure.
    pub stale: Vec<String>,
    /// No success past the deadline but still erroring — alive, retrying, and rebuilding its
    /// provider; visible but not restart-worthy.
    pub degraded: Vec<String>,
}

impl Report {
    /// Whether the liveness probe should pass.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.stale.is_empty()
    }
}

/// Shared liveness registry. Workers heartbeat by name; `/health` checks every registered name
/// against [`PROGRESS_DEADLINE`].
#[derive(Debug)]
pub struct Health {
    components: Mutex<HashMap<String, Component>>,
    deadline_ms: u64,
    /// The last verdict handed out by [`Health::report`], so transitions can be logged exactly
    /// once instead of on every probe.
    last_reported: Mutex<Report>,
}

impl Health {
    #[must_use]
    pub fn new(deadline: Duration) -> Arc<Self> {
        Arc::new(Self {
            components: Mutex::new(HashMap::new()),
            deadline_ms: u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
            last_reported: Mutex::new(Report::default()),
        })
    }

    /// Report forward progress for `name`, registering it on first call. Workers call this once at
    /// startup (so a worker that wedges before its first successful poll still goes stale and trips
    /// a restart) and again after every successful poll iteration.
    pub fn heartbeat(&self, name: &str) {
        let now = now_unix_ms();
        let mut guard = self.components.lock().expect("health mutex poisoned");
        guard.entry(name.to_owned()).or_default().last_ok = now;
    }

    /// Report that `name`'s poll iteration ran and **failed**. Proves the loop is turning without
    /// counting as progress: a worker that only ever reports errors becomes *degraded*, never
    /// *stale*, so an upstream outage it is already retrying through does not trip a liveness
    /// restart. Registers the component if the failure is its first report.
    pub fn error(&self, name: &str) {
        let now = now_unix_ms();
        let mut guard = self.components.lock().expect("health mutex poisoned");
        let entry = guard.entry(name.to_owned()).or_default();
        if entry.last_ok == 0 {
            // First report ever was a failure: date the registration so the deadline is measured
            // from here rather than from the epoch.
            entry.last_ok = now;
        }
        entry.last_err = now;
    }

    /// Every registered worker with the unix-millis of its last reported progress, sorted by
    /// name. Read at `/metrics` scrape time to publish per-worker progress as a gauge — same
    /// source of truth as `/health`, so the metric and the probe can never disagree about who
    /// is wedged.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(String, u64)> {
        let guard = self.components.lock().expect("health mutex poisoned");
        let mut out: Vec<(String, u64)> =
            guard.iter().map(|(n, c)| (n.clone(), c.last_ok)).collect();
        out.sort();
        out
    }

    /// Classify every registered worker against the deadline. Pure read; see [`Health::report`]
    /// for the variant that also logs transitions.
    #[must_use]
    pub fn status(&self) -> Report {
        let now = now_unix_ms();
        let guard = self.components.lock().expect("health mutex poisoned");
        let mut report = Report::default();
        for (name, c) in guard.iter() {
            let ok_overdue = now.saturating_sub(c.last_ok) > self.deadline_ms;
            if !ok_overdue {
                continue;
            }
            let err_recent = c.last_err != 0 && now.saturating_sub(c.last_err) <= self.deadline_ms;
            if err_recent {
                report.degraded.push(name.clone());
            } else {
                report.stale.push(name.clone());
            }
        }
        report.stale.sort();
        report.degraded.sort();
        report
    }

    /// [`Health::status`], plus a log line whenever the verdict changes: `WARN` naming the workers
    /// that went stale (the probe is about to fail) or degraded, `INFO` when a set clears. Called by
    /// the `/health` handler, i.e. once per probe, so the transition is recorded at the moment the
    /// probe saw it.
    #[must_use]
    pub fn report(&self) -> Report {
        let current = self.status();
        let mut last = self.last_reported.lock().expect("health mutex poisoned");
        if *last == current {
            return current;
        }
        if current.stale != last.stale {
            if current.stale.is_empty() {
                info!(recovered = ?last.stale, "✅ /health: no stale workers — probe passing again");
            } else {
                warn!(
                    stale = ?current.stale,
                    deadline_secs = self.deadline_ms / 1000,
                    "💀 /health: worker(s) silent past the deadline — liveness probe will fail and \
                     k8s will restart this relayer"
                );
            }
        }
        if current.degraded != last.degraded {
            if current.degraded.is_empty() {
                info!(recovered = ?last.degraded, "✅ /health: no degraded workers");
            } else {
                warn!(
                    degraded = ?current.degraded,
                    deadline_secs = self.deadline_ms / 1000,
                    "🩹 /health: worker(s) erroring without progress past the deadline — degraded, \
                     probe still passing (no restart; the worker is retrying and rebuilding its \
                     provider)"
                );
            }
        }
        *last = current.clone();
        current
    }

    /// Test seam: register `name` as if its last success was `ok_ago` ago and (optionally) its
    /// last error `err_ago` ago, so the deadline logic can be exercised without sleeping.
    #[cfg(test)]
    pub(crate) fn set_for_test(&self, name: &str, ok_ago: Duration, err_ago: Option<Duration>) {
        let now = now_unix_ms();
        let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        let mut g = self.components.lock().expect("health mutex poisoned");
        g.insert(
            name.to_owned(),
            Component {
                last_ok: now.saturating_sub(ms(ok_ago)),
                last_err: err_ago.map_or(0, |ago| now.saturating_sub(ms(ago))),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backdate(h: &Health, name: &str, ok_ago_ms: u64, err_ago_ms: Option<u64>) {
        h.set_for_test(
            name,
            Duration::from_millis(ok_ago_ms),
            err_ago_ms.map(Duration::from_millis),
        );
    }

    #[test]
    fn empty_registry_is_alive() {
        let h = Health::new(PROGRESS_DEADLINE);
        let r = h.status();
        assert!(r.is_alive());
        assert_eq!(r, Report::default());
    }

    #[test]
    fn fresh_heartbeat_is_alive() {
        let h = Health::new(PROGRESS_DEADLINE);
        h.heartbeat("outbox:2");
        let r = h.status();
        assert!(r.is_alive());
        assert!(r.stale.is_empty() && r.degraded.is_empty());
    }

    #[test]
    fn stale_component_reports_unhealthy() {
        let h = Health::new(Duration::from_secs(5 * 60));
        // One worker went silent 10 minutes ago (past the 5-minute deadline), one is current.
        backdate(&h, "outbox:2", 10 * 60 * 1000, None);
        h.heartbeat("pool");
        let r = h.status();
        assert!(!r.is_alive());
        assert_eq!(r.stale, vec!["outbox:2".to_owned()]);
        assert!(r.degraded.is_empty());
    }

    /// The 2026-09-17 shape: Base RPC 503 for 5+ minutes. The ack worker kept ticking and failing.
    /// That is degraded, not stale — the probe must keep passing.
    #[test]
    fn erroring_component_is_degraded_not_stale() {
        let h = Health::new(Duration::from_secs(5 * 60));
        backdate(&h, "ack:9", 6 * 60 * 1000, Some(20 * 1000));
        let r = h.status();
        assert!(
            r.is_alive(),
            "an erroring-but-alive worker must not fail liveness"
        );
        assert_eq!(r.degraded, vec!["ack:9".to_owned()]);
        assert!(r.stale.is_empty());
    }

    /// Errors only count while they are recent: a worker whose last error is itself past the
    /// deadline has stopped ticking altogether and is stale.
    #[test]
    fn old_errors_do_not_keep_a_silent_worker_alive() {
        let h = Health::new(Duration::from_secs(5 * 60));
        backdate(&h, "ack:9", 20 * 60 * 1000, Some(10 * 60 * 1000));
        let r = h.status();
        assert!(!r.is_alive());
        assert_eq!(r.stale, vec!["ack:9".to_owned()]);
    }

    /// A success clears degraded immediately, even though the error timestamp stays behind.
    #[test]
    fn success_after_errors_recovers() {
        let h = Health::new(Duration::from_secs(5 * 60));
        backdate(&h, "ack:9", 6 * 60 * 1000, Some(20 * 1000));
        assert_eq!(h.status().degraded, vec!["ack:9".to_owned()]);
        h.heartbeat("ack:9");
        assert_eq!(h.status(), Report::default());
    }

    /// `error` on an unregistered name registers it (dated now), so a worker whose very first
    /// iteration fails is neither invisible nor instantly stale.
    #[test]
    fn first_report_being_an_error_registers_fresh() {
        let h = Health::new(PROGRESS_DEADLINE);
        h.error("claim:8");
        assert_eq!(h.status(), Report::default());
        assert_eq!(h.snapshot().len(), 1);
    }

    /// `report` is `status` plus transition logging; the verdict itself must be identical and the
    /// stored last report must track it.
    #[test]
    fn report_matches_status_and_tracks_transitions() {
        let h = Health::new(Duration::from_secs(5 * 60));
        backdate(&h, "outbox:2", 10 * 60 * 1000, None);
        let r = h.report();
        assert_eq!(r, h.status());
        assert_eq!(*h.last_reported.lock().unwrap(), r);
        h.heartbeat("outbox:2");
        let r2 = h.report();
        assert_eq!(r2, Report::default());
        assert_eq!(*h.last_reported.lock().unwrap(), Report::default());
    }
}
