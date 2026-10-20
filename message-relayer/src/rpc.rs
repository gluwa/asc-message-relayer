//! A lazily-connected, self-rebuilding RPC provider for the long-lived polling workers.
//!
//! The Outbox watcher, the ack submitter and the claim submitter each hold one provider for the
//! life of the process and poll it forever. Until now the only thing that ever replaced such a
//! provider was a process restart pulled by the `/health` liveness watchdog — a hammer that also
//! restarts every healthy route and forgets the in-memory delivery verdicts (`crate::outcome`).
//! Now that an erroring-but-alive worker is *degraded* rather than *stale* (see `crate::health`),
//! the watchdog no longer restarts it, so the worker has to be able to recover on its own from
//! the one failure a restart genuinely used to fix: a transport that is dead but still answers
//! every call with an error (an alloy WS provider whose pubsub service exited, a keep-alive HTTP
//! pool pinned to a load balancer that went away).
//!
//! The rule is deliberately dumb: after [`REBUILD_AFTER_FAILURES`] consecutive failed iterations
//! the provider is dropped and the next iteration dials a fresh one. A genuine upstream outage
//! (the 2026-09-17 Base `503`s) just means a re-dial every few ticks, which is cheap; a dead
//! transport is fixed on the first re-dial. Mirrors the per-tick reconnect `crate::balance` and
//! `crate::attestor_set` already do, without paying a dial on every successful poll.

use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use anyhow::{Context, Result};
use tracing::{info, warn};

/// Consecutive failed iterations before the provider is dropped and re-dialed. Three, not one:
/// a single failed `eth_getLogs` on a healthy transport (a transient `502` from a load balancer)
/// should not cost a reconnect, and the pollers run at 6–30 s cadences, so three failures still
/// means a rebuild well inside the health deadline.
pub const REBUILD_AFTER_FAILURES: u32 = 3;

/// One worker's long-lived provider slot.
#[derive(Debug)]
pub struct Reconnecting {
    label: String,
    url: String,
    provider: Option<DynProvider>,
    consecutive_failures: u32,
    rebuilds: u64,
}

impl Reconnecting {
    /// `label` names the worker in the rebuild log lines (`"ack:9 destination"`); nothing is
    /// dialed until [`Reconnecting::connect`].
    #[must_use]
    pub fn new(label: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            url: url.into(),
            provider: None,
            consecutive_failures: 0,
            rebuilds: 0,
        }
    }

    /// The live provider, dialing one if the slot is empty (first use, or after a rebuild). The
    /// returned handle is cheap to clone (Arc-backed transport), and callers clone it out so they
    /// can report the iteration's outcome on `self` afterwards.
    pub async fn connect(&mut self) -> Result<&DynProvider> {
        if self.provider.is_none() {
            let provider = ProviderBuilder::new()
                .connect(&self.url)
                .await
                .with_context(|| {
                    format!("{}: failed to connect to RPC at {}", self.label, self.url)
                })?
                .erased();
            if self.rebuilds > 0 {
                info!(worker = %self.label, rebuilds = self.rebuilds, "🔌 RPC provider rebuilt");
            }
            self.provider = Some(provider);
        }
        Ok(self.provider.as_ref().expect("filled above"))
    }

    /// The iteration succeeded: the transport is fine, forget any failure streak.
    pub fn note_ok(&mut self) {
        self.consecutive_failures = 0;
    }

    /// The iteration failed. Returns `true` when this failure completed a streak of
    /// [`REBUILD_AFTER_FAILURES`] and the provider was dropped, so the next [`Reconnecting::connect`]
    /// dials afresh.
    pub fn note_err(&mut self) -> bool {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures < REBUILD_AFTER_FAILURES {
            return false;
        }
        self.consecutive_failures = 0;
        self.rebuilds = self.rebuilds.saturating_add(1);
        if self.provider.take().is_some() {
            warn!(
                worker = %self.label,
                failures = REBUILD_AFTER_FAILURES,
                "🔌 RPC provider dropped after consecutive failures; rebuilding on the next tick"
            );
        }
        true
    }

    /// How many times the provider has been dropped for rebuild. Test and log surface.
    #[must_use]
    pub fn rebuilds(&self) -> u64 {
        self.rebuilds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebuilds_only_after_a_full_streak() {
        let mut rc = Reconnecting::new("test", "http://127.0.0.1:1");
        for _ in 1..REBUILD_AFTER_FAILURES {
            assert!(!rc.note_err(), "a partial streak must not rebuild");
        }
        assert!(rc.note_err(), "the Nth consecutive failure rebuilds");
        assert_eq!(rc.rebuilds(), 1);
    }

    #[test]
    fn a_success_resets_the_streak() {
        let mut rc = Reconnecting::new("test", "http://127.0.0.1:1");
        for _ in 1..REBUILD_AFTER_FAILURES {
            rc.note_err();
        }
        rc.note_ok();
        for _ in 1..REBUILD_AFTER_FAILURES {
            assert!(!rc.note_err());
        }
        assert_eq!(rc.rebuilds(), 0);
    }

    /// An HTTP provider is built without a network round-trip, so `connect` must succeed offline
    /// and a rebuild must hand out a fresh handle on the next call.
    #[tokio::test]
    async fn connect_is_lazy_and_redials_after_rebuild() {
        let mut rc = Reconnecting::new("test", "http://127.0.0.1:1");
        rc.connect().await.expect("http provider builds offline");
        for _ in 0..REBUILD_AFTER_FAILURES {
            rc.note_err();
        }
        assert!(rc.provider.is_none(), "rebuild must drop the slot");
        rc.connect().await.expect("re-dial builds offline too");
        assert!(rc.provider.is_some());
        assert_eq!(rc.rebuilds(), 1);
    }
}
