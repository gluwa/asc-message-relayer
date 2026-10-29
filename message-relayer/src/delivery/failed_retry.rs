//! Bounded `retryFailedMessage` budget for messages whose destination call failed.
//!
//! A `DestinationFailed` message stays `isRetryable` on the Inbox until someone's
//! `retryFailedMessage` succeeds, and every attempt pays for a full destination execution. A
//! destination that reverts deterministically (asc-devnet, Oct 2026: traffic-simulator probes
//! aimed at Multicall3) can never be fixed by resending the same call, so unbounded supervised
//! retries only drain the signer. [`FailedRetries`] spaces attempts out per
//! [`FailedRetryPolicy::backoff`] and caps them at [`FailedRetryPolicy::max_attempts`]; past that
//! the delivery worker drops the work and leaves the message to anyone on-chain.
//!
//! The delivery worker is the single gate because it is the only place gas is spent on
//! `retryFailedMessage`, and every path to that call goes through it: supervised retries,
//! `MessageAlreadyValidated` reconciliation, and restart or rescan probes. The pool's own attempt
//! counter is memory-only and resets whenever a slot rotates out of the working set, so it cannot
//! carry the budget. State is kept in memory and, when persistence is enabled, written through to
//! the [`WorkStore`] sidecar. Reads take the stricter of the two, so a failed disk write never
//! hands a message a fresh budget within a process lifetime.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use alloy::primitives::B256;
use tracing::error;

use crate::config::FailedRetryPolicy;
use crate::work::{FailedRetryState, WorkStore};

/// What the worker may do with a `retryFailedMessage` candidate right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gate {
    /// Send the next attempt.
    Proceed,
    /// Too early; the next attempt is due at this Unix second.
    Wait(u64),
    /// The budget is spent (or was already abandoned before a restart).
    GiveUp(FailedRetryState),
}

/// Per-route `retryFailedMessage` bookkeeping. See the module docs.
pub struct FailedRetries {
    chain_key: u64,
    work: Option<Arc<WorkStore>>,
    memory: Mutex<HashMap<B256, FailedRetryState>>,
}

impl FailedRetries {
    pub fn new(chain_key: u64, work: Option<Arc<WorkStore>>) -> Self {
        Self {
            chain_key,
            work,
            memory: Mutex::default(),
        }
    }

    /// Memory-only ledger (persistence disabled, and tests).
    #[cfg(test)]
    pub fn in_memory(chain_key: u64) -> Self {
        Self::new(chain_key, None)
    }

    pub(crate) async fn get(&self, message_id: B256) -> Option<FailedRetryState> {
        let memory = self.memory().get(&message_id).copied();
        let disk = match &self.work {
            Some(work) => match work.failed_retry(self.chain_key, message_id).await {
                Ok(state) => state,
                Err(err) => {
                    error!(chain_key = self.chain_key, %message_id, %err,
                        "could not read retryFailedMessage state; using the in-memory copy");
                    None
                }
            },
            None => None,
        };
        match (memory, disk) {
            (Some(a), Some(b)) => Some(stricter(a, b)),
            (a, b) => a.or(b),
        }
    }

    async fn put(&self, message_id: B256, state: FailedRetryState) {
        self.memory().insert(message_id, state);
        if let Some(work) = &self.work {
            if let Err(err) = work
                .put_failed_retry(self.chain_key, message_id, state)
                .await
            {
                // The in-memory copy still bounds this process; only a restart could reset it.
                error!(chain_key = self.chain_key, %message_id, %err, attempts = state.attempts,
                    "could not persist retryFailedMessage state");
            }
        }
    }

    /// Execution is confirmed; nothing left to bound.
    pub(crate) async fn forget(&self, message_id: B256) {
        self.memory().remove(&message_id);
        if let Some(work) = &self.work {
            if let Err(err) = work.forget_failed_retry(self.chain_key, message_id).await {
                error!(chain_key = self.chain_key, %message_id, %err,
                    "could not remove retryFailedMessage state");
            }
        }
    }

    /// The first `DestinationFailed` was just observed: schedule attempt one. An existing entry
    /// (e.g. replayed after a crash) is kept rather than reset.
    pub(crate) async fn start(
        &self,
        message_id: B256,
        policy: &FailedRetryPolicy,
        now: u64,
    ) -> FailedRetryState {
        if let Some(state) = self.get(message_id).await {
            return state;
        }
        let state = FailedRetryState {
            attempts: 0,
            next_attempt_at: now.saturating_add(policy.backoff(0).as_secs()),
            gave_up_at: None,
        };
        self.put(message_id, state).await;
        state
    }

    /// May a `retryFailedMessage` be sent now? A message with no entry (first seen before this
    /// relayer version, or a lost first receipt) starts with a full budget and no wait.
    pub(crate) async fn gate(
        &self,
        message_id: B256,
        policy: &FailedRetryPolicy,
        now: u64,
    ) -> Gate {
        let state = self.get(message_id).await.unwrap_or_default();
        if state.gave_up_at.is_some() || state.attempts >= policy.max_attempts {
            Gate::GiveUp(state)
        } else if now < state.next_attempt_at {
            Gate::Wait(state.next_attempt_at)
        } else {
            Gate::Proceed
        }
    }

    /// Count a broadcast `retryFailedMessage` and schedule the next one.
    pub(crate) async fn record_attempt(
        &self,
        message_id: B256,
        policy: &FailedRetryPolicy,
        now: u64,
    ) -> FailedRetryState {
        let previous = self.get(message_id).await.unwrap_or_default();
        let attempts = previous.attempts.saturating_add(1);
        let state = FailedRetryState {
            attempts,
            next_attempt_at: now.saturating_add(policy.backoff(attempts).as_secs()),
            gave_up_at: None,
        };
        self.put(message_id, state).await;
        state
    }

    /// Leave a tombstone so neither this process nor a restarted one retries the message again.
    pub(crate) async fn give_up(
        &self,
        message_id: B256,
        state: FailedRetryState,
        now: u64,
    ) -> FailedRetryState {
        let state = FailedRetryState {
            gave_up_at: Some(state.gave_up_at.unwrap_or(now)),
            ..state
        };
        self.put(message_id, state).await;
        state
    }

    fn memory(&self) -> std::sync::MutexGuard<'_, HashMap<B256, FailedRetryState>> {
        // A poisoned map still holds valid counters; losing them would reopen the budget.
        self.memory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Combine two views of the same message, keeping whichever spends less gas.
fn stricter(a: FailedRetryState, b: FailedRetryState) -> FailedRetryState {
    FailedRetryState {
        attempts: a.attempts.max(b.attempts),
        next_attempt_at: a.next_attempt_at.max(b.next_attempt_at),
        gave_up_at: a.gave_up_at.or(b.gave_up_at),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn policy(max_attempts: u32) -> FailedRetryPolicy {
        FailedRetryPolicy {
            max_attempts,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn schedule_backs_off_and_gives_up_after_the_budget() {
        let retries = FailedRetries::in_memory(2);
        let id = B256::repeat_byte(1);
        let policy = policy(3);
        // Unknown messages (first seen before this version) may retry at once.
        assert_eq!(retries.gate(id, &policy, NOW).await, Gate::Proceed);

        let started = retries.start(id, &policy, NOW).await;
        assert_eq!(started.next_attempt_at, NOW + 60);
        assert_eq!(
            retries.gate(id, &policy, NOW + 59).await,
            Gate::Wait(NOW + 60)
        );
        assert_eq!(retries.gate(id, &policy, NOW + 60).await, Gate::Proceed);
        // A replayed first receipt does not reset the schedule.
        assert_eq!(retries.start(id, &policy, NOW + 30).await, started);

        let mut now = NOW + 60;
        let mut waits = Vec::new();
        for _ in 0..3 {
            assert_eq!(retries.gate(id, &policy, now).await, Gate::Proceed);
            let state = retries.record_attempt(id, &policy, now).await;
            waits.push(state.next_attempt_at - now);
            now = state.next_attempt_at;
        }
        assert_eq!(waits, [120, 240, 480]);
        let Gate::GiveUp(state) = retries.gate(id, &policy, now).await else {
            panic!("budget of 3 must be exhausted");
        };
        assert_eq!(state.attempts, 3);

        // A raised cap would allow more, but a tombstone is final.
        retries.give_up(id, state, now).await;
        assert!(matches!(
            retries.gate(id, &FailedRetryPolicy::default(), now).await,
            Gate::GiveUp(FailedRetryState {
                gave_up_at: Some(_),
                ..
            })
        ));
        retries.forget(id).await;
        assert_eq!(retries.get(id).await, None);
    }

    #[tokio::test]
    async fn zero_budget_never_retries() {
        let retries = FailedRetries::in_memory(2);
        assert!(matches!(
            retries.gate(B256::repeat_byte(1), &policy(0), NOW).await,
            Gate::GiveUp(_)
        ));
    }

    #[tokio::test]
    async fn persisted_budget_survives_restart_and_tombstone_blocks_rescans() {
        let dir = tempfile::tempdir().unwrap();
        let checkpoint = dir.path().join("cp");
        let id = B256::repeat_byte(1);
        let policy = policy(2);
        let store = || Arc::new(WorkStore::for_checkpoint(&checkpoint));

        let retries = FailedRetries::new(2, Some(store()));
        retries.start(id, &policy, NOW).await;
        retries.record_attempt(id, &policy, NOW + 60).await;
        drop(retries);

        // A new process (empty memory) resumes the count and the wait.
        let retries = FailedRetries::new(2, Some(store()));
        assert_eq!(retries.get(id).await.unwrap().attempts, 1);
        assert_eq!(
            retries.gate(id, &policy, NOW + 61).await,
            Gate::Wait(NOW + 60 + 120)
        );
        retries.record_attempt(id, &policy, NOW + 180).await;
        let Gate::GiveUp(state) = retries.gate(id, &policy, NOW + 10_000).await else {
            panic!("exhausted");
        };
        retries.give_up(id, state, NOW + 180).await;
        drop(retries);

        // After a restart even a larger budget does not reopen an abandoned message.
        let retries = FailedRetries::new(2, Some(store()));
        assert!(matches!(
            retries
                .gate(id, &FailedRetryPolicy::default(), NOW + 99_999)
                .await,
            Gate::GiveUp(FailedRetryState {
                attempts: 2,
                gave_up_at: Some(_),
                ..
            })
        ));
    }

    #[tokio::test]
    async fn memory_and_disk_merge_to_the_stricter_view() {
        let dir = tempfile::tempdir().unwrap();
        let work = Arc::new(WorkStore::for_checkpoint(&dir.path().join("cp")));
        let id = B256::repeat_byte(1);
        let retries = FailedRetries::new(2, Some(work.clone()));
        retries.record_attempt(id, &policy(5), NOW).await;
        retries.record_attempt(id, &policy(5), NOW).await;
        // Simulate a lost write: disk lags memory. The higher count must win.
        work.put_failed_retry(
            2,
            id,
            FailedRetryState {
                attempts: 1,
                next_attempt_at: NOW + 1_000_000,
                gave_up_at: None,
            },
        )
        .await
        .unwrap();
        let merged = retries.get(id).await.unwrap();
        assert_eq!(merged.attempts, 2);
        assert_eq!(merged.next_attempt_at, NOW + 1_000_000);
    }
}
