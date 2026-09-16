//! Per-message delivery outcomes, kept in a bounded in-memory store and served over HTTP.
//!
//! The vote pool answers "how many attestors have signed" while a message is in flight and forgets
//! it once delivered; nothing answered "what happened to it" afterwards. Operators and the
//! dashboard had to read the relayer logs to learn that a message was delivered (and in which
//! destination tx), that the destination call reverted (`MessageExecutionFailed`), or that the
//! relayer refused it as undeliverable (a payload the Inbox cannot decode, an envelope over the
//! route's caps, an under-funded message past its top-up window). This module records that
//! verdict per `messageId` at the moment the delivery worker reaches it and exposes it as
//! `GET /outcomes/{message_id}` and `GET /outcomes?ids=a,b,c`.
//!
//! Only terminal verdicts are recorded; transient failures return the job to the pool and leave
//! no entry, so a missing entry means "not seen" or "still in flight" — the caller distinguishes
//! the two from the vote pool.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::B256;
use serde::Serialize;

/// Bound on remembered outcomes. At usc-devnet volumes this is months of traffic; a busier
/// deployment evicts oldest-first, and anything older is still provable from the chains.
pub const DEFAULT_CAP: usize = 10_000;

/// What the delivery worker concluded for a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    /// `deliverMessage` mined with `MessageDelivered` and the destination call succeeded (or another
    /// relayer's did — idempotent success).
    Delivered,
    /// Mined and consumed, but the destination call failed (`MessageExecutionFailed`, #36). No retry
    /// is possible; the relay fee is still claimable.
    DestinationFailed,
    /// Mined with `MessagePending`: the dispatcher deferred/queued it; bounded `retryPendingMessage`
    /// attempts follow.
    Pending,
    /// The relayer refused to send because the message can never be delivered as published: the
    /// Inbox reverts before dispatch (typically a payload that is not an
    /// `abi.encode(address,uint256,uint256,bytes)` envelope), or the envelope exceeds the route's
    /// native-value / gas caps. Fixable only by publishing a new message.
    Undeliverable,
    /// Any other deterministic, non-retryable failure (validation revert, dispatcher misconfigured,
    /// under-funded past the top-up window, mined-and-reverted).
    Terminal,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeliveryOutcome {
    pub kind: OutcomeKind,
    pub chain_key: u64,
    /// Destination-chain transaction that carried the delivery, when one was mined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<B256>,
    /// Human-readable reason for the non-delivered kinds (revert selector, cap, decode failure…).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Unix seconds when the worker reached the verdict.
    pub recorded_at: u64,
}

impl DeliveryOutcome {
    pub fn new(kind: OutcomeKind, chain_key: u64) -> Self {
        Self {
            kind,
            chain_key,
            tx_hash: None,
            reason: None,
            recorded_at: now_unix(),
        }
    }

    #[must_use]
    pub fn with_tx(mut self, tx_hash: B256) -> Self {
        self.tx_hash = Some(tx_hash);
        self
    }

    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

/// Bounded, insertion-ordered map `messageId -> DeliveryOutcome`. A later verdict for the same
/// message replaces the earlier one in place (e.g. `Pending` followed by a successful
/// `retryPendingMessage` would become `Delivered`).
pub struct OutcomeStore {
    inner: Mutex<Inner>,
    cap: usize,
}

struct Inner {
    by_id: HashMap<B256, DeliveryOutcome>,
    order: VecDeque<B256>,
}

impl OutcomeStore {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                by_id: HashMap::new(),
                order: VecDeque::new(),
            }),
            cap: cap.max(1),
        }
    }

    pub fn record(&self, message_id: B256, outcome: DeliveryOutcome) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if inner.by_id.insert(message_id, outcome).is_none() {
            inner.order.push_back(message_id);
            while inner.order.len() > self.cap {
                if let Some(old) = inner.order.pop_front() {
                    inner.by_id.remove(&old);
                }
            }
        }
    }

    #[must_use]
    pub fn get(&self, message_id: &B256) -> Option<DeliveryOutcome> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.by_id.get(message_id).cloned()
    }

    /// Outcomes for the requested ids, in request order, omitting unknown ones.
    #[must_use]
    pub fn get_many(&self, ids: &[B256]) -> Vec<(B256, DeliveryOutcome)> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        ids.iter()
            .filter_map(|id| inner.by_id.get(id).map(|o| (*id, o.clone())))
            .collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .by_id
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> B256 {
        B256::repeat_byte(n)
    }

    #[test]
    fn records_and_reads_back() {
        let store = OutcomeStore::new(10);
        store.record(
            id(1),
            DeliveryOutcome::new(OutcomeKind::Delivered, 8).with_tx(id(9)),
        );
        let got = store.get(&id(1)).expect("recorded");
        assert_eq!(got.kind, OutcomeKind::Delivered);
        assert_eq!(got.tx_hash, Some(id(9)));
        assert!(store.get(&id(2)).is_none());
    }

    #[test]
    fn later_verdict_replaces_earlier_without_growing() {
        let store = OutcomeStore::new(10);
        store.record(id(1), DeliveryOutcome::new(OutcomeKind::Pending, 8));
        store.record(id(1), DeliveryOutcome::new(OutcomeKind::Delivered, 8));
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&id(1)).unwrap().kind, OutcomeKind::Delivered);
    }

    #[test]
    fn evicts_oldest_past_cap() {
        let store = OutcomeStore::new(2);
        for n in 1..=3 {
            store.record(id(n), DeliveryOutcome::new(OutcomeKind::Terminal, 8));
        }
        assert_eq!(store.len(), 2);
        assert!(store.get(&id(1)).is_none(), "oldest evicted");
        assert!(store.get(&id(3)).is_some());
    }

    #[test]
    fn get_many_keeps_request_order_and_skips_unknown() {
        let store = OutcomeStore::new(10);
        store.record(id(2), DeliveryOutcome::new(OutcomeKind::Undeliverable, 8));
        store.record(id(1), DeliveryOutcome::new(OutcomeKind::Delivered, 9));
        let got = store.get_many(&[id(1), id(7), id(2)]);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, id(1));
        assert_eq!(got[1].0, id(2));
    }

    #[test]
    fn serializes_snake_case_and_skips_empty_fields() {
        let json = serde_json::to_string(&DeliveryOutcome {
            kind: OutcomeKind::DestinationFailed,
            chain_key: 8,
            tx_hash: None,
            reason: Some("MessageExecutionFailed".into()),
            recorded_at: 1,
        })
        .unwrap();
        assert!(json.contains("\"kind\":\"destination_failed\""));
        assert!(!json.contains("tx_hash"));
        assert!(json.contains("\"reason\":\"MessageExecutionFailed\""));
    }
}
