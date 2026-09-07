//! Scan-boundary selection for the Creditcoin Outbox watcher.
//!
//! Creditcoin has deterministic GRANDPA finality, so the right boundary for "which
//! `MessagePublished` logs may I act on" is the **finalized head**: a finalized block cannot be
//! reorged out from under a delivery, and on devnet it trails the tip by only a couple of blocks.
//! The attestors already sign at exactly that boundary (creditcoin3
//! `attestor/src/tasks/write_ability/listener.rs`), which is why they had their votes out ~12 s
//! after a publish while the relayer, scanning `tip - block_confirmation_depth` with depth 32,
//! did not even notice the message for ~3 minutes (usc-devnet, 2026-09-07).
//!
//! This module mirrors the attestor's policy so both sides see a message at the same moment:
//! the finalized head is primary; `block_confirmation_depth` is only the *fallback* bound, used
//! when the RPC has no `finalized` tag (or the read fails) or when finality has stalled for longer
//! than [`FINALITY_STALL_TIMEOUT`]. The fallback never regresses the scan below a finalized head
//! we have already trusted.

use std::time::{Duration, Instant};

use alloy::eips::BlockNumberOrTag;
use alloy::providers::Provider;
use tracing::warn;

/// How long the finalized head may stay frozen while the tip keeps advancing before we treat
/// finality as *stalled* (not merely lagging) and fall back to the probabilistic depth bound.
/// Ten minutes is far beyond any healthy GRANDPA lag and short enough that a genuinely stuck
/// finality gadget does not strand delivery indefinitely.
pub const FINALITY_STALL_TIMEOUT: Duration = Duration::from_secs(600);

/// Per-read deadline for the `finalized` block lookup. Only this call is bounded here; the log
/// scan that follows has its own handling in the watcher.
const FINALIZED_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Which boundary a scan may advance to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalityPolicy {
    /// Scan up to the chain's finalized head (exact, reorg-proof): the production policy for
    /// Creditcoin. Falls back to `tip - fallback_depth` only when the finalized head is unavailable
    /// or has stalled past [`FINALITY_STALL_TIMEOUT`].
    Finalized { fallback_depth: u64 },
    /// Always scan up to `tip - depth` (probabilistic). For chains or harnesses without
    /// deterministic finality.
    Depth(u64),
}

/// Runtime finality state carried across polls so a genuine finality *stall* can be told apart
/// from ordinary lag, and so a transient failed `finalized` read can never move the scan
/// backwards past a head already known to be final.
#[derive(Debug)]
pub struct FinalityTracker {
    last_finalized: Option<u64>,
    last_advance: Instant,
    in_fallback: bool,
}

impl FinalityTracker {
    #[must_use]
    pub fn new(now: Instant) -> Self {
        Self {
            last_finalized: None,
            last_advance: now,
            in_fallback: false,
        }
    }

    /// Whether the most recent [`pick_to_block`] used the depth fallback instead of finality.
    #[must_use]
    pub fn in_fallback(&self) -> bool {
        self.in_fallback
    }
}

/// Choose the highest block a scan may include this poll.
///
/// Pure so the rules are unit-testable without an RPC or timers; the watcher supplies
/// `finalized` from [`read_finalized_head`] and `now` from the clock.
#[must_use]
pub fn pick_to_block(
    finalized: Option<u64>,
    tip: u64,
    policy: &FinalityPolicy,
    tracker: &mut FinalityTracker,
    now: Instant,
) -> u64 {
    match *policy {
        FinalityPolicy::Depth(depth) => {
            tracker.in_fallback = false;
            tip.saturating_sub(depth)
        }
        FinalityPolicy::Finalized { fallback_depth } => match finalized {
            Some(f) => {
                let advanced = tracker.last_finalized.is_none_or(|prev| f > prev);
                if advanced {
                    tracker.last_finalized = Some(f);
                    tracker.last_advance = now;
                    tracker.in_fallback = false;
                    f
                } else if now.duration_since(tracker.last_advance) >= FINALITY_STALL_TIMEOUT {
                    // Finality genuinely stalled: use the probabilistic bound, but never below the
                    // last finalized head we already trust.
                    tracker.in_fallback = true;
                    tip.saturating_sub(fallback_depth).max(f)
                } else {
                    // Lagging but not stalled: stay at the finalized head.
                    tracker.in_fallback = false;
                    f
                }
            }
            None => {
                // No finalized head this poll (tag unsupported, read failed or timed out). Use the
                // probabilistic bound but never regress below a head we already trusted, or a
                // transient blip could re-scan and re-deliver from an unfinalized range.
                tracker.in_fallback = true;
                tip.saturating_sub(fallback_depth)
                    .max(tracker.last_finalized.unwrap_or(0))
            }
        },
    }
}

/// The chain's current finalized block number, or `None` when the RPC cannot say (no `finalized`
/// tag, error, or timeout). Callers treat `None` as "use the depth fallback this poll"; the
/// warning here is the only trace that the fallback is being exercised.
pub async fn read_finalized_head<P: Provider>(provider: &P, chain_key: u64) -> Option<u64> {
    match tokio::time::timeout(
        FINALIZED_READ_TIMEOUT,
        provider.get_block_by_number(BlockNumberOrTag::Finalized),
    )
    .await
    {
        Ok(Ok(Some(block))) => Some(block.header.number),
        Ok(Ok(None)) => None,
        Ok(Err(err)) => {
            warn!(
                chain_key,
                %err,
                "finalized-head read failed; Outbox scan uses the depth fallback this poll"
            );
            None
        }
        Err(_) => {
            warn!(
                chain_key,
                "finalized-head read timed out; Outbox scan uses the depth fallback this poll"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_policy_uses_tip_minus_depth() {
        let t0 = Instant::now();
        let mut tr = FinalityTracker::new(t0);
        assert_eq!(
            pick_to_block(None, 110, &FinalityPolicy::Depth(3), &mut tr, t0),
            107
        );
        assert!(!tr.in_fallback());
        assert_eq!(
            pick_to_block(Some(50), 110, &FinalityPolicy::Depth(0), &mut tr, t0),
            110,
            "a depth policy ignores the finalized head entirely"
        );
    }

    #[test]
    fn finalized_primary_uses_finalized_head() {
        let t0 = Instant::now();
        let pol = FinalityPolicy::Finalized { fallback_depth: 32 };
        let mut tr = FinalityTracker::new(t0);
        // Finalized trails the tip by 2, depth would have said 78: we scan to 108, not 78.
        assert_eq!(pick_to_block(Some(108), 110, &pol, &mut tr, t0), 108);
        assert!(!tr.in_fallback());
        assert_eq!(
            pick_to_block(Some(118), 120, &pol, &mut tr, t0 + Duration::from_secs(6)),
            118
        );
        assert!(!tr.in_fallback());
    }

    #[test]
    fn lagging_but_not_stalled_stays_at_finalized() {
        let t0 = Instant::now();
        let pol = FinalityPolicy::Finalized { fallback_depth: 3 };
        let mut tr = FinalityTracker::new(t0);
        assert_eq!(pick_to_block(Some(100), 110, &pol, &mut tr, t0), 100);
        let within = t0 + FINALITY_STALL_TIMEOUT - Duration::from_secs(1);
        assert_eq!(pick_to_block(Some(100), 200, &pol, &mut tr, within), 100);
        assert!(!tr.in_fallback());
    }

    #[test]
    fn stalled_finality_falls_back_to_depth_bound_then_recovers() {
        let t0 = Instant::now();
        let pol = FinalityPolicy::Finalized { fallback_depth: 3 };
        let mut tr = FinalityTracker::new(t0);
        assert_eq!(pick_to_block(Some(100), 110, &pol, &mut tr, t0), 100);
        let past = t0 + FINALITY_STALL_TIMEOUT + Duration::from_secs(1);
        assert_eq!(pick_to_block(Some(100), 200, &pol, &mut tr, past), 197);
        assert!(tr.in_fallback());
        // Finality resumes: back to the finalized head, fallback flag clears.
        assert_eq!(
            pick_to_block(Some(210), 220, &pol, &mut tr, past + Duration::from_secs(6)),
            210
        );
        assert!(!tr.in_fallback());
    }

    #[test]
    fn stalled_fallback_never_goes_below_the_finalized_head() {
        let t0 = Instant::now();
        let pol = FinalityPolicy::Finalized { fallback_depth: 50 };
        let mut tr = FinalityTracker::new(t0);
        assert_eq!(pick_to_block(Some(100), 110, &pol, &mut tr, t0), 100);
        let past = t0 + FINALITY_STALL_TIMEOUT + Duration::from_secs(1);
        // tip - depth = 70 < finalized 100: the finalized head wins.
        assert_eq!(pick_to_block(Some(100), 120, &pol, &mut tr, past), 100);
    }

    #[test]
    fn no_finalized_head_uses_depth_bound() {
        let t0 = Instant::now();
        let pol = FinalityPolicy::Finalized { fallback_depth: 5 };
        let mut tr = FinalityTracker::new(t0);
        assert_eq!(pick_to_block(None, 100, &pol, &mut tr, t0), 95);
        assert!(tr.in_fallback());
    }

    #[test]
    fn no_finalized_head_never_regresses_below_last_finalized() {
        let t0 = Instant::now();
        let pol = FinalityPolicy::Finalized { fallback_depth: 5 };
        let mut tr = FinalityTracker::new(t0);
        assert_eq!(pick_to_block(Some(100), 100, &pol, &mut tr, t0), 100);
        // A failed read right after: tip - depth would be 96, but 100 is already trusted.
        assert_eq!(pick_to_block(None, 101, &pol, &mut tr, t0), 100);
        assert!(tr.in_fallback());
        assert_eq!(pick_to_block(None, 110, &pol, &mut tr, t0), 105);
    }
}
