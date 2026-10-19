//! Creditcoin's source authorization is defined at a finalized block. RPC errors and elapsed
//! time cannot authorize an unfinalized scan, including when deterministic finality is stalled.

use std::time::{Duration, Instant};

use alloy::eips::BlockNumberOrTag;
use alloy::providers::Provider;
use anyhow::{Context, Result};

pub const FINALITY_STALL_TIMEOUT: Duration = Duration::from_secs(600);
const FINALIZED_READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalityPolicy {
    /// Production Creditcoin source policy; fails closed when finality is unavailable.
    Finalized,
    /// Explicit policy for test chains without deterministic finality. Never selected as fallback.
    Depth(u64),
}

#[derive(Debug)]
pub struct FinalityTracker {
    last_finalized: Option<u64>,
    last_advance: Instant,
    stalled: bool,
}

impl FinalityTracker {
    #[must_use]
    pub fn new(now: Instant) -> Self {
        Self {
            last_finalized: None,
            last_advance: now,
            stalled: false,
        }
    }

    #[must_use]
    pub fn is_stalled(&self) -> bool {
        self.stalled
    }
}

pub fn pick_to_block(
    finalized: Option<u64>,
    tip: u64,
    policy: &FinalityPolicy,
    tracker: &mut FinalityTracker,
    now: Instant,
) -> Result<u64> {
    match policy {
        FinalityPolicy::Depth(depth) => Ok(tip.saturating_sub(*depth)),
        FinalityPolicy::Finalized => {
            let finalized = finalized.context("finalized head unavailable; source scan paused")?;
            anyhow::ensure!(
                tracker
                    .last_finalized
                    .is_none_or(|previous| finalized >= previous),
                "finalized head regressed; source scan paused"
            );
            if tracker
                .last_finalized
                .is_none_or(|previous| finalized > previous)
            {
                tracker.last_finalized = Some(finalized);
                tracker.last_advance = now;
                tracker.stalled = false;
            } else {
                tracker.stalled =
                    now.duration_since(tracker.last_advance) >= FINALITY_STALL_TIMEOUT;
            }
            Ok(finalized)
        }
    }
}

pub async fn read_finalized_head<P: Provider>(provider: &P) -> Result<u64> {
    let block = tokio::time::timeout(
        FINALIZED_READ_TIMEOUT,
        provider.get_block_by_number(BlockNumberOrTag::Finalized),
    )
    .await
    .context("finalized head lookup timed out; source scan paused")?
    .context("finalized head lookup failed; source scan paused")?
    .context("finalized head unavailable; source scan paused")?;
    Ok(block.header.number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_policy_is_explicit() {
        let now = Instant::now();
        let mut tracker = FinalityTracker::new(now);
        assert_eq!(
            pick_to_block(None, 100, &FinalityPolicy::Depth(5), &mut tracker, now).unwrap(),
            95
        );
        assert!(pick_to_block(None, 100, &FinalityPolicy::Finalized, &mut tracker, now).is_err());
    }

    #[test]
    fn finalized_boundary_never_falls_back_on_stall_or_regression() {
        let now = Instant::now();
        let mut tracker = FinalityTracker::new(now);
        let policy = FinalityPolicy::Finalized;
        assert_eq!(
            pick_to_block(Some(90), 100, &policy, &mut tracker, now).unwrap(),
            90
        );
        assert_eq!(
            pick_to_block(
                Some(90),
                1000,
                &policy,
                &mut tracker,
                now + FINALITY_STALL_TIMEOUT
            )
            .unwrap(),
            90
        );
        assert!(tracker.is_stalled());
        assert!(pick_to_block(
            None,
            1000,
            &policy,
            &mut tracker,
            now + FINALITY_STALL_TIMEOUT
        )
        .is_err());
        assert!(pick_to_block(
            Some(89),
            1000,
            &policy,
            &mut tracker,
            now + FINALITY_STALL_TIMEOUT
        )
        .is_err());
        assert_eq!(tracker.last_finalized, Some(90));
        assert_eq!(
            pick_to_block(
                Some(91),
                1000,
                &policy,
                &mut tracker,
                now + FINALITY_STALL_TIMEOUT
            )
            .unwrap(),
            91
        );
        assert!(!tracker.is_stalled());
    }
}
