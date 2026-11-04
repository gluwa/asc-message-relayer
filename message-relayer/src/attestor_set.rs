//! Per-route on-chain attestor-set watcher.
//!
//! Every route sources its attestor set from the destination `EOAValidator`. This worker
//! periodically reads the destination chain id, verifies the validator's EIP-712 message-vote
//! domain (see [`crate::vote_domain`]), reads its `attestors()` + `threshold()`, and pushes a
//! [`RouteAttestors`] update to the vote pool whenever any of it changes. That lets an operator
//! add/remove an attestor on the `EOAValidator` (or change the threshold) and have the relayer pick
//! it up **without a restart**. It is also the only place the destination is read for the vote
//! path, so a destination that is down at startup just leaves the route idle until a poll succeeds.

use std::time::Duration;

use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::abi::IVoteValidator;
use crate::config::ChainRoute;
use crate::pool::RouteAttestors;
use crate::vote_domain::{self, DomainError};
use write_ability::hash::MessageVoteDomain;

/// How often to re-read the on-chain attestor set. Set changes are rare, so a slow poll keeps RPC
/// load negligible while still bounding how long the relayer runs on a stale set.
const ATTESTOR_SET_POLL_SECS: u64 = 30;

/// Run the attestor-set watcher for one route.
pub async fn run(
    route: ChainRoute,
    set_tx: mpsc::Sender<RouteAttestors>,
    health: std::sync::Arc<crate::health::Health>,
    cancel: CancellationToken,
) -> Result<()> {
    let chain_key = route.chain_key;
    let validator = route.attestor_set.validator;

    info!(chain_key, %validator, "🛂 attestor-set watcher online");

    // Health matters more here than for any other worker: every route starts at
    // `threshold: usize::MAX` with no vote domain, so until this watcher's first successful read
    // (domain verified and set read) the pool rejects
    // every vote — a watcher that can never read the validator is a *completely dead route*
    // (S1r). Heartbeat on every successful read (set changed or not); a persistent read failure
    // is reported through `Health::error`, so `/health` names the route as degraded (still
    // retrying — every poll re-dials, see below) and only a *silent* watcher goes stale and
    // restarts the process.
    let health_key = format!("attestor-set:{chain_key}");
    health.heartbeat(&health_key);

    // Last (domain, set, threshold) we pushed to the pool; `None` until the first successful read.
    let mut last: Option<(MessageVoteDomain, Vec<Address>, usize)> = None;

    // `interval` fires immediately on the first tick, so the set is resolved promptly at startup.
    let mut tick = tokio::time::interval(Duration::from_secs(ATTESTOR_SET_POLL_SECS));
    let mut pacer = crate::pacing::RateLimitPacer::default();
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!(chain_key, "🛑 attestor-set watcher exiting on cancel");
                return Ok(());
            }
            _ = tick.tick() => {
                // Rate-limit pacing: skip the poll while a deferral window is active (no arm-
                // blocking sleeps — see `crate::pacing`).
                if let Some(remaining) = pacer.deferring() {
                    tracing::debug!(chain_key, remaining_ms = remaining.as_millis() as u64,
                        "⏸️ pacing attestor-set watcher — skipping poll");
                    continue;
                }
                // Connect per poll (a bare alloy WS provider's pubsub service exits permanently
                // after one failed reconnect, which would silently freeze this watcher on a routine
                // RPC blip — part of C4). A fresh connection each 30s tick is cheap and self-heals.
                match connect_and_read(&route).await {
                    Ok((vote_domain, attestors, threshold)) => {
                        // Before the unchanged-shortcut: an unchanged set is still a successful
                        // read and must count as progress — for the health watchdog AND the
                        // pacer's decay (bugbot: the `continue` below skipped decay, freezing the
                        // level at its storm-time value through the most common success path).
                        health.heartbeat(&health_key);
                        pacer.after(false);
                        let changed = last.as_ref().is_none_or(|(d, a, t)| {
                            *d != vote_domain || a != &attestors || *t != threshold
                        });
                        if !changed {
                            continue;
                        }
                        info!(
                            chain_key,
                            attestors = attestors.len(),
                            threshold,
                            chain_id = vote_domain.chain_id,
                            validator = %vote_domain.validator,
                            inbox = %vote_domain.inbox,
                            "📥 on-chain attestor set and EIP-712 vote domain resolved/changed"
                        );
                        last = Some((vote_domain, attestors.clone(), threshold));
                        let update = RouteAttestors {
                            chain_key,
                            attestors,
                            threshold,
                            vote_domain: Some(vote_domain),
                        };
                        tokio::select! {
                            res = set_tx.send(update) => {
                                if res.is_err() {
                                    warn!(chain_key, "pool set-update channel closed; watcher exiting");
                                    return Ok(());
                                }
                            }
                            () = cancel.cancelled() => return Ok(()),
                        }
                    }
                    Err(ReadError::Incompatible(err)) => {
                        // Not transient, but not fatal either: the route stays idle (no vote is
                        // accepted) and /health shows it degraded until the validator or config is
                        // fixed. Polling continues so a fix is picked up without a restart.
                        health.error(&health_key);
                        pacer.after(false);
                        error!(chain_key, %validator, err = %format!("{err:#}"),
                            "destination validator is not compatible with EIP-712 message votes; \
                             route accepts no votes until fixed");
                    }
                    Err(ReadError::Transient(err)) => {
                        let rate_limited =
                            crate::pacing::error_looks_rate_limited(&format!("{err:#}"));
                        health.error(&health_key);
                        warn!(chain_key, %err, "failed to read on-chain attestor set; will retry");
                        // Rate-limit pacing — see `crate::pacing`: this 30s poll runs on every
                        // route and collides with the attestor fleet's synchronized per-block
                        // bursts on shared, RPS-capped endpoints. Arm a deferral window instead
                        // of colliding again next tick.
                        pacer.after(rate_limited);
                        if rate_limited {
                            if let Some(window) = pacer.deferring() {
                                warn!(chain_key, defer_ms = window.as_millis() as u64,
                                    "🧯 provider is rate limiting — deferring attestor-set polls");
                            }
                        }
                    }
                }
            }
        }
    }
}

/// A failed poll, split like [`DomainError`]: transport trouble, or a validator that does not
/// match the route's EIP-712 vote domain.
enum ReadError {
    Transient(anyhow::Error),
    Incompatible(anyhow::Error),
}

impl From<anyhow::Error> for ReadError {
    fn from(err: anyhow::Error) -> Self {
        Self::Transient(err)
    }
}

/// Connect to the destination RPC, read and verify the vote domain, then read `attestors()` +
/// `threshold()`. A fresh connection per call so a dropped WS transport self-heals on the next
/// poll instead of wedging the watcher.
async fn connect_and_read(
    route: &ChainRoute,
) -> Result<(MessageVoteDomain, Vec<Address>, usize), ReadError> {
    let url = &route.destination_rpc_url;
    let provider = ProviderBuilder::new().connect(url).await.with_context(|| {
        format!("attestor-set watcher failed to connect to destination RPC at {url}")
    })?;
    let domain = vote_domain::read(&provider, route)
        .await
        .map_err(|err| match err {
            DomainError::Transient(e) => ReadError::Transient(e),
            DomainError::Incompatible(e) => ReadError::Incompatible(e),
        })?;
    let (attestors, threshold) = read_set(&provider, route.attestor_set.validator).await?;
    Ok((domain, attestors, threshold))
}

/// Read `attestors()` + `threshold()` from the destination validator contract.
async fn read_set<P: Provider>(provider: &P, validator: Address) -> Result<(Vec<Address>, usize)> {
    let validator = IVoteValidator::new(validator, provider);

    let attestors = validator
        .attestors()
        .call()
        .await
        .context("IVoteValidator.attestors() call failed")?;

    let threshold_u256 = validator
        .threshold()
        .call()
        .await
        .context("IVoteValidator.threshold() call failed")?;
    // Saturate rather than panic on an absurd on-chain value; an over-large threshold simply means
    // "never deliver", which is the safe direction.
    let threshold = u64::try_from(threshold_u256).unwrap_or(u64::MAX) as usize;

    Ok((attestors, threshold))
}
