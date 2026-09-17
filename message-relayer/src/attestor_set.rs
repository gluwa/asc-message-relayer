//! Per-route on-chain attestor-set watcher.
//!
//! For routes whose attestor set is sourced on-chain (`AttestorSet::OnChain { Evm }`), this worker
//! periodically reads the destination validator's `attestors()` + `threshold()` and pushes a
//! [`RouteAttestors`] update to the vote pool whenever they change. That lets an operator
//! add/remove an attestor on the `EOAValidator` (or change the threshold) and have the relayer pick
//! it up **without a restart** — closing the "static set, resolved once" gap. Routes with a static
//! configured set don't run a watcher.

use std::time::Duration;

use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::abi::IVoteValidator;
use crate::config::{AttestorSet, AttestorSource, ChainRoute};
use crate::pool::RouteAttestors;

/// How often to re-read the on-chain attestor set. Set changes are rare, so a slow poll keeps RPC
/// load negligible while still bounding how long the relayer runs on a stale set.
const ATTESTOR_SET_POLL_SECS: u64 = 30;

/// Run the attestor-set watcher for one route. Only `AttestorSet::OnChain { Evm }` routes should be
/// spawned (callers filter); the `Cc3` source is not yet implemented and a static set never changes.
pub async fn run(
    route: ChainRoute,
    set_tx: mpsc::Sender<RouteAttestors>,
    health: std::sync::Arc<crate::health::Health>,
    cancel: CancellationToken,
) -> Result<()> {
    let chain_key = route.chain_key;
    let validator = match &route.attestor_set {
        AttestorSet::OnChain {
            source: AttestorSource::Evm { address },
        } => *address,
        AttestorSet::OnChain {
            source: AttestorSource::Cc3 { .. },
        } => {
            // Not yet implemented — but this worker was still spawned (lib.rs filters on
            // `OnChain { .. }`, which matches Cc3), and returning here would look to the supervisor
            // like a worker died, tearing down the whole relayer into a crash-loop (S2r). Park until
            // shutdown instead: the route simply runs on its startup-resolved set with no hot-reload.
            warn!(
                chain_key,
                "cc3 attestor-set source is not implemented; set will not hot-reload — parking watcher"
            );
            cancel.cancelled().await;
            return Ok(());
        }
        // Defensive: static routes are not spawned (lib.rs filters them out), but park rather than
        // exit-as-fatal if one ever reaches here.
        AttestorSet::Static(_) => {
            cancel.cancelled().await;
            return Ok(());
        }
    };

    info!(chain_key, %validator, "🛂 attestor-set watcher online");

    // Health matters more here than for any other worker: an OnChain route starts at
    // `threshold: usize::MAX`, so until this watcher's first successful read the pool rejects
    // every vote — a watcher that can never read the validator is a *completely dead route*
    // (S1r). Heartbeat on every successful read (set changed or not); a persistent read failure
    // is reported through `Health::error`, so `/health` names the route as degraded (still
    // retrying — every poll re-dials, see below) and only a *silent* watcher goes stale and
    // restarts the process. Registered only in this Evm arm — the parked Cc3/static arms above
    // never resolve a set, so registering them would trip a permanently-stale false positive.
    let health_key = format!("attestor-set:{chain_key}");
    health.heartbeat(&health_key);

    // Last (set, threshold) we pushed to the pool; `None` until the first successful read.
    let mut last: Option<(Vec<Address>, usize)> = None;

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
                match connect_and_read_set(&route.destination_rpc_url, validator).await {
                    Ok((attestors, threshold)) => {
                        // Before the unchanged-shortcut: an unchanged set is still a successful
                        // read and must count as progress — for the health watchdog AND the
                        // pacer's decay (bugbot: the `continue` below skipped decay, freezing the
                        // level at its storm-time value through the most common success path).
                        health.heartbeat(&health_key);
                        pacer.after(false);
                        let changed = last
                            .as_ref()
                            .is_none_or(|(a, t)| a != &attestors || *t != threshold);
                        if !changed {
                            continue;
                        }
                        info!(
                            chain_key,
                            attestors = attestors.len(),
                            threshold,
                            "📥 on-chain attestor set resolved/changed"
                        );
                        last = Some((attestors.clone(), threshold));
                        let update = RouteAttestors { chain_key, attestors, threshold };
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
                    Err(err) => {
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

/// Connect to the destination RPC and read `attestors()` + `threshold()`. A fresh connection per
/// call so a dropped WS transport self-heals on the next poll instead of wedging the watcher.
async fn connect_and_read_set(url: &str, validator: Address) -> Result<(Vec<Address>, usize)> {
    let provider = ProviderBuilder::new().connect(url).await.with_context(|| {
        format!("attestor-set watcher failed to connect to destination RPC at {url}")
    })?;
    read_set(&provider, validator).await
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
