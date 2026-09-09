//! Off-chain acknowledgment submitter (research §05/§10).
//!
//! Trust-minimized acknowledgment is **proof-based, not vote-based**. For each route that opts in
//! (`route.ack = Some(..)`), this worker:
//!
//!  1. Watches the **destination** Inbox for `MessageDelivered(bytes32 indexed messageId)` —
//!     evidence that a message was delivered to the destination dApp.
//!  2. For the transaction that emitted it, fetches a native USC delivery proof from the proof-gen
//!     API (`GET {proof_gen_url}/api/v1/proof-by-tx/{chain_key}/{tx_hash}`): the prover `txBytes`
//!     plus the merkle-inclusion and continuity proofs.
//!  3. Submits that proof to the source-chain `AcknowledgmentValidator.submitAcknowledgment(..)`.
//!     The contract verifies the proof against the block-prover precompile, decodes the
//!     `MessageDelivered` logs, and calls `Outbox.acknowledgeMessage` for each — so the relayer
//!     never needs acknowledge authority; the proof is self-validating.
//!
//! ## Relay-fee claiming (`AckAndClaim` mode)
//!
//! When the route has a `RelayerContract` configured (`route.relayer_contract_address = Some(..)`),
//! this same watcher ALSO settles the relay fee: from the same delivery proof it calls
//! `RelayerContract.claimDelivery(messageId, ..)` per delivered message, which pays the relay fee
//! (+ any unexpired tip) to the relayer proven in the destination `MessageDelivered` event.
//!
//! The discovery scan also watches `MessagePending` (dApp callback reverted; message stored for
//! `retryPendingMessage`): `EVMDeliveryDecoder` accepts a proof over a `MessagePending`-emitting
//! tx as payable, but only from the *original* `deliverMessage` tx — a later `retryPendingMessage`
//! tx carries the wrong call selector and the decoder rejects it. Without this, a message that
//! ever goes pending strands its relay fee forever: the originating tx is never enqueued, and a
//! successful retry's tx is unusable as a claim proof. A `MessagePending` tx has no
//! `submitAcknowledgment` proof to offer — `acknowledge_tx`'s existing terminal classification
//! already handles that, skipping straight to the claim.
//!
//! Since usc-contracts #23 the claim does NOT acknowledge — ack settlement lives solely on the
//! `AcknowledgmentValidator` — so the two submissions are independent and BOTH run here, ack first:
//! the message's user-set ackFee is an open bounty paid to the first successful `submitAcknowledgment`
//! sender (front-runnable by design, Jul 28 decision), while `claimDelivery` pays the proven relayer
//! no matter who or when submits. Losing the ack race is therefore terminal-but-harmless for the
//! bounty and never blocks the fee claim. Everything else — the destination watcher, proof-gen
//! fetch, checkpointing, dedup, and backoff — is shared verbatim between the two settlements.
//!
//! Submission is keyed (and deduped) by destination **transaction hash**: one transaction may
//! contain several `MessageDelivered` logs and the validator acknowledges all of them in a single
//! call. A transaction whose proof is not available *yet* — HTTP 422 (`BlockNotReady`: block not
//! attested) or 404 (proof-gen's own view of the destination chain has not caught up with the tx)
//! from the proof-gen API — is re-polled on a flat, short cadence for a bounded window and only
//! then slides into the slow backoff; see [`crate::pending::NotReadyPolicy`] and
//! [`crate::proofgen`] for why a 404 is "not yet" rather than an error.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::network::{Ethereum, EthereumWallet};
use alloy::primitives::{Address, B256, U256};
use alloy::providers::{PendingTransactionBuilder, Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolError, SolEvent};
use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::abi::{IInbox, IOutbox};
use crate::checkpoint::CheckpointStore;
use crate::config::{AckConfig, ChainRoute};
use crate::events::{OutboxResolver, DEFAULT_RESOLVE_POLL_INTERVAL_SECS};
use crate::pending::{BoundedSeen, PendingTxs};
use crate::prom::{Metrics, ProofFetchOutcome, SettlementOutcome};
use crate::proofgen::{ProofFetch, ProofGenClient, ProofNotReady};

/// Poll cadence for the destination `MessageDelivered` watcher and the pending-proof retry queue.
pub const ACK_POLL_INTERVAL_SECS: u64 = 6;

/// Maximum `encodedTransaction` size accepted on-chain by
/// `AcknowledgmentValidator.submitAcknowledgment`. Mirrors `MAX_ENCODED_TRANSACTION_BYTES` in
/// `usc-messaging/contracts/src/AcknowledgmentValidator.sol`; keep the two in sync. Proofs larger
/// than this are rejected on submission (`EncodedTransactionTooLarge`), so we skip them locally
/// instead of paying gas on a guaranteed revert.
pub const MAX_ENCODED_TRANSACTION_BYTES: usize = 500_000;

/// Hard cap on the unacknowledged-tx queue. Without it a prolonged proof-gen outage (or a delivery
/// whose block never attests) would grow `pending` without bound. On overflow the oldest entry is
/// given up (logged) so newer deliveries keep flowing.
const MAX_PENDING_ACKS: usize = 10_000;

/// Hard cap on the set of recently-finished tx hashes kept for in-session dedup. The destination
/// cursor is monotonic, so evicting the oldest entries cannot cause a re-scan to re-process them —
/// this just stops a long-running relayer from leaking one entry per delivery forever.
const MAX_DONE_TRACKED: usize = 10_000;

/// Most pending txs attempted per tick. Bounds how long one tick can run (and how many proof-gen
/// requests it can fan out) regardless of how large `pending` has grown; the rest are retried on
/// subsequent ticks in oldest-first order.
const MAX_ACKS_PER_TICK: usize = 256;

/// Maximum concurrent proof-fetch + submit attempts within a tick. Bounds load on the proof-gen
/// API and the source RPC while still pipelining instead of going strictly serial.
const MAX_ACK_CONCURRENCY: usize = 8;

/// Maximum block span per `eth_getLogs` scan. Public RPCs cap the queryable range; an over-large
/// resume range (long downtime, deep `start_block` backfill) would error on every tick and wedge
/// discovery forever. Bounded chunks advance the cursor incrementally — the 6s tick catches up.
const MAX_BLOCKS_PER_SCAN: u64 = 2_000;

/// Upper bound on waiting for the submitAcknowledgment receipt, so one stuck tx cannot wedge the
/// per-tick pipeline. On timeout the tx stays pending and is retried on a later tick (idempotent:
/// a duplicate lands as `MessageAlreadyAcknowledged`, a terminal revert).
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Upper bound on a single `submitAcknowledgment` broadcast — the gas/fee/nonce reads plus
/// `eth_sendRawTransaction`. Alloy's HTTP transport sets no timeout of its own, so a black-holed
/// Creditcoin RPC would otherwise park this attempt forever, and with it the tick's whole
/// `buffer_unordered` batch and the worker's cancel branch. Bounding it also bounds how long one
/// attempt can hold the signer's broadcast slot.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Give up on a tx whose proof never becomes ready (e.g. its block is never attested, or the tx
/// hash proof-gen keeps answering 404 for does not exist). Generous: far beyond any healthy
/// finality + attestation latency. The re-poll cadence *before* this point is the route's
/// [`crate::pending::NotReadyPolicy`] (`ack.not_ready_poll_secs` /
/// `ack.not_ready_poll_window_secs`): flat and short while the proof is expected to appear on its
/// own, slow backoff once it is overdue. Not ready never counts against the transient-failure
/// budget.
const MAX_ACK_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Give up loudly after this many *transient* submit failures (RPC down, timeout, nonce) — a
/// permanently failing submit (e.g. unfunded ack signer) must not hammer the RPC forever. The
/// per-attempt exponential backoff lives in [`crate::pending`].
const MAX_ACK_TRANSIENT_ATTEMPTS: u32 = 20;

/// Spawn the acknowledgment submitter for one route. Returns immediately when the route has no
/// `ack` config; otherwise loops until `cancel` fires or an unrecoverable error occurs.
/// `scan_lookback_blocks` rewinds the persisted cursor on startup so acks that were pending when
/// the process died are re-discovered (see [`crate::config::DEFAULT_SCAN_LOOKBACK_BLOCKS`]).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    route: ChainRoute,
    creditcoin_eth_rpc_url: String,
    resolver: Arc<dyn OutboxResolver>,
    checkpoint: Option<Arc<CheckpointStore>>,
    scan_lookback_blocks: u64,
    metrics: Metrics,
    health: Arc<crate::health::Health>,
    broadcast_locks: Arc<crate::broadcast::BroadcastLocks>,
    cancel: CancellationToken,
) -> Result<()> {
    let chain_key = route.chain_key;
    let checkpoint_key = format!("ack:{chain_key}");
    let health_key = checkpoint_key.clone();
    let Some(ack) = route.ack.clone() else {
        debug!(chain_key, "ack disabled for route; submitter not started");
        return Ok(());
    };

    // A route with a RelayerContract configured settles the relay fee via `claimDelivery` IN
    // ADDITION to the standalone `submitAcknowledgment` — since usc-contracts #23 the claim no
    // longer bundles the ack, so the two submissions are independent and both must run; see the
    // module docs. The chain key is passed to `claimDelivery` as `bytes32(uint256(chainKey))`,
    // matching the ledger's route check.
    let mode = match route.relayer_contract_address {
        Some(relayer_contract) => SettlementMode::AckAndClaim {
            relayer_contract,
            chain_key: B256::from(U256::from(chain_key)),
        },
        None => SettlementMode::Ack,
    };

    // Register with the health watchdog BEFORE any fallible or blocking setup: `Health::status`
    // only inspects components that have registered, so a worker that never called `heartbeat` is
    // invisible to it and counts as healthy. Both connects below, and the `get_block_number` start
    // lookup on first boot, are unbounded RPC awaits — registering after them means a black-holed
    // endpoint leaves acks permanently unsubmitted while `/health` keeps answering 200. Must stay
    // *after* the `route.ack` guard above, though: a route with acks disabled has no worker to
    // report on, and registering one would make it go stale forever.
    health.heartbeat(&health_key);

    // Read-only provider on the destination chain (where MessageDelivered is emitted).
    let dest_provider = ProviderBuilder::new()
        .connect(&route.destination_rpc_url)
        .await
        .with_context(|| {
            format!(
                "chain_key {chain_key}: ack submitter failed to connect to destination RPC at {}",
                route.destination_rpc_url
            )
        })?;

    // Wallet-bearing provider on the source (Creditcoin) chain, where we submit the ack.
    let signer: PrivateKeySigner = ack
        .signer_key
        .trim()
        .parse()
        .with_context(|| format!("chain_key {chain_key}: invalid ack.signer_key"))?;
    let submitter_address = signer.address();
    // Chain-read nonces: a failed broadcast must not consume a nonce the chain never saw, which with
    // a local counter wedges every later ack until restart. The submit loop below fans out
    // `MAX_ACK_CONCURRENCY` sends over this one provider, so they would otherwise all read the same
    // pending count and all but one fail as `nonce too low`; `broadcast_locks` serializes them on the
    // submitter address instead — and, unlike the per-provider counter it replaces, also against any
    // other route configured with this same Creditcoin key. See `crate::broadcast`.
    let source_provider = crate::broadcast::chain_nonce_builder()
        .wallet(EthereumWallet::from(signer))
        .connect(&creditcoin_eth_rpc_url)
        .await
        .with_context(|| {
            format!(
                "chain_key {chain_key}: ack submitter failed to connect to Creditcoin EVM RPC at \
                 {creditcoin_eth_rpc_url}"
            )
        })?;

    let client = ProofGenClient::new(&ack.proof_gen_url)?;

    // Best-effort source Outbox address for `acknowledge_tx`'s `canAck`/already-acked pre-check —
    // a pure cost-saving shortcut, so failure to resolve here is not fatal: the pre-check just
    // fails open until a resolution succeeds.
    let dyn_provider = source_provider.clone().erased();
    let mut outbox = match resolver.resolve(&route, &dyn_provider).await {
        Ok(resolved) => Some(resolved.address),
        Err(err) => {
            debug!(
                chain_key,
                %err,
                "source Outbox not resolved yet; canAck pre-check fails open until it is"
            );
            None
        }
    };

    match &mode {
        SettlementMode::Ack => info!(
            chain_key,
            inbox = %route.inbox_address,
            validator = %ack.validator_address,
            submitter = %submitter_address,
            proof_gen_url = %ack.proof_gen_url,
            "🧾 acknowledgment submitter online (ack mode)"
        ),
        SettlementMode::AckAndClaim {
            relayer_contract, ..
        } => info!(
            chain_key,
            inbox = %route.inbox_address,
            validator = %ack.validator_address,
            relayer_contract = %relayer_contract,
            submitter = %submitter_address,
            proof_gen_url = %ack.proof_gen_url,
            "💰 settlement submitter online (ack + relay-fee claim; independent since usc-contracts #23)"
        ),
    }

    // Resume from the persisted cursor so MessageDelivered events emitted while we were down are
    // not skipped; fall back to the current head on first run / when persistence is disabled.
    // The cursor is rewound by `scan_lookback_blocks`: the pending-ack queue is memory-only, so a
    // delivery discovered-but-not-acknowledged before a crash would otherwise be skipped forever.
    // Re-processing is cheap — already-acked / no-ack-needed txs are skipped by the canAck
    // pre-check before any proof is fetched.
    let mut last_seen = match checkpoint.as_ref().and_then(|c| c.get(&checkpoint_key)) {
        Some(block) => {
            let resume = block.saturating_sub(scan_lookback_blocks);
            info!(
                chain_key,
                checkpoint = block,
                resume_from = resume + 1,
                "↩️ resuming ack scan from checkpoint (rewound by lookback)"
            );
            resume
        }
        None => {
            if let Some(start) = ack.start_block {
                info!(
                    chain_key,
                    start_block = start,
                    "⏮️ no ack checkpoint; starting initial scan from configured block"
                );
                start.saturating_sub(1)
            } else {
                dest_provider.get_block_number().await.with_context(|| {
                    format!("chain_key {chain_key}: ack submitter failed to read chain head")
                })?
            }
        }
    };

    // Destination tx hashes seen but not yet acknowledged (proof not ready / transient failure).
    let mut pending = PendingTxs::new(MAX_PENDING_ACKS);
    // Tx hashes already acknowledged (or terminally skipped) — never re-submitted (bounded).
    let mut done = BoundedSeen::new(MAX_DONE_TRACKED);
    // The source Outbox each pending tx was tagged with at first discovery — captured once and
    // never updated again for that entry, even if `outbox` later rotates. Using whatever `outbox`
    // is *now* would ask a message's canAck state from a contract it was never published on after
    // a rotation (unknown id defaults to `false`), turning a real unsettled ack into a false
    // "nothing to do". Kept in lockstep with `pending`/`done`: removed wherever they are.
    let mut pending_outbox: HashMap<B256, Address> = HashMap::new();

    let mut tick = tokio::time::interval(Duration::from_secs(crate::config::poll_secs_override(
        "RELAYER_ACK_POLL_SECS",
        ACK_POLL_INTERVAL_SECS,
    )));
    let mut pacer = crate::pacing::RateLimitPacer::default();
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut resolve_tick =
        tokio::time::interval(Duration::from_secs(crate::config::poll_secs_override(
            "RELAYER_OUTBOX_RESOLVE_POLL_SECS",
            DEFAULT_RESOLVE_POLL_INTERVAL_SECS,
        )));
    resolve_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!(chain_key, "🛑 acknowledgment submitter exiting on cancel");
                return Ok(());
            }
            _ = resolve_tick.tick() => {
                match resolver.resolve(&route, &dyn_provider).await {
                    Ok(resolved) => {
                        if outbox != Some(resolved.address) {
                            info!(
                                chain_key,
                                outbox = %resolved.address,
                                "🔁 source Outbox resolved for the canAck pre-check"
                            );
                            outbox = Some(resolved.address);
                        }
                    }
                    Err(err) => debug!(chain_key, %err, "source Outbox re-resolution failed; keeping previous state"),
                }
            }
            _ = tick.tick() => {
                // Rate-limit pacing: while a deferral window is active, skip the tick entirely —
                // no sleeping inside the select arm (see `crate::pacing`).
                if let Some(remaining) = pacer.deferring() {
                    tracing::debug!(chain_key, remaining_ms = remaining.as_millis() as u64,
                        "⏸️ pacing ack discovery — skipping tick");
                    continue;
                }
                let mut rate_limited = false;
                match discover_delivered(
                    chain_key,
                    route.inbox_address,
                    ack.confirmation_depth,
                    &dest_provider,
                    &mut last_seen,
                    &mut pending,
                    &done,
                    outbox,
                    &mut pending_outbox,
                ).await {
                    Ok(()) => {
                        // Successful destination scan = loop progress (C2r).
                        health.heartbeat(&health_key);
                        if let Some(cp) = &checkpoint {
                            // Clamp the *persisted* cursor so it never advances past a tx that is
                            // still pending (proof not ready / retrying): a restart then rescans
                            // from before the oldest unfinished tx and re-discovers it, no matter
                            // how long it was pending. The in-memory cursor keeps advancing, so the
                            // live scan never re-reads; re-discovery on restart is idempotent
                            // (canAck / AlreadyAcknowledged pre-checks).
                            let persist = pending
                                .oldest_pending_block()
                                .map_or(last_seen, |b| last_seen.min(b.saturating_sub(1)));
                            if let Err(err) = cp.set(&checkpoint_key, persist) {
                                warn!(chain_key, %err, "failed to persist ack checkpoint");
                            }
                        }
                    }
                    Err(err) => {
                        rate_limited = crate::pacing::error_looks_rate_limited(&format!("{err:#}"));
                        warn!(chain_key, %err, "ack discovery iteration failed; will retry");
                    }
                }

                process_pending(
                    chain_key,
                    &ack,
                    &mode,
                    &mut pending_outbox,
                    &client,
                    &source_provider,
                    submitter_address,
                    &broadcast_locks,
                    &metrics,
                    &mut pending,
                    &mut done,
                ).await;

                // Publish the queue depth every tick, not only when there is work. This is the
                // settlement path's liveness signal: the per-outcome counters say nothing while a
                // tx is being re-deferred (a failing proof fetch defers rather than resolves), and
                // they say nothing at all on a route with no settlement work — so an idle worker
                // and a dead one produced identical metrics. A depth that never returns to zero is
                // the shape of the two-day outage that hid behind a WARN.
                metrics.set_settlement_queue_depth(chain_key, pending.len() as i64);

                // Rate-limit pacing — see `crate::pacing`: a rate-limited failure arms a deferral
                // window (checked at tick start); clean iterations decay and are never slowed.
                pacer.after(rate_limited);
                if rate_limited {
                    if let Some(window) = pacer.deferring() {
                        warn!(chain_key, defer_ms = window.as_millis() as u64,
                            "🧯 provider is rate limiting — deferring ack discovery");
                    }
                }
            }
        }
    }
}

/// Poll the destination Inbox for new `MessageDelivered` AND `MessagePending` events and enqueue
/// their tx hashes (see the module docs' "Relay-fee claiming" section for why `MessagePending`
/// matters here too).
///
/// Scans only up to `tip - confirmation_depth` so a destination reorg on the unsafe head cannot
/// enqueue an ack for a delivery that later disappears.
///
/// `outbox`, if known, is recorded in `pending_outbox` for every *newly* discovered tx (see that
/// field's doc in [`run`]); `None` just leaves that tx's pre-check failing open.
#[allow(clippy::too_many_arguments)]
async fn discover_delivered<P: Provider>(
    chain_key: u64,
    inbox: alloy::primitives::Address,
    confirmation_depth: u64,
    provider: &P,
    last_seen: &mut u64,
    pending: &mut PendingTxs,
    done: &BoundedSeen,
    outbox: Option<Address>,
    pending_outbox: &mut HashMap<B256, Address>,
) -> Result<()> {
    let tip = provider.get_block_number().await?;
    let confirmed = tip.saturating_sub(confirmation_depth);
    if confirmed <= *last_seen {
        return Ok(());
    }
    let from_block = *last_seen + 1;
    // Bounded chunk (see MAX_BLOCKS_PER_SCAN): never ask the RPC for more than it will serve.
    let to_block = confirmed.min(last_seen.saturating_add(MAX_BLOCKS_PER_SCAN));

    let filter = Filter::new()
        .address(inbox)
        .event_signature(vec![
            IInbox::MessageDelivered::SIGNATURE_HASH,
            IInbox::MessagePending::SIGNATURE_HASH,
        ])
        .from_block(from_block)
        .to_block(to_block);

    let logs = provider.get_logs(&filter).await.with_context(|| {
        format!(
            "eth_getLogs MessageDelivered/MessagePending from {from_block} to {to_block} failed"
        )
    })?;

    for log in logs {
        let Some(tx_hash) = log.transaction_hash else {
            warn!(chain_key, "delivery log without transaction_hash; skipping");
            continue;
        };
        let Some(block) = log.block_number else {
            warn!(
                chain_key,
                %tx_hash,
                "delivery log without block_number; skipping"
            );
            continue;
        };

        // The delivered/pending messageId feeds the canAck and relay-claimable pre-checks, so
        // bridge or already-settled traffic never costs a proof fetch. A tx may carry several
        // such logs (one call, several messages).
        let (event_name, message_id) = match decode_delivery_log(&log) {
            Ok(Some(decoded)) => decoded,
            Ok(None) => {
                // Filter should prevent this, but skip rather than mis-decode if it doesn't.
                continue;
            }
            Err(err) => {
                warn!(chain_key, %tx_hash, %err, "could not decode delivery log; skipping");
                continue;
            }
        };

        if done.contains(&tx_hash) {
            continue;
        }
        if pending.contains(&tx_hash) {
            pending.note_meta(&tx_hash, message_id);
            continue;
        }
        if let Some(evicted) = pending.insert(tx_hash, Instant::now(), block, vec![message_id]) {
            pending_outbox.remove(&evicted);
            warn!(
                chain_key,
                %evicted,
                "ack pending queue at capacity; giving up on oldest un-acknowledged delivery"
            );
        }
        if let Some(addr) = outbox {
            pending_outbox.insert(tx_hash, addr);
        }
        debug!(chain_key, %tx_hash, %message_id, event_name, "🧾 observed delivery event; queued for settlement");
    }

    *last_seen = to_block;
    Ok(())
}

/// Classify and decode one destination log by topic0: `Ok(Some((name, messageId)))` for a
/// recognized `MessageDelivered`/`MessagePending` log, `Ok(None)` for anything else, `Err` if the
/// topic0 matched but the log body failed to decode. Split out from [`discover_delivered`] so
/// this dispatch is unit-testable without a live provider.
fn decode_delivery_log(
    log: &alloy::rpc::types::Log,
) -> Result<Option<(&'static str, B256)>, alloy::sol_types::Error> {
    match log.topics().first().copied() {
        Some(sig) if sig == IInbox::MessageDelivered::SIGNATURE_HASH => {
            IInbox::MessageDelivered::decode_log(&log.inner)
                .map(|decoded| Some(("MessageDelivered", decoded.data.messageId)))
        }
        Some(sig) if sig == IInbox::MessagePending::SIGNATURE_HASH => {
            IInbox::MessagePending::decode_log(&log.inner)
                .map(|decoded| Some(("MessagePending", decoded.data.messageId)))
        }
        _ => Ok(None),
    }
}

/// Try to fetch a proof and submit an acknowledgment for every pending destination tx that is due
/// for an attempt. Successful (or terminally-reverting) submissions move to `done`; not-yet-ready
/// proofs are re-polled per the route's [`crate::pending::NotReadyPolicy`] (flat cadence inside
/// the window, slow backoff past it, `MAX_ACK_AGE` give-up); transient failures back off
/// exponentially and escalate the log after [`MAX_ACK_TRANSIENT_ATTEMPTS`].
#[allow(clippy::too_many_arguments)]
async fn process_pending<P: Provider>(
    chain_key: u64,
    ack: &AckConfig,
    mode: &SettlementMode,
    pending_outbox: &mut HashMap<B256, Address>,
    client: &ProofGenClient,
    source_provider: &P,
    submitter_address: alloy::primitives::Address,
    broadcast_locks: &Arc<crate::broadcast::BroadcastLocks>,
    metrics: &Metrics,
    pending: &mut PendingTxs,
    done: &mut BoundedSeen,
) {
    // Retry oldest-first, a bounded batch per tick, so a large backlog cannot make one tick run
    // unboundedly long (or starve `discover_delivered` / shutdown).
    let now = Instant::now();
    let batch = pending.ready(MAX_ACKS_PER_TICK, now);
    if batch.is_empty() {
        return;
    }

    // Fetch proofs + submit with bounded concurrency rather than strictly serially: each attempt
    // is independent and dominated by network latency. Mutations to `pending`/`done` are applied
    // afterwards, on this task, so no shared-state synchronization is needed.
    let results: Vec<(B256, Vec<B256>, Result<AckOutcome>)> = futures::stream::iter(batch)
        .map(|(tx_hash, message_ids)| {
            // Tagged at discovery time, not whatever the resolver reports now — see `pending_outbox`.
            let outbox = pending_outbox.get(&tx_hash).copied();
            async move {
                let outcome = acknowledge_tx(
                    chain_key,
                    ack,
                    mode,
                    outbox,
                    &message_ids,
                    client,
                    source_provider,
                    submitter_address,
                    broadcast_locks,
                    metrics,
                    tx_hash,
                )
                .await;
                (tx_hash, message_ids, outcome)
            }
        })
        .buffer_unordered(MAX_ACK_CONCURRENCY)
        .collect()
        .await;

    let not_ready_policy = ack.not_ready_policy();
    let now = Instant::now();
    for (tx_hash, message_ids, outcome) in results {
        match outcome {
            Ok(AckOutcome::Acknowledged) => {
                info!(chain_key, %tx_hash, "✅ delivery settled on source chain");
                pending.remove(&tx_hash);
                pending_outbox.remove(&tx_hash);
                done.insert(tx_hash);
            }
            Ok(AckOutcome::Terminal(reason)) => {
                info!(chain_key, %tx_hash, %reason, "ack skipped (terminal); will not retry");
                pending.remove(&tx_hash);
                pending_outbox.remove(&tx_hash);
                done.insert(tx_hash);
            }
            Ok(AckOutcome::NotReady(reason)) => {
                // Normal early state (destination finality + attestation take minutes) — re-poll
                // without burning the transient budget, but don't wait forever on a block that
                // never attests. INFO, not WARN: nothing is wrong yet, and the operator reading
                // the latency of an ack needs to see how long it has been waiting and on what.
                let waited = pending.age(&tx_hash, now).unwrap_or_default();
                if waited > MAX_ACK_AGE {
                    warn!(
                        chain_key,
                        %tx_hash,
                        %reason,
                        "proof never became ready within {MAX_ACK_AGE:?}; giving up on this ack"
                    );
                    pending.remove(&tx_hash);
                    pending_outbox.remove(&tx_hash);
                    done.insert(tx_hash);
                } else {
                    let retry_in = not_ready_policy.next_delay(waited);
                    let past_window = waited >= not_ready_policy.poll_window;
                    info!(
                        chain_key,
                        %tx_hash,
                        message_ids = ?message_ids,
                        %reason,
                        waited_secs = waited.as_secs(),
                        retry_in_secs = retry_in.as_secs(),
                        past_poll_window = past_window,
                        "⏳ proof not ready yet (destination block not attested / proof-gen catching \
                         up); polling"
                    );
                    pending.defer(&tx_hash, now + retry_in);
                }
            }
            Err(err) => {
                let attempts = pending.record_transient_failure(&tx_hash, now);
                // Do NOT drop after a fixed budget. The old give-up removed the tx and marked it
                // `done`, so a multi-hour proof-gen / Creditcoin-RPC outage (proof-gen infra errors
                // are `Err`, not `NotReady`) silently and *permanently* lost every ack discovered
                // before it — unrecoverable even across restarts, because the discovery cursor
                // already advanced past the tx and the ~2.7h exhaustion time exceeds the scan
                // lookback window (C1r/C2). Keep retrying at the capped backoff instead
                // (TRANSIENT_BACKOFF_MAX = 10min): re-submission is idempotent on-chain
                // (AlreadyAcknowledged), and the queue stays memory-bounded by its cap. Escalate the
                // log past the old budget so a genuinely stuck ack is alertable.
                if attempts >= MAX_ACK_TRANSIENT_ATTEMPTS {
                    warn!(
                        chain_key,
                        %tx_hash,
                        attempts,
                        %err,
                        "ack still failing after {MAX_ACK_TRANSIENT_ATTEMPTS}+ transient attempts; \
                         continuing to retry at capped backoff (operator action likely required — \
                         check the ack signer balance, proof-gen, and the Creditcoin RPC)"
                    );
                } else {
                    warn!(
                        chain_key,
                        %tx_hash,
                        attempts,
                        %err,
                        "ack attempt failed transiently; will retry with backoff"
                    );
                }
            }
        }
    }
}

/// What this worker submits once a delivery proof is ready — chosen per route in [`run`].
#[derive(Clone, Copy, Debug)]
enum SettlementMode {
    /// No RelayerContract on the route: prove delivery to the `AcknowledgmentValidator` only
    /// (`submitAcknowledgment`, one call per tx — the validator acks every `MessageDelivered` log
    /// under try/catch). The validator address comes from `ack.validator_address`.
    Ack,
    /// The route has a `RelayerContract` (fee ledger): submit BOTH settlements from one proof —
    /// `submitAcknowledgment` (which also earns the message's user-set ackFee, an open bounty paid
    /// to the first submitter) and `claimDelivery` per messageId (relay fee + tip, always paid to
    /// the proven relayer). Since usc-contracts #23 the claim does NOT acknowledge, so skipping
    /// either call would leave messages unacknowledged or fees unclaimed. `chain_key` is passed to
    /// `claimDelivery` as `bytes32(uint256(chainKey))`.
    AckAndClaim {
        relayer_contract: Address,
        chain_key: B256,
    },
}

enum AckOutcome {
    /// Proof verified and the settlement call (`submitAcknowledgment` / `claimDelivery`) succeeded
    /// or was already terminal for every message — either way the tx is resolved.
    Acknowledged,
    /// Proof-gen cannot serve the proof yet (block not attested / its chain view lagging — see
    /// [`crate::proofgen`]); re-poll per the route's [`crate::pending::NotReadyPolicy`].
    NotReady(ProofNotReady),
    /// A permanent condition (e.g. on-chain revert: already acknowledged / does not require ack).
    Terminal(String),
}

/// Result of one confirmed-or-terminal on-chain submission; transient failures are `Err` (retryable).
enum SubmitOutcome {
    /// Mined successfully. Fields are the on-chain gas cost, recorded via Display (`%`) because
    /// `tracing` has no native u128 value impl.
    Confirmed {
        gas_used: u128,
        effective_gas_price: u128,
        gas_cost_wei: u128,
        tx_hash: B256,
    },
    /// A permanent on-chain condition (revert: already settled / does not require ack / reverted).
    Terminal(String),
}

/// Await a broadcast result and classify it, shared by both submit paths so the receipt-wait, revert
/// classification, and gas accounting cannot drift between ack and claim. `Err` is a transient
/// failure the caller should retry; `Ok(Terminal)` is permanent. `call` names the call for logs.
async fn classify_submit(
    pending_tx: Result<PendingTransactionBuilder<Ethereum>, alloy::contract::Error>,
    call: &str,
) -> Result<SubmitOutcome> {
    match pending_tx {
        // `crate::receipt::await_receipt` instead of `builder.get_receipt()`: the latter runs on
        // alloy's block-decoding heartbeat, which wedges against Frontier's mixHash-less blocks
        // (see the `receipt` module docs).
        Ok(builder) => {
            match tokio::time::timeout(RECEIPT_TIMEOUT, crate::receipt::await_receipt(&builder))
                .await
            {
                Err(_elapsed) => Err(anyhow!(
                    "no receipt within {RECEIPT_TIMEOUT:?} ({call} tx possibly stuck)"
                )),
                Ok(Ok(receipt)) if receipt.status() => {
                    let gas_used = u128::from(receipt.gas_used);
                    let effective_gas_price = receipt.effective_gas_price;
                    Ok(SubmitOutcome::Confirmed {
                        gas_used,
                        effective_gas_price,
                        gas_cost_wei: gas_used.saturating_mul(effective_gas_price),
                        tx_hash: receipt.transaction_hash,
                    })
                }
                Ok(Ok(_)) => Ok(SubmitOutcome::Terminal("tx mined but reverted".into())),
                Ok(Err(err)) => Err(anyhow!("receipt fetch failed: {err}")),
            }
        }
        Err(err) if is_terminal_revert(&err) => Ok(SubmitOutcome::Terminal(describe_revert(&err))),
        Err(err) => Err(anyhow!("{call} send failed: {err}")),
    }
}

/// MessageIds in `ids` whose relay fee is still claimable: funded through the RelayerContract
/// ledger (`payer != 0`) and not yet settled. Empty means nothing to claim for this tx. Traffic
/// funded outside the relayer (e.g. bridge messages) reports `payer == 0` and is skipped.
async fn relay_claimable_ids<P: Provider>(
    provider: &P,
    relayer_contract: Address,
    ids: &[B256],
) -> Result<Vec<B256>> {
    let ledger = crate::abi::IRelayerContract::new(relayer_contract, provider);
    let mut claimable = Vec::new();
    for id in ids {
        let info = ledger
            .getMessageInfo(*id)
            .call()
            .await
            .context("IRelayerContract.getMessageInfo call failed")?;
        if info.payer != Address::ZERO && !info.relaySettled {
            claimable.push(*id);
        }
    }
    Ok(claimable)
}

/// Fetch the delivery proof for `tx_hash` and submit it to the source `AcknowledgmentValidator`.
///
/// Before any proof is fetched, the delivered messageIds are checked against the source Outbox:
/// when none requires an acknowledgment (bridge traffic publishes `canAck = false`) or all
/// are already acknowledged, the tx is terminal without costing a proof-gen round-trip or a
/// guaranteed-revert gas estimate.
#[allow(clippy::too_many_arguments)]
async fn acknowledge_tx<P: Provider>(
    chain_key: u64,
    ack: &AckConfig,
    mode: &SettlementMode,
    outbox: Option<alloy::primitives::Address>,
    message_ids: &[B256],
    client: &ProofGenClient,
    source_provider: &P,
    submitter_address: alloy::primitives::Address,
    broadcast_locks: &Arc<crate::broadcast::BroadcastLocks>,
    metrics: &Metrics,
    tx_hash: B256,
) -> Result<AckOutcome> {
    // Pre-checks: skip the proof fetch entirely when nothing is left to do. Both checks fail
    // open — a view-call error falls through to the proof path, where the contracts enforce the
    // same rules on-chain; this is purely a cost-saving shortcut. The two settlements are
    // independent (usc-contracts #23: `claimDelivery` no longer acknowledges), so the tx is only
    // terminal when NEITHER an ack nor a claim remains outstanding.
    let needs_ack: bool = if let Some(outbox_addr) = outbox {
        if message_ids.is_empty() {
            true // discovery always records ids; treat the impossible case fail-open
        } else {
            match any_requires_ack(source_provider, outbox_addr, message_ids).await {
                Ok(needed) => needed,
                Err(err) => {
                    warn!(chain_key, %tx_hash, %err, "canAck pre-check failed; assuming ack needed");
                    true
                }
            }
        }
    } else {
        true // no Outbox view configured — let the validator decide on-chain
    };

    let claim_ids: Vec<B256> = match mode {
        SettlementMode::Ack => Vec::new(),
        SettlementMode::AckAndClaim {
            relayer_contract, ..
        } => match relay_claimable_ids(source_provider, *relayer_contract, message_ids).await {
            Ok(ids) => ids,
            Err(err) => {
                warn!(chain_key, %tx_hash, %err, "relay-claimable pre-check failed; attempting all ids");
                message_ids.to_vec()
            }
        },
    };

    if !needs_ack && claim_ids.is_empty() {
        // Count the no-op rather than returning silently. Without this, a route whose messages
        // legitimately need no settlement is metrically identical to one whose settlement worker
        // has stopped: both leave the outcome families empty, and an unincremented Prometheus
        // family emits nothing at all.
        metrics.inc_ack_submission(chain_key, SettlementOutcome::NothingToSettle);
        if matches!(mode, SettlementMode::AckAndClaim { .. }) {
            metrics.inc_claim_submission(chain_key, SettlementOutcome::NothingToSettle);
        }
        return Ok(AckOutcome::Terminal(
            "nothing left to settle (no message requires an ack, no unsettled relay fee)".into(),
        ));
    }

    let proof = match client.proof_by_tx(chain_key, tx_hash).await {
        Ok(ProofFetch::Ready(p)) => {
            metrics.inc_ack_proof_fetch(chain_key, ProofFetchOutcome::Ready);
            p
        }
        Ok(ProofFetch::NotReady(reason)) => {
            // Counted apart from `Error`: a stream of these with matching `Ready` growth is
            // attestation latency, not a fault, and must not look like the outage shape below.
            metrics.inc_ack_proof_fetch(chain_key, ProofFetchOutcome::NotReady);
            return Ok(AckOutcome::NotReady(reason));
        }
        Err(err) => {
            metrics.inc_ack_proof_fetch(chain_key, ProofFetchOutcome::Error);
            // Whichever settlement(s) this poll needed failed to even get a proof — this is
            // exactly the shape that hid a two-day settlement outage behind a WARN nobody read
            // (proof-gen's archiver silently unable to build continuity proofs): delivery kept
            // working while every ack/claim attempt died right here.
            if needs_ack {
                metrics.inc_ack_submission(chain_key, SettlementOutcome::Failed);
            }
            if !claim_ids.is_empty() {
                metrics.inc_claim_submission(chain_key, SettlementOutcome::Failed);
            }
            return Err(err);
        }
    };

    let encoded_tx = proof.encoded_transaction()?;

    // Mirror the on-chain cap: an oversized prover txBytes payload is rejected on-chain
    // (EncodedTransactionTooLarge) — the bytes now travel inside `inclusionProof.data`, but the cap
    // is enforced on the same decoded length — so skip it before spending gas on a guaranteed
    // revert. Permanent for this proof, hence Terminal (no retry).
    if encoded_tx.len() > MAX_ENCODED_TRANSACTION_BYTES {
        return Ok(AckOutcome::Terminal(format!(
            "encodedTransaction {} bytes exceeds on-chain max {} bytes",
            encoded_tx.len(),
            MAX_ENCODED_TRANSACTION_BYTES
        )));
    }

    let height = proof.header_number;

    // Serialized on the submitter address so this tick's concurrent sends (and any other worker
    // sharing this Creditcoin key) cannot read the same chain nonce. The guard (inside `broadcast`)
    // covers the broadcast only — the receipt is awaited in `classify_submit`, outside it, so one
    // confirmation does not stall the batch. A stall consumes no nonce, so it is reported as
    // transient and retried (idempotently: a duplicate lands as `MessageAlreadyAcknowledged` /
    // `RelayAlreadySettled`).
    //
    // Ack FIRST, claim second: the ack fee is an open bounty paid to the first successful
    // submitter (front-runnable by design), while the relay-fee claim always pays the proven
    // relayer no matter who or when submits — so the time-sensitive settlement goes first.
    // A transient failure anywhere aborts the whole tx for retry; both settlements are idempotent
    // on-chain, and the pre-checks drop already-settled work on the retry, so retries converge.
    if needs_ack {
        let (inclusion, continuity) = proof.to_inclusion_and_continuity()?;
        let validator =
            crate::abi::IAcknowledgmentValidator::new(ack.validator_address, source_provider);
        let pending_tx = match broadcast_locks
            .broadcast(
                submitter_address,
                SEND_TIMEOUT,
                validator
                    .submitAcknowledgment(height, inclusion, continuity)
                    .send(),
            )
            .await
        {
            Ok(res) => res,
            Err(stalled) => {
                metrics.inc_ack_submission(chain_key, SettlementOutcome::Failed);
                return Err(anyhow!("submitAcknowledgment {stalled}"));
            }
        };
        match classify_submit(pending_tx, "submitAcknowledgment").await {
            Ok(SubmitOutcome::Confirmed {
                gas_used,
                effective_gas_price,
                gas_cost_wei,
                tx_hash: settle_tx,
            }) => {
                metrics.inc_ack_submission(chain_key, SettlementOutcome::Confirmed);
                info!(
                    chain_key,
                    %tx_hash,
                    ack_tx_hash = %settle_tx,
                    gas_used = %gas_used,
                    effective_gas_price_wei = %effective_gas_price,
                    gas_cost_wei = %gas_cost_wei,
                    "submitAcknowledgment confirmed (ack fee, if any, paid to this submitter)",
                );
            }
            // Terminal here (e.g. NoMessageDeliveredLogs because another submitter front-ran the
            // bounty and every log is now already-acked) must not block the relay-fee claim below —
            // the claim pays the proven relayer regardless of who acknowledged.
            Ok(SubmitOutcome::Terminal(reason)) => {
                metrics.inc_ack_submission(chain_key, SettlementOutcome::Terminal);
                info!(chain_key, %tx_hash, %reason, "submitAcknowledgment terminal; continuing to claim");
            }
            Err(err) => {
                metrics.inc_ack_submission(chain_key, SettlementOutcome::Failed);
                return Err(err);
            }
        }
    }

    // One claimDelivery per messageId (the ledger settles a single message per call, unlike the
    // validator which acks every log in one tx). A tx usually carries one delivery, so the proof
    // structs are rebuilt per id rather than cloned.
    if let SettlementMode::AckAndClaim {
        relayer_contract,
        chain_key: ck,
    } = mode
    {
        let ledger = crate::abi::IRelayerContract::new(*relayer_contract, source_provider);
        for id in &claim_ids {
            let (inclusion, continuity) = proof.to_inclusion_and_continuity()?;
            let pending_tx = match broadcast_locks
                .broadcast(
                    submitter_address,
                    SEND_TIMEOUT,
                    ledger
                        .claimDelivery(*id, *ck, height, inclusion, continuity)
                        .send(),
                )
                .await
            {
                Ok(res) => res,
                Err(stalled) => {
                    metrics.inc_claim_submission(chain_key, SettlementOutcome::Failed);
                    return Err(anyhow!("claimDelivery {stalled}"));
                }
            };
            match classify_submit(pending_tx, "claimDelivery").await {
                Ok(SubmitOutcome::Confirmed {
                    gas_used,
                    effective_gas_price,
                    gas_cost_wei,
                    tx_hash: settle_tx,
                }) => {
                    metrics.inc_claim_submission(chain_key, SettlementOutcome::Confirmed);
                    info!(
                        chain_key,
                        %tx_hash,
                        message_id = %id,
                        claim_tx_hash = %settle_tx,
                        gas_used = %gas_used,
                        effective_gas_price_wei = %effective_gas_price,
                        gas_cost_wei = %gas_cost_wei,
                        "claimDelivery confirmed (relay fee settled to proven relayer)",
                    );
                }
                Ok(SubmitOutcome::Terminal(reason)) => {
                    metrics.inc_claim_submission(chain_key, SettlementOutcome::Terminal);
                    info!(
                        chain_key,
                        %tx_hash,
                        message_id = %id,
                        %reason,
                        "claimDelivery skipped for message (terminal)",
                    );
                }
                Err(err) => {
                    metrics.inc_claim_submission(chain_key, SettlementOutcome::Failed);
                    return Err(err);
                }
            }
        }
    }

    Ok(AckOutcome::Acknowledged)
}

/// Whether any of `ids` still needs an acknowledgment on the source Outbox: published with
/// `canAck = true`, known to the outbox (`emitter != 0`), and not yet acknowledged.
async fn any_requires_ack<P: Provider>(
    provider: &P,
    outbox: alloy::primitives::Address,
    ids: &[B256],
) -> Result<bool> {
    let outbox = IOutbox::new(outbox, provider);
    for id in ids {
        if !outbox
            .messageCanAck(*id)
            .call()
            .await
            .context("IOutbox.messageCanAck call failed")?
        {
            // `messageRequiresAck` is false for an unknown id (mapping default), so passing this
            // gate already implies the message exists — no separate existence check needed.
            continue;
        }
        if !outbox
            .isAcknowledged(*id)
            .call()
            .await
            .context("IOutbox.isAcknowledged call failed")?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Decode a known ack-path revert selector into its error name, for actionable Terminal logs
/// (Creditcoin's EVM RPC returns raw selector data with no decoded name). Selectors come from the
/// shared [`write_ability::abi`] `sol!` declarations, so they cannot drift from the contracts.
fn ack_revert_name(sel: [u8; 4]) -> Option<&'static str> {
    use crate::abi::{IAcknowledgmentValidator as V, IOutbox as O, IRelayerContract as RC};
    Some(match sel {
        s if s == O::MessageCannotBeAcknowledged::SELECTOR => "MessageCannotBeAcknowledged",
        s if s == O::MessageAlreadyAcknowledged::SELECTOR => "MessageAlreadyAcknowledged",
        s if s == O::MessageNotFound::SELECTOR => "MessageNotFound",
        s if s == V::ProofInvalid::SELECTOR => "ProofInvalid",
        s if s == V::NoMessageDeliveredLogs::SELECTOR => "NoMessageDeliveredLogs",
        s if s == RC::RelayAlreadySettled::SELECTOR => "RelayAlreadySettled",
        s if s == RC::UnknownOperation::SELECTOR => "UnknownOperation",
        _ => return None,
    })
}

/// Classify a submit error as a permanent on-chain revert (vs. a transient RPC failure). A contract
/// revert observed at send / gas-estimation time is deterministic, so it must be terminal — otherwise
/// the tx is retried forever (e.g. every bridge Release delivery, which reverts
/// `MessageCannotBeAcknowledged`). Matches revert phrasing across node dialects (see [`crate::revert`])
/// plus decoded error names as a fallback.
fn is_terminal_revert(err: &impl std::fmt::Display) -> bool {
    let s = err.to_string();
    // NativeTransferFailed is the one revert that is NOT deterministic for a given message: it
    // means a native send to a recipient failed, which clears when the recipient starts accepting
    // (or is drained via withdrawNative). The ABI docs promise it stays retryable, and the generic
    // is_revert() catch-all below would otherwise flip it terminal. Post-#23 contracts defer
    // failed pushes instead of reverting, so this is a belt-and-braces carve-out for older
    // deployments and the withdraw path rather than a live code path.
    if crate::revert::revert_selector(&s)
        .is_some_and(|sel| sel == crate::abi::IRelayerContract::NativeTransferFailed::SELECTOR)
        || s.contains("NativeTransferFailed")
    {
        return false;
    }
    // Any other revert observed at send/estimation time is deterministic for the proof + message
    // state at hand, so it must be terminal — otherwise e.g. every bridge Release delivery
    // (MessageCannotBeAcknowledged) retries forever. A mined-but-reverted settlement is terminal for
    // the same reason: the state that made it revert (already settled / already acked) does not
    // un-happen, and the pre-checks drop that id on the next pass anyway.
    if crate::revert::is_revert(&s) {
        return true;
    }
    // Decoded error-name fallback (nodes that surface the custom-error name without standard
    // revert phrasing). Both the current name (CannotBeAcknowledged) and its pre-#23 predecessor
    // (DoesNotRequireAck) are matched: name-decoding nodes fronting an old deployment still emit
    // the retired string, and matching one extra name costs nothing.
    s.contains("AlreadyAcknowledged")
        || s.contains("CannotBeAcknowledged")
        || s.contains("DoesNotRequireAck")
        || s.contains("MessageNotFound")
        || s.contains("ProofInvalid")
        || s.contains("NoMessageDeliveredLogs")
        || s.contains("RelayAlreadySettled")
        || s.contains("UnknownOperation")
}

/// Prefix a terminal revert with the decoded error name when the selector is recognized, so the
/// `ack skipped (terminal)` log tells the operator *why* without a manual selector lookup.
fn describe_revert(err: &impl std::fmt::Display) -> String {
    let s = err.to_string();
    match crate::revert::revert_selector(&s).and_then(ack_revert_name) {
        Some(name) => format!("{name}: {s}"),
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_revert_classification() {
        // Decoded-name form (nodes that surface the custom-error name).
        assert!(is_terminal_revert(&"reverted: MessageAlreadyAcknowledged"));
        // Both names of the no-ack-required error: the current one and its pre-#23 predecessor
        // (bugbot: the rename fixed the selector map but left this fallback matching only the
        // retired string — a name-decoding node without standard revert phrasing looped forever).
        assert!(is_terminal_revert(&"reverted: MessageCannotBeAcknowledged"));
        assert!(is_terminal_revert(&"reverted: MessageDoesNotRequireAck"));
        assert!(is_terminal_revert(&"execution reverted"));

        // NativeTransferFailed is the documented retryable exception: it clears when the recipient
        // starts accepting native, so it must NOT be terminal — in either the decoded-name form or
        // the raw-selector form the Creditcoin RPC emits.
        assert!(!is_terminal_revert(&"reverted: NativeTransferFailed"));
        let selector_hex = crate::abi::IRelayerContract::NativeTransferFailed::SELECTOR
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert!(!is_terminal_revert(&format!(
            "claimDelivery send failed: VM Exception while processing transaction: revert, data: \
             \"0x{selector_hex}0000000000000000000000000000000000000000000000000000000000000000\""
        )));

        // Creditcoin EVM RPC form: raw selector data, no decoded name — this is what was slipping
        // through and retrying forever on every bridge Release delivery. (Shape captured live;
        // selector updated for the post-#23 rename to MessageCannotBeAcknowledged.)
        assert!(is_terminal_revert(
            &"submitAcknowledgment send failed: server returned an error response: error code \
              -32603: VM Exception while processing transaction: revert, data: \
              \"0x52818d8ec8e0b2db4217508f44fb2d148bd9fab3c94e876a56a3fdbcf71f17570ecbe54c\""
        ));
        // Unknown selector but a clear revert phrasing is still terminal.
        assert!(is_terminal_revert(
            &"VM Exception while processing transaction: revert, data: \"0xdeadbeef\""
        ));

        // Genuine transient infra failures stay retryable.
        assert!(!is_terminal_revert(
            &"error sending request: connection refused"
        ));
        assert!(!is_terminal_revert(
            &"server returned an error response: error code -32000: insufficient funds for gas"
        ));
    }

    #[test]
    fn describe_revert_decodes_known_selectors() {
        // The real-world Creditcoin node string shape for a bridge Release delivery: raw selector,
        // no name. The Terminal log should still name the error for the operator. (Selector updated
        // for the post-#23 rename to MessageCannotBeAcknowledged — caught by abi_surface.)
        let s = "VM Exception while processing transaction: revert, data: \
                 \"0x52818d8ec8e0b2db4217508f44fb2d148bd9fab3c94e876a56a3fdbcf71f17570ecbe54c\"";
        assert!(describe_revert(&s).starts_with("MessageCannotBeAcknowledged: "));
        // Unknown selector passes through unchanged.
        let unknown = "revert, data: \"0xdeadbeef\"";
        assert_eq!(describe_revert(&unknown), unknown);
        // Selector constants in the shared ABI must still hash to the on-wire values.
        assert_eq!(
            crate::abi::IOutbox::MessageCannotBeAcknowledged::SELECTOR,
            [0x52, 0x81, 0x8d, 0x8e]
        );
        assert_eq!(
            crate::abi::IOutbox::MessageAlreadyAcknowledged::SELECTOR,
            [0x33, 0x70, 0x4b, 0x28]
        );
        assert_eq!(
            crate::abi::IOutbox::MessageNotFound::SELECTOR,
            [0x5d, 0x80, 0x3c, 0xca]
        );
    }

    fn rpc_log(address: Address, data: alloy::primitives::LogData) -> alloy::rpc::types::Log {
        alloy::rpc::types::Log {
            inner: alloy::primitives::Log { address, data },
            ..Default::default()
        }
    }

    #[test]
    fn decode_delivery_log_dispatches_on_topic0() {
        let message_id = B256::from([7u8; 32]);
        let addr = Address::from([1u8; 20]);

        let delivered = IInbox::MessageDelivered {
            messageId: message_id,
            processor: addr,
            relayer: addr,
        };
        let (name, id) = decode_delivery_log(&rpc_log(addr, delivered.encode_log_data()))
            .expect("decodes")
            .expect("recognized");
        assert_eq!(name, "MessageDelivered");
        assert_eq!(id, message_id);

        let pending = IInbox::MessagePending {
            messageId: message_id,
            destinationContract: addr,
            relayer: addr,
        };
        let (name, id) = decode_delivery_log(&rpc_log(addr, pending.encode_log_data()))
            .expect("decodes")
            .expect("recognized");
        assert_eq!(name, "MessagePending");
        assert_eq!(id, message_id);
    }

    #[test]
    fn decode_delivery_log_ignores_unrelated_topic0() {
        // The discovery filter only requests these two topic0s, but an RPC is not trusted to
        // honor that — an unrelated event on the same Inbox (e.g. the ack validator's
        // Acknowledged, a completely different contract in practice but same shape of concern)
        // must be skipped, not mis-decoded as one of the two we expect.
        let unrelated = crate::abi::IAcknowledgmentValidator::Acknowledged {
            messageId: B256::from([9u8; 32]),
        };
        let log = rpc_log(Address::ZERO, unrelated.encode_log_data());
        assert!(decode_delivery_log(&log)
            .expect("no decode error")
            .is_none());
    }

    #[test]
    fn decode_delivery_log_surfaces_decode_errors_for_matching_topic0() {
        // Right topic0, but too few topics for the event's three indexed fields (messageId,
        // processor, relayer) — a malformed/truncated log must error, not silently drop the
        // relay-fee claim by falling through as "unrecognized".
        let malformed = alloy::primitives::LogData::new(
            vec![IInbox::MessageDelivered::SIGNATURE_HASH],
            Default::default(),
        )
        .expect("valid LogData");
        let log = rpc_log(Address::ZERO, malformed);
        assert!(decode_delivery_log(&log).is_err());
    }
}
