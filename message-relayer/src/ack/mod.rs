//! Off-chain acknowledgment submitter (research §05/§10).
//!
//! Trust-minimized acknowledgment is **proof-based, not vote-based**. For each route that opts in
//! (`route.ack = Some(..)`), this worker:
//!
//!  1. Watches the **destination** Inbox for `MessageReceived(bytes32 indexed messageId)` —
//!     evidence that a relay attempt reached the destination dApp (asc-contracts #54: this fires
//!     on every accepted delivery attempt, success or destination-failure alike — see below for
//!     why the watcher discovers on it in ADDITION to, not instead of, the success-only
//!     `MessageExecuted`).
//!  2. For the transaction that emitted it, fetches a native USC delivery proof from the proof-gen
//!     API (`GET {proof_gen_url}/api/v1/proof-by-tx/{chain_key}/{tx_hash}`): the prover `txBytes`
//!     plus the merkle-inclusion and continuity proofs.
//!  3. Submits that proof to the source-chain `AcknowledgmentValidator.submitAcknowledgment(..)`.
//!     The contract verifies the proof against the block-prover precompile, decodes the
//!     `MessageExecuted` logs, and calls `Outbox.acknowledgeMessage` for each — so the relayer
//!     never needs acknowledge authority; the proof is self-validating. `MessageExecuted` only
//!     fires on a successful destination call, so a proof built from a destination-failure-only
//!     tx correctly reverts `NoMessageExecutedLogs` here (handled the same way a
//!     `MessageQueued`/`MessageDeferred` tx already is — see below) without ever falsely
//!     acknowledging a retryable failure. Conversely, a message that failed at the destination and
//!     later succeeded via `retryFailedMessage`/`retryPendingMessage` emits `MessageExecuted`
//!     ALONE on that later tx — no `MessageReceived` — so the watcher discovers `MessageExecuted`
//!     directly too; without it, a retried-then-succeeded message's ack (and ack-fee bounty) would
//!     never be submitted, since the only tx that could ever prove `MessageExecuted` is the one no
//!     filter ever surfaced.
//!
//! ## Relay-fee claiming (`AckAndClaim` mode)
//!
//! When the route has a `RelayerContract` configured (`route.relayer_contract_address = Some(..)`),
//! this same watcher ALSO settles the relay fee: from the same delivery proof it calls
//! `RelayerContract.claimDelivery(messageId, ..)` per delivered message, which pays the relay fee
//! (+ any unexpired tip) to the relayer proven in the destination `MessageReceived` event — this
//! is *why* the watcher discovers on `MessageReceived` as well as `MessageExecuted`: relay-fee
//! settlement is for relay work done, not destination success, so a destination-failure retry
//! must still be discoverable for the claim even though it is not ack-eligible. `MessageExecuted`
//! from a retry has no `MessageReceived` on its own tx and offers no fee-claim proof of its own —
//! the fee was already claimable from the original `MessageReceived` tx, discovered separately.
//!
//! The discovery scan also watches `MessageQueued`/`MessageDeferred` (dApp callback reverted or
//! dispatcher queued it; message stored for `retryPendingMessage`): `EVMDeliveryDecoder` accepts a
//! proof over a `MessageQueued`/`MessageDeferred`-emitting tx as payable, but only from the
//! *original* `deliverMessage` tx — a later `retryPendingMessage` tx carries the wrong call
//! selector and the decoder rejects it. Without this, a message that ever goes pending strands its
//! relay fee forever: the originating tx is never enqueued, and a successful retry's tx is unusable
//! as a claim proof. Like a destination-failure-only tx (see above), a
//! `MessageQueued`/`MessageDeferred` tx has no `submitAcknowledgment` proof to offer —
//! `acknowledge_tx`'s existing terminal classification already handles that, skipping straight to
//! the claim.
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
//! contain several `MessageExecuted` logs and the validator acknowledges all of them in a single
//! call. A transaction whose proof is not available *yet* — HTTP 422 (`BlockNotReady`: block not
//! attested) or 404 (proof-gen's own view of the destination chain has not caught up with the tx)
//! from the proof-gen API — is re-polled on a flat, short cadence for a bounded window and only
//! then slides into the slow backoff; see [`crate::pending::NotReadyPolicy`] and
//! [`crate::proofgen`] for why a 404 is "not yet" rather than an error.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::network::{Ethereum, EthereumWallet};
use alloy::primitives::{Address, B256, U256};
use alloy::providers::{PendingTransactionBuilder, Provider};
use alloy::rpc::types::{BlockNumberOrTag, Filter};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolError, SolEvent};
use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::abi::IInbox;
use crate::checkpoint::CheckpointStore;
use crate::config::{AckConfig, ChainRoute};
use crate::pending::{BoundedSeen, PendingTxs};
use crate::prom::{Metrics, ProofFetchOutcome, SettlementOutcome};
use crate::proofgen::{ProofFetch, ProofGenClient, ProofNotReady};

mod routes;

/// Execution qualifies for acknowledgment; received/queued/deferred qualify only for fee claims.
/// Retain both when the same transaction emits multiple event kinds for a message.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DeliveryEvent {
    message_id: B256,
    executed: bool,
}

/// Poll cadence for the destination `MessageReceived` watcher and the pending-proof retry queue.
pub const ACK_POLL_INTERVAL_SECS: u64 = 6;

/// Maximum `encodedTransaction` size accepted on-chain by
/// `AcknowledgmentValidator.submitAcknowledgment`. Mirrors `MAX_ENCODED_TRANSACTION_BYTES` in
/// `usc-messaging/contracts/src/AcknowledgmentValidator.sol`; keep the two in sync. Proofs larger
/// than this are rejected on submission (`EncodedTransactionTooLarge`), so we skip them locally
/// instead of paying gas on a guaranteed revert.
pub const MAX_ENCODED_TRANSACTION_BYTES: usize = 500_000;

/// Hard cap on the unacknowledged-tx queue. Without it a prolonged proof-gen outage (or a delivery
/// whose block never attests) would grow `pending` without bound. At capacity discovery pauses
/// before advancing its cursor; pending work is never evicted.
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

/// Escalate prolonged proof unavailability without abandoning settlement or releasing the
/// checkpoint holdback. The not-ready policy caps retries after its fast-poll window.
const ACK_OVERDUE_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// Escalate the log after this many transient submit failures. Retries continue at capped backoff.
const MAX_ACK_TRANSIENT_ATTEMPTS: u32 = 20;

/// Spawn the acknowledgment submitter for one route. Returns immediately when the route has no
/// `ack` config; otherwise loops until `cancel` fires or an unrecoverable error occurs.
/// `scan_lookback_blocks` rewinds the persisted cursor on startup so acks that were pending when
/// the process died are re-discovered (see [`crate::config::DEFAULT_SCAN_LOOKBACK_BLOCKS`]).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    route: ChainRoute,
    creditcoin_eth_rpc_url: String,
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

    // Read-only provider on the destination chain (where MessageReceived is emitted). Held in a
    // rebuilding slot: after `rpc::REBUILD_AFTER_FAILURES` failed scans it is re-dialed, so a dead
    // transport heals in-process rather than through a liveness restart (see `crate::health`).
    let mut dest_rpc = crate::rpc::Reconnecting::new(
        format!("ack:{chain_key} destination"),
        route.destination_rpc_url.clone(),
    );
    let dest_provider = dest_rpc
        .connect()
        .await
        .with_context(|| {
            format!(
                "chain_key {chain_key}: ack submitter failed to connect to destination RPC at {}",
                route.destination_rpc_url
            )
        })?
        .clone();

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

    // Routing history is independent of the delivery cursor and includes retired Outboxes.
    // In particular, ack.start_block must not skip support events preceding a late retry.
    let history_path = checkpoint.as_ref().map(|cp| {
        cp.path().with_extension(format!(
            "ack-routes-{chain_key}-{}.json",
            route.inbox_address
        ))
    });
    let mut route_history =
        routes::RouteHistory::load(history_path, route.inbox_address, route.creditcoin_chain_id)?;
    if let Err(err) = route_history.seed(&dest_provider).await {
        warn!(chain_key, %err, "current Outbox hints unavailable; recovering complete support history");
    }
    if let Err(err) = route_history
        .seed_validator(&source_provider, ack.validator_address)
        .await
    {
        debug!(chain_key, %err, "configured validator's Outbox hint unavailable; using Inbox history");
    }

    match &mode {
        SettlementMode::Ack => info!(
            chain_key,
            inbox = %route.inbox_address,
            validator_hint = %ack.validator_address,
            submitter = %submitter_address,
            proof_gen_url = %ack.proof_gen_url,
            "🧾 acknowledgment submitter online (ack mode)"
        ),
        SettlementMode::AckAndClaim {
            relayer_contract, ..
        } => info!(
            chain_key,
            inbox = %route.inbox_address,
            validator_hint = %ack.validator_address,
            relayer_contract = %relayer_contract,
            submitter = %submitter_address,
            proof_gen_url = %ack.proof_gen_url,
            "💰 settlement submitter online (ack + relay-fee claim; independent since usc-contracts #23)"
        ),
    }

    // Resume from the persisted cursor so MessageReceived events emitted while we were down are
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
    let mut tick = tokio::time::interval(Duration::from_secs(crate::config::poll_secs_override(
        "RELAYER_ACK_POLL_SECS",
        ACK_POLL_INTERVAL_SECS,
    )));
    let mut pacer = crate::pacing::RateLimitPacer::default();
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!(chain_key, "🛑 acknowledgment submitter exiting on cancel");
                return Ok(());
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
                let scan = match dest_rpc.connect().await {
                    Ok(provider) => {
                        let provider = provider.clone();
                        if let Err(err) = route_history.refresh(&provider, ack.confirmation_depth).await {
                            warn!(chain_key, %err, "settlement support history incomplete; unknown routes remain retryable");
                        }
                        discover_delivered(
                            chain_key,
                            route.inbox_address,
                            ack.confirmation_depth,
                            &provider,
                            &mut last_seen,
                            &mut pending,
                            &done,
                        ).await
                    }
                    Err(err) => Err(err),
                };
                match scan {
                    Ok(()) => {
                        // Successful destination scan = loop progress (C2r).
                        dest_rpc.note_ok();
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
                                metrics.inc_checkpoint_write_failure(chain_key);
                                warn!(chain_key, %err, "failed to persist ack checkpoint");
                            }
                        }
                    }
                    Err(err) => {
                        rate_limited = crate::pacing::error_looks_rate_limited(&format!("{err:#}"));
                        // The loop is turning, the upstream is not: degraded, not stale (see
                        // `crate::health`), and the provider is re-dialed after a failure streak.
                        health.error(&health_key);
                        dest_rpc.note_err();
                        warn!(chain_key, %err, "ack discovery iteration failed; will retry");
                    }
                }

                process_pending(
                    chain_key,
                    &ack,
                    &mode,
                    route.creditcoin_chain_id,
                    route_history.outboxes(),
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

/// Poll the destination Inbox for new `MessageReceived`, `MessageQueued`, `MessageDeferred` AND
/// `MessageExecuted` events and enqueue their tx hashes (see the module docs' "Relay-fee claiming"
/// section for why `MessageQueued`/`MessageDeferred`, and a destination-failure-only
/// `MessageReceived`, still matter here even though neither is ack-eligible by itself — and why
/// `MessageExecuted` is watched directly, not just discovered as a side effect of `MessageReceived`).
///
/// Scans only up to `tip - confirmation_depth` so a destination reorg on the unsafe head cannot
/// enqueue an ack for a delivery that later disappears.
///
/// Publication routes are resolved independently from historical Inbox authorization.
#[allow(clippy::too_many_arguments)]
async fn discover_delivered<P: Provider>(
    chain_key: u64,
    inbox: alloy::primitives::Address,
    confirmation_depth: u64,
    provider: &P,
    last_seen: &mut u64,
    pending: &mut PendingTxs<DeliveryEvent>,
    done: &BoundedSeen,
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
            IInbox::MessageReceived::SIGNATURE_HASH,
            IInbox::MessageQueued::SIGNATURE_HASH,
            IInbox::MessageDeferred::SIGNATURE_HASH,
            IInbox::MessageExecuted::SIGNATURE_HASH,
        ])
        .from_block(from_block)
        .to_block(to_block);

    let logs = provider.get_logs(&filter).await.with_context(|| {
        format!(
            "eth_getLogs MessageReceived/MessageQueued/MessageDeferred/MessageExecuted from \
             {from_block} to {to_block} failed"
        )
    })?;

    // Decode the whole range before admitting any transaction. Otherwise a malformed or
    // incomplete Executed companion could let its Received-only half finish as a fee-only tx.
    let mut decoded = Vec::with_capacity(logs.len());
    for log in logs {
        if log.address() != inbox || log.removed {
            anyhow::bail!("delivery RPC returned a removed log or a different Inbox");
        }
        let tx_hash = log
            .transaction_hash
            .context("delivery log without transaction hash")?;
        let block = log
            .block_number
            .context("delivery log without block number")?;
        if block < from_block || block > to_block {
            anyhow::bail!("delivery RPC returned a log outside the requested range");
        }
        let Some((event_name, message_id)) =
            decode_delivery_log(&log).context("decoding delivery log")?
        else {
            continue;
        };
        decoded.push((tx_hash, block, event_name, message_id));
    }
    let mut first_unadmitted_block: Option<u64> = None;
    for (tx_hash, block, event_name, message_id) in decoded {
        let event = DeliveryEvent {
            message_id,
            executed: event_name == "MessageExecuted",
        };
        if done.contains(&tx_hash) {
            continue;
        }
        if pending.contains(&tx_hash) {
            pending.note_meta(&tx_hash, event);
            continue;
        }
        if pending.is_full() {
            // Keep the cursor before the earliest unadmitted block, while existing pending
            // work retains its checkpoint barrier. Advancing the fully admitted prefix avoids
            // replaying it forever after the bounded completed-tx cache rolls over.
            debug!(
                chain_key,
                "ack pending queue full; pausing discovery until settlement frees capacity"
            );
            // Still consume metadata for already-admitted transactions later in this response.
            // RPC log ordering must not let a Received event hide its Executed companion.
            first_unadmitted_block =
                Some(first_unadmitted_block.map_or(block, |old| old.min(block)));
            continue;
        }
        pending.insert(tx_hash, Instant::now(), block, vec![event]);
        debug!(chain_key, %tx_hash, %message_id, event_name, "🧾 observed delivery event; queued for settlement");
    }

    *last_seen = first_unadmitted_block.map_or(to_block, |block| block.saturating_sub(1));
    Ok(())
}

/// Classify and decode one destination log by topic0: `Ok(Some((name, messageId)))` for a
/// recognized `MessageReceived`/`MessageQueued`/`MessageDeferred`/`MessageExecuted` log,
/// `Ok(None)` for anything else, `Err` if the topic0 matched but the log body failed to decode.
/// Split out from [`discover_delivered`] so this dispatch is unit-testable without a live provider.
fn decode_delivery_log(
    log: &alloy::rpc::types::Log,
) -> Result<Option<(&'static str, B256)>, alloy::sol_types::Error> {
    match log.topics().first().copied() {
        Some(sig) if sig == IInbox::MessageReceived::SIGNATURE_HASH => {
            IInbox::MessageReceived::decode_log(&log.inner)
                .map(|decoded| Some(("MessageReceived", decoded.data.messageId)))
        }
        Some(sig) if sig == IInbox::MessageQueued::SIGNATURE_HASH => {
            IInbox::MessageQueued::decode_log(&log.inner)
                .map(|decoded| Some(("MessageQueued", decoded.data.messageId)))
        }
        Some(sig) if sig == IInbox::MessageDeferred::SIGNATURE_HASH => {
            IInbox::MessageDeferred::decode_log(&log.inner)
                .map(|decoded| Some(("MessageDeferred", decoded.data.messageId)))
        }
        // #54: a successful retryFailedMessage/retryPendingMessage emits MessageExecuted ALONE —
        // no MessageReceived on that tx — so without watching this directly, a message that ever
        // went DestinationFailed (or pending) and later succeeded on retry would never be
        // discovered, and its ack (and ack fee) would never be submitted.
        Some(sig) if sig == IInbox::MessageExecuted::SIGNATURE_HASH => {
            IInbox::MessageExecuted::decode_log(&log.inner)
                .map(|decoded| Some(("MessageExecuted", decoded.data.messageId)))
        }
        _ => Ok(None),
    }
}

/// Try to fetch a proof and submit an acknowledgment for every pending destination tx that is due
/// for an attempt. Successful (or terminally-reverting) submissions move to `done`; not-yet-ready
/// proofs are re-polled per the route's [`crate::pending::NotReadyPolicy`] (flat cadence inside
/// the window, capped slow backoff past it); transient failures back off
/// exponentially and escalate the log after [`MAX_ACK_TRANSIENT_ATTEMPTS`].
#[allow(clippy::too_many_arguments)]
async fn process_pending<P: Provider>(
    chain_key: u64,
    ack: &AckConfig,
    mode: &SettlementMode,
    source_chain_id: u64,
    outboxes: &BTreeSet<Address>,
    client: &ProofGenClient,
    source_provider: &P,
    submitter_address: alloy::primitives::Address,
    broadcast_locks: &Arc<crate::broadcast::BroadcastLocks>,
    metrics: &Metrics,
    pending: &mut PendingTxs<DeliveryEvent>,
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
    let results: Vec<(B256, Vec<DeliveryEvent>, Result<AckOutcome>)> = futures::stream::iter(batch)
        .map(|(tx_hash, message_ids)| async move {
            let outcome = acknowledge_tx(
                chain_key,
                mode,
                source_chain_id,
                outboxes,
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
                done.insert(tx_hash);
            }
            Ok(AckOutcome::Terminal(reason)) => {
                info!(chain_key, %tx_hash, %reason, "ack skipped (terminal); will not retry");
                pending.remove(&tx_hash);
                done.insert(tx_hash);
            }
            Ok(AckOutcome::NotReady(reason)) => {
                // A delayed proof remains an obligation even after a prolonged outage. Keeping
                // the pending entry also holds the durable cursor behind its discovery block.
                let waited = pending.age(&tx_hash, now).unwrap_or_default();
                let retry_in = not_ready_policy.next_delay(waited);
                if waited > ACK_OVERDUE_AFTER {
                    warn!(
                        chain_key,
                        %tx_hash,
                        %reason,
                        waited_secs = waited.as_secs(),
                        retry_in_secs = retry_in.as_secs(),
                        "proof is overdue; retaining settlement and retrying at capped backoff"
                    );
                } else {
                    info!(
                        chain_key,
                        %tx_hash,
                        message_ids = ?message_ids,
                        %reason,
                        waited_secs = waited.as_secs(),
                        retry_in_secs = retry_in.as_secs(),
                        past_poll_window = waited >= not_ready_policy.poll_window,
                        "⏳ proof not ready yet (destination block not attested / proof-gen catching \
                         up); polling"
                    );
                }
                pending.defer(&tx_hash, now + retry_in);
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
    /// (`submitAcknowledgment`, one call per tx — the validator acks every `MessageExecuted` log
    /// under try/catch). Each original Outbox supplies its own current validator.
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
    /// A reverted submission. Source acknowledgment/fee state must confirm completion before
    /// this is allowed to release the transaction from the pending queue.
    Terminal(String),
}

/// Await a broadcast result and classify it, shared by both submit paths so the receipt-wait, revert
/// classification, and gas accounting cannot drift between ack and claim. `Err` is a transient
/// failure the caller should retry; `Ok(Terminal)` still requires a finalized source-state check.
/// `call` names the call for logs.
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
            .block(BlockNumberOrTag::Finalized.into())
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
    mode: &SettlementMode,
    source_chain_id: u64,
    outboxes: &BTreeSet<Address>,
    messages: &[DeliveryEvent],
    client: &ProofGenClient,
    source_provider: &P,
    submitter_address: alloy::primitives::Address,
    broadcast_locks: &Arc<crate::broadcast::BroadcastLocks>,
    metrics: &Metrics,
    tx_hash: B256,
) -> Result<AckOutcome> {
    // Resolve each original publication before deciding no settlement remains. Missing history
    // or RPC failures must never turn an unknown message into a no-op on today's default Outbox.
    let message_ids: Vec<B256> = messages
        .iter()
        .filter(|event| !event.executed)
        .map(|event| event.message_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let executed_ids: Vec<B256> = messages
        .iter()
        .filter(|event| event.executed)
        .map(|event| event.message_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let ack_routes = if executed_ids.is_empty() {
        routes::Resolution::default()
    } else {
        routes::validators(
            source_provider,
            source_chain_id,
            chain_key,
            outboxes,
            &executed_ids,
        )
        .await
    };
    let needs_ack = !ack_routes.authorities.is_empty() || ack_routes.failure.is_some();
    let mut failure = ack_routes.failure;

    let claim_ids: Vec<B256> = match mode {
        SettlementMode::Ack => Vec::new(),
        SettlementMode::AckAndClaim {
            relayer_contract, ..
        } => match relay_claimable_ids(source_provider, *relayer_contract, &message_ids).await {
            Ok(ids) => ids,
            Err(err) => {
                warn!(chain_key, %tx_hash, %err, "relay-claimable pre-check failed; attempting all ids");
                message_ids.clone()
            }
        },
    };

    if claim_ids.is_empty() && ack_routes.authorities.is_empty() {
        // Other known routes and independent fee claims can still settle during backfill.
        if let Some(err) = failure {
            return Err(err);
        }
    }
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
            if let Some(err) = failure {
                // Preserve the routing error while history or source RPCs recover, even when
                // proof-gen also needs more time.
                return Err(err.context(format!("delivery proof also not ready: {reason}")));
            }
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
    // Attempt every independent settlement even when one fails. On retry, source-state reads
    // skip completed work and select current authorities, so partial successes converge.
    for authority in &ack_routes.authorities {
        let (inclusion, continuity) = proof.to_inclusion_and_continuity()?;
        let validator = crate::abi::IAcknowledgmentValidator::new(*authority, source_provider);
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
                failure.get_or_insert_with(|| anyhow!("submitAcknowledgment {stalled}"));
                continue;
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
            // Terminal here (e.g. NoMessageExecutedLogs because another submitter front-ran the
            // bounty and every log is now already-acked, or because this tx has no MessageExecuted
            // log at all — a destination-failure-only or MessageQueued/MessageDeferred tx) must
            // not block the relay-fee claim below — the claim pays the proven relayer regardless of
            // destination outcome or who acknowledged.
            Ok(SubmitOutcome::Terminal(reason)) => {
                metrics.inc_ack_submission(chain_key, SettlementOutcome::Terminal);
                info!(chain_key, %tx_hash, %reason, "submitAcknowledgment reverted; continuing other settlements before source-state verification");
            }
            Err(err) => {
                metrics.inc_ack_submission(chain_key, SettlementOutcome::Failed);
                failure.get_or_insert(err);
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
                    failure.get_or_insert_with(|| anyhow!("claimDelivery {stalled}"));
                    continue;
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
                        "claimDelivery reverted; checking fee-ledger state before completing",
                    );
                }
                Err(err) => {
                    metrics.inc_claim_submission(chain_key, SettlementOutcome::Failed);
                    failure.get_or_insert(err);
                }
            }
        }
    }

    // A successful receipt or NoMessageExecutedLogs is not proof of acknowledgment: the
    // validator catches individual Outbox failures, including a concurrently rotated authority.
    // Only source state can release executed obligations. Non-executed deliveries are excluded,
    // so queued/failure-only transactions finish their fee claim without waiting for a later retry.
    if !executed_ids.is_empty() {
        let remaining = routes::validators(
            source_provider,
            source_chain_id,
            chain_key,
            outboxes,
            &executed_ids,
        )
        .await;
        if let Some(err) = remaining.failure {
            failure.get_or_insert(err);
        }
        if !remaining.authorities.is_empty() {
            failure.get_or_insert_with(|| {
                anyhow!("executed messages remain unacknowledged on their original Outboxes")
            });
        }
    }
    if let SettlementMode::AckAndClaim {
        relayer_contract, ..
    } = mode
    {
        match relay_claimable_ids(source_provider, *relayer_contract, &claim_ids).await {
            Ok(remaining) if !remaining.is_empty() => {
                failure.get_or_insert_with(|| {
                    anyhow!("relay fees remain unsettled in the configured ledger")
                });
            }
            Err(err) => {
                failure.get_or_insert(err);
            }
            Ok(_) => {}
        }
    }
    if let Some(err) = failure {
        return Err(err);
    }
    Ok(AckOutcome::Acknowledged)
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
        s if s == V::NoMessageExecutedLogs::SELECTOR => "NoMessageExecutedLogs",
        s if s == RC::RelayAlreadySettled::SELECTOR => "RelayAlreadySettled",
        s if s == RC::UnknownOperation::SELECTOR => "UnknownOperation",
        _ => return None,
    })
}

/// Recognize on-chain reverts for submission diagnostics. Even a deterministic revert needs a
/// finalized source-state check before the settlement can be removed from the queue.
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
    // Reverts can reflect already-settled work or temporary contract state (pause/verifier
    // changes). The caller checks the actual obligation after processing all independent groups.
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
        || s.contains("NoMessageExecutedLogs")
        || s.contains("RelayAlreadySettled")
        || s.contains("UnknownOperation")
}

/// Prefix a terminal revert with the decoded error name when the selector is recognized, so the
/// submission diagnostic tells the operator why without a manual selector lookup.
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
    use alloy::primitives::{Bytes, U64};
    use alloy::providers::ProviderBuilder;
    use alloy::sol_types::SolValue;
    use alloy::transports::mock::Asserter;

    #[tokio::test]
    async fn full_pending_queue_keeps_cursor_and_unfinished_work() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(rpc.clone());
        let inbox = Address::repeat_byte(1);
        let mut pending = PendingTxs::new(1);
        let mut done = BoundedSeen::new(10);
        let mut cursor = 10;
        let tx1 = B256::repeat_byte(1);
        let tx2 = B256::repeat_byte(2);
        let id1 = B256::repeat_byte(11);
        let id2 = B256::repeat_byte(12);
        let log = |tx, id| alloy::rpc::types::Log {
            inner: alloy::primitives::Log {
                address: inbox,
                data: IInbox::MessageReceived {
                    messageId: id,
                    processor: inbox,
                    relayer: inbox,
                }
                .encode_log_data(),
            },
            transaction_hash: Some(tx),
            block_number: Some(11),
            ..Default::default()
        };
        let executed = alloy::rpc::types::Log {
            inner: alloy::primitives::Log {
                address: inbox,
                data: IInbox::MessageExecuted {
                    messageId: id1,
                    emitterAddress: inbox,
                    destination: inbox,
                    dispatcher: inbox,
                    relayer: inbox,
                    messagePayload: Bytes::new(),
                }
                .encode_log_data(),
            },
            transaction_hash: Some(tx1),
            block_number: Some(11),
            ..Default::default()
        };
        // Deliberately unsorted: execution metadata for an admitted tx arrives after capacity.
        let logs = vec![log(tx1, id1), log(tx2, id2), executed];
        rpc.push_success(&U64::from(12));
        rpc.push_success(&logs);
        discover_delivered(2, inbox, 0, &provider, &mut cursor, &mut pending, &done)
            .await
            .unwrap();
        assert_eq!(cursor, 10, "a partial range must be replayed");
        assert!(pending.contains(&tx1));
        assert!(!pending.contains(&tx2));
        assert_eq!(pending.oldest_pending_block(), Some(11));
        assert!(pending.ready(1, Instant::now())[0]
            .1
            .iter()
            .any(|event| event.executed));
        pending.remove(&tx1);
        done.insert(tx1);
        rpc.push_success(&U64::from(12));
        rpc.push_success(&logs);
        discover_delivered(2, inbox, 0, &provider, &mut cursor, &mut pending, &done)
            .await
            .unwrap();
        assert_eq!(cursor, 12);
        assert!(pending.contains(&tx2));
    }

    #[tokio::test]
    async fn queued_transaction_without_execution_has_no_ack_obligation() {
        let provider = ProviderBuilder::new().connect_mocked_client(Asserter::new());
        let result = acknowledge_tx(
            2,
            &SettlementMode::Ack,
            42,
            &BTreeSet::new(),
            &[DeliveryEvent {
                message_id: B256::repeat_byte(1),
                executed: false,
            }],
            &ProofGenClient::new("http://unused.invalid").unwrap(),
            &provider,
            Address::repeat_byte(1),
            &crate::broadcast::BroadcastLocks::new(),
            &(crate::prom::NoopMetrics::new() as Metrics),
            B256::repeat_byte(2),
        )
        .await
        .unwrap();
        assert!(matches!(result, AckOutcome::Terminal(_)));
    }

    #[tokio::test]
    async fn execution_flag_survives_a_later_received_event() {
        let provider = ProviderBuilder::new().connect_mocked_client(Asserter::new());
        let id = B256::repeat_byte(1);
        let result = acknowledge_tx(
            2,
            &SettlementMode::Ack,
            42,
            &BTreeSet::new(),
            &[
                DeliveryEvent {
                    message_id: id,
                    executed: true,
                },
                DeliveryEvent {
                    message_id: id,
                    executed: false,
                },
            ],
            &ProofGenClient::new("http://unused.invalid").unwrap(),
            &provider,
            Address::repeat_byte(1),
            &crate::broadcast::BroadcastLocks::new(),
            &(crate::prom::NoopMetrics::new() as Metrics),
            B256::repeat_byte(2),
        )
        .await;
        assert!(
            result.is_err(),
            "unknown executed obligations must remain retryable"
        );
    }

    async fn proof_server() -> (ProofGenClient, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new().fallback(|| async {
            axum::Json(serde_json::json!({
                "headerNumber": 12, "txBytes": "0x01",
                "continuityProof": { "lowerEndpointDigest": B256::ZERO, "roots": [] },
                "merkleProof": { "root": B256::ZERO, "siblings": [] },
            }))
        });
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (ProofGenClient::new(&url).unwrap(), task)
    }

    #[tokio::test]
    async fn overdue_proof_remains_pending_and_holds_restart_checkpoint() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(rpc.clone());
        let outbox = Address::repeat_byte(1);
        let validator = Address::repeat_byte(2);
        let message = crate::abi::OutboxMessage {
            emitter: Address::repeat_byte(3),
            sequence: 4,
            timestamp: 5,
            canAck: true,
            acknowledged: false,
            payloadHash: B256::repeat_byte(6),
        };
        let id = alloy::primitives::keccak256(
            (
                outbox,
                message.emitter,
                message.sequence,
                message.payloadHash,
                U256::from(42),
            )
                .abi_encode_params(),
        );
        rpc.push_success(&Bytes::from(message.abi_encode()));
        rpc.push_success(&Bytes::from(validator.abi_encode()));
        rpc.push_success(&Bytes::from(outbox.abi_encode()));
        rpc.push_success(&Bytes::from(2u64.abi_encode()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new().fallback(|| async { axum::http::StatusCode::NOT_FOUND });
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let ack = AckConfig {
            proof_gen_url: url.clone(),
            validator_address: validator,
            signer_key: String::new(),
            confirmation_depth: 0,
            start_block: None,
            not_ready_poll_secs: 6,
            not_ready_poll_window_secs: 600,
        };
        let tx = B256::repeat_byte(9);
        let mut pending = PendingTxs::new(1);
        let mut done = BoundedSeen::new(10);
        pending.insert(
            tx,
            Instant::now() - ACK_OVERDUE_AFTER - Duration::from_secs(1),
            12,
            vec![DeliveryEvent {
                message_id: id,
                executed: true,
            }],
        );
        process_pending(
            2,
            &ack,
            &SettlementMode::Ack,
            42,
            &BTreeSet::from([outbox]),
            &ProofGenClient::new(&url).unwrap(),
            &provider,
            Address::repeat_byte(8),
            &crate::broadcast::BroadcastLocks::new(),
            &(crate::prom::NoopMetrics::new() as Metrics),
            &mut pending,
            &mut done,
        )
        .await;
        server.abort();
        assert!(
            pending.contains(&tx),
            "old proof unavailability must not abandon custody"
        );
        assert!(!done.contains(&tx));
        assert_eq!(pending.oldest_pending_block(), Some(12));
        assert!(pending.ready(1, Instant::now()).is_empty());
        assert_eq!(
            pending
                .ready(1, Instant::now() + crate::pending::TRANSIENT_BACKOFF_MAX)
                .len(),
            1
        );
        assert!(rpc.read_q().is_empty());
    }

    #[tokio::test]
    async fn settlement_completion_reads_finalized_source_state() {
        let outbox = Address::repeat_byte(1);
        let message = crate::abi::OutboxMessage {
            emitter: Address::repeat_byte(3),
            sequence: 4,
            timestamp: 5,
            canAck: true,
            acknowledged: true,
            payloadHash: B256::repeat_byte(6),
        };
        let id = alloy::primitives::keccak256(
            (
                outbox,
                message.emitter,
                message.sequence,
                message.payloadHash,
                U256::from(42),
            )
                .abi_encode_params(),
        );
        let info = crate::abi::IRelayerContract::MessageInfo {
            payer: Address::repeat_byte(1),
            destinationChain: 2,
            gasLimit: U256::from(100_000),
            relayFee: U256::from(1),
            tip: U256::ZERO,
            tipExpiry: U256::ZERO,
            deliveryDeadline: U256::ZERO,
            relaySettled: true,
            feesInNative: false,
        };
        let responses = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::from([
            Bytes::from(message.abi_encode()),
            Bytes::from(info.abi_encode()),
        ])));
        let received = responses.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new().fallback(move |axum::Json(request): axum::Json<serde_json::Value>| {
            let received = received.clone();
            async move {
                assert_eq!(request["method"], "eth_call");
                assert_eq!(request["params"][1], "finalized");
                let result = received.lock().unwrap().pop_front().unwrap();
                axum::Json(serde_json::json!({ "jsonrpc": "2.0", "id": request["id"], "result": result }))
            }
        });
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let provider = ProviderBuilder::new().connect_http(url.parse().unwrap());
        let resolved = routes::validators(&provider, 42, 2, &BTreeSet::from([outbox]), &[id]).await;
        assert!(resolved.failure.is_none());
        assert!(resolved.authorities.is_empty());
        assert!(
            relay_claimable_ids(&provider, Address::repeat_byte(2), &[id])
                .await
                .unwrap()
                .is_empty()
        );
        server.abort();
        assert!(responses.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn no_executed_logs_revert_cannot_discard_an_unacknowledged_execution() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_mocked_client(rpc.clone());
        let outbox = Address::repeat_byte(1);
        let validator = Address::repeat_byte(2);
        let message = crate::abi::OutboxMessage {
            emitter: Address::repeat_byte(3),
            sequence: 4,
            timestamp: 5,
            canAck: true,
            acknowledged: false,
            payloadHash: B256::repeat_byte(6),
        };
        let id = alloy::primitives::keccak256(
            (
                outbox,
                message.emitter,
                message.sequence,
                message.payloadHash,
                U256::from(42),
            )
                .abi_encode_params(),
        );
        let push_route = || {
            rpc.push_success(&Bytes::from(message.abi_encode()));
            rpc.push_success(&Bytes::from(validator.abi_encode()));
            rpc.push_success(&Bytes::from(outbox.abi_encode()));
            rpc.push_success(&Bytes::from(2u64.abi_encode()));
        };
        push_route();
        rpc.push_failure_msg("execution reverted: NoMessageExecutedLogs");
        push_route();
        let (client, server) = proof_server().await;
        let result = acknowledge_tx(
            2,
            &SettlementMode::Ack,
            42,
            &BTreeSet::from([outbox]),
            &[DeliveryEvent {
                message_id: id,
                executed: true,
            }],
            &client,
            &provider,
            Address::repeat_byte(8),
            &crate::broadcast::BroadcastLocks::new(),
            &(crate::prom::NoopMetrics::new() as Metrics),
            B256::repeat_byte(9),
        )
        .await;
        server.abort();
        assert!(
            result.is_err(),
            "a caught Outbox failure is not settlement evidence"
        );
        assert!(
            rpc.read_q().is_empty(),
            "source acknowledgment state must be rechecked"
        );
    }

    #[tokio::test]
    async fn one_authority_failure_does_not_block_other_acknowledgments() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_mocked_client(rpc.clone());
        let a = Address::repeat_byte(1);
        let b = Address::repeat_byte(2);
        let record = |acknowledged| crate::abi::OutboxMessage {
            emitter: Address::repeat_byte(3),
            sequence: 4,
            timestamp: 5,
            canAck: true,
            acknowledged,
            payloadHash: B256::repeat_byte(6),
        };
        let id = |outbox: Address| {
            alloy::primitives::keccak256(
                (
                    outbox,
                    record(false).emitter,
                    4u64,
                    B256::repeat_byte(6),
                    U256::from(42),
                )
                    .abi_encode_params(),
            )
        };
        let push = |outbox: Address, authority: Address| {
            rpc.push_success(&Bytes::from(record(false).abi_encode()));
            rpc.push_success(&Bytes::from(authority.abi_encode()));
            rpc.push_success(&Bytes::from(outbox.abi_encode()));
            rpc.push_success(&Bytes::from(2u64.abi_encode()));
        };
        let mut publications = [a, b];
        publications.sort_by_key(|outbox| id(*outbox));
        for outbox in publications {
            if outbox == a {
                push(a, Address::repeat_byte(11));
            } else {
                rpc.push_failure_msg("execution reverted: 0x5d803cca");
                push(b, Address::repeat_byte(12));
            }
        }
        rpc.push_failure_msg("validator A RPC failure");
        // B raced with another submitter, which already acknowledged it successfully.
        rpc.push_failure_msg("execution reverted: NoMessageExecutedLogs");
        for outbox in publications {
            if outbox == a {
                push(a, Address::repeat_byte(11));
            } else {
                rpc.push_failure_msg("execution reverted: 0x5d803cca");
                rpc.push_success(&Bytes::from(record(true).abi_encode()));
            }
        }
        let (client, server) = proof_server().await;
        let result = acknowledge_tx(
            2,
            &SettlementMode::Ack,
            42,
            &BTreeSet::from([a, b]),
            &[
                DeliveryEvent {
                    message_id: id(a),
                    executed: true,
                },
                DeliveryEvent {
                    message_id: id(b),
                    executed: true,
                },
            ],
            &client,
            &provider,
            Address::repeat_byte(8),
            &crate::broadcast::BroadcastLocks::new(),
            &(crate::prom::NoopMetrics::new() as Metrics),
            B256::repeat_byte(9),
        )
        .await;
        server.abort();
        assert!(result.is_err(), "A must remain queued");
        assert!(
            rpc.read_q().is_empty(),
            "B must be attempted even when A fails"
        );
    }

    #[tokio::test]
    async fn a_claim_revert_cannot_discard_an_unsettled_fee() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_mocked_client(rpc.clone());
        let info = crate::abi::IRelayerContract::MessageInfo {
            payer: Address::repeat_byte(1),
            destinationChain: 2,
            gasLimit: U256::from(100_000),
            relayFee: U256::from(1),
            tip: U256::ZERO,
            tipExpiry: U256::ZERO,
            deliveryDeadline: U256::ZERO,
            relaySettled: false,
            feesInNative: false,
        };
        rpc.push_success(&Bytes::from(info.abi_encode()));
        rpc.push_failure_msg("execution reverted: EnforcedPause");
        rpc.push_success(&Bytes::from(info.abi_encode()));
        let (client, server) = proof_server().await;
        let result = acknowledge_tx(
            2,
            &SettlementMode::AckAndClaim {
                relayer_contract: Address::repeat_byte(2),
                chain_key: B256::from(U256::from(2)),
            },
            42,
            &BTreeSet::new(),
            &[DeliveryEvent {
                message_id: B256::repeat_byte(1),
                executed: false,
            }],
            &client,
            &provider,
            Address::repeat_byte(8),
            &crate::broadcast::BroadcastLocks::new(),
            &(crate::prom::NoopMetrics::new() as Metrics),
            B256::repeat_byte(9),
        )
        .await;
        server.abort();
        assert!(
            result.is_err(),
            "an operational revert must leave the fee claim queued"
        );
        assert!(
            rpc.read_q().is_empty(),
            "fee settlement must be checked after submission"
        );
    }

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

        let received = IInbox::MessageReceived {
            messageId: message_id,
            processor: addr,
            relayer: addr,
        };
        let (name, id) = decode_delivery_log(&rpc_log(addr, received.encode_log_data()))
            .expect("decodes")
            .expect("recognized");
        assert_eq!(name, "MessageReceived");
        assert_eq!(id, message_id);

        let queued = IInbox::MessageQueued {
            messageId: message_id,
            destinationContract: addr,
            relayer: addr,
        };
        let (name, id) = decode_delivery_log(&rpc_log(addr, queued.encode_log_data()))
            .expect("decodes")
            .expect("recognized");
        assert_eq!(name, "MessageQueued");
        assert_eq!(id, message_id);

        let deferred = IInbox::MessageDeferred {
            messageId: message_id,
            destinationContract: addr,
            relayer: addr,
        };
        let (name, id) = decode_delivery_log(&rpc_log(addr, deferred.encode_log_data()))
            .expect("decodes")
            .expect("recognized");
        assert_eq!(name, "MessageDeferred");
        assert_eq!(id, message_id);

        // #54: a retry-only success (no MessageReceived on that tx) must still be discoverable, or
        // its ack (and ack-fee bounty) is never submitted.
        let executed = IInbox::MessageExecuted {
            messageId: message_id,
            emitterAddress: addr,
            destination: addr,
            dispatcher: addr,
            relayer: addr,
            messagePayload: alloy::primitives::Bytes::new(),
        };
        let (name, id) = decode_delivery_log(&rpc_log(addr, executed.encode_log_data()))
            .expect("decodes")
            .expect("recognized");
        assert_eq!(name, "MessageExecuted");
        assert_eq!(id, message_id);
    }

    #[test]
    fn decode_delivery_log_ignores_unrelated_topic0() {
        // The discovery filter only requests these four topic0s, but an RPC is not trusted to
        // honor that — an unrelated event on the same Inbox (e.g. the ack validator's
        // Acknowledged, a completely different contract in practice but same shape of concern)
        // must be skipped, not mis-decoded as one of the four we expect.
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
            vec![IInbox::MessageReceived::SIGNATURE_HASH],
            Default::default(),
        )
        .expect("valid LogData");
        let log = rpc_log(Address::ZERO, malformed);
        assert!(decode_delivery_log(&log).is_err());
    }
}
