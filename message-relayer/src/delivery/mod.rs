//! Per-route delivery worker.
//!
//! Consumes [`DeliveryJob`]s from the vote pool and submits `Inbox.deliverMessage(...)` on the
//! destination chain. Implements the PoC §7 + §9 behaviour:
//!
//!  1. Refuse what can never be delivered: an envelope whose `nativeCoinValue` exceeds the route's
//!     `max_native_coin_value_wei`, or whose attested `gasLimit` exceeds `max_gas_limit`
//!     (asc-contracts #36 — the router only rejects `gasLimit == 0`, so an oversized one would be
//!     retried forever). Both are terminal with their own metric label.
//!  2. Optionally simulate early, then always preflight the exact gas limit before broadcasting.
//!     Permanent envelope failures are terminal; pauses, quorum changes and other mutable-state
//!     reverts stay retryable. Already-validated messages are reconciled against confirmed Inbox
//!     execution state, since acceptance alone does not establish successful execution.
//!  3. Send the transaction, watching for receipt (bounded by [`RECEIPT_TIMEOUT`] so a stuck
//!     underpriced tx cannot wedge the route's serial worker).
//!  4. Classify the outcome from the receipt logs. `MessageQueued`/`MessageDeferred` and
//!     (asc-contracts #54) `DestinationFailed` are **events on a successful tx**: the former means
//!     the dispatcher deferred/queued the message (retryable via `retryPendingMessage`), the
//!     latter that the destination call failed but the message is NOT consumed — retryable via
//!     the permissionless `retryFailedMessage` (NOT a fresh `deliverMessage`: Inbox marks it
//!     `isRetryable` and a second `deliverMessage` for the same id now reverts
//!     `MessageAlreadyValidated`; delivery still counts and is still paid via `MessageReceived`
//!     either way). A mined-but-reverted tx is replayed to learn why: an
//!     `InsufficientGasForDestination` revert is retried with 25% more gas up to `max_gas_limit`.
//!  5. Keep queued/failed execution in the durable pool. Its serial worker reconciles the Inbox
//!     and runs one permissionless retry per scheduled job, honoring `RetryDeferred(retryAfter)`.
//!     Restart probes reconstruct execution state without requiring another committee quorum.
//!     `retryFailedMessage` (failed destination call) is bounded by the route's
//!     [`FailedRetryPolicy`](crate::config::FailedRetryPolicy): exponential backoff, then the work
//!     is dropped and the message left retryable on-chain — see [`failed_retry`].
//!  6. On RPC-level failure, retry up to `delivery.max_retries` with backoff.
//!
//! The worker processes one job at a time per route — serial nonce management is the simplest
//! approach for PoC scope and matches PoC §7.2 ("optional multiple wallets for throughput, out
//! of PoC scope"). Each route runs in its own [`tokio::spawn`] so a slow destination chain
//! does not block the others.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::eips::BlockId;
use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::Log;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolError, SolEvent, SolValue};
use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::abi::{IInbox, IMessageDispatcher, IMessageReceiver, IRelayerContract};
use crate::config::{ChainRoute, DeliveryConfig};
use crate::outcome::{DeliveryOutcome, OutcomeKind, OutcomeStore};
use crate::prom::{DeliveryStatus, Metrics};
use crate::revert::{is_revert, revert_data, revert_selector};

pub mod encode;
pub mod failed_retry;

use failed_retry::{FailedRetries, Gate};

/// Initial retry backoff. Subsequent attempts double the wait, capped by [`MAX_BACKOFF`].
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// The four-field EVM envelope `abi.encode(destination, nativeCoinValue, gasLimit, payloadData)`
/// (asc-contracts #36) — or rather the two words of it the relayer acts on. A payload that is not
/// an envelope (legacy dApps, raw bytes) carries no value and no attested gas.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct EnvelopeTerms {
    native_value: U256,
    /// Attested destination `gasLimit`; `None` when the payload is not an envelope.
    gas_limit: Option<U256>,
}

fn envelope_terms(payload: &[u8]) -> EnvelopeTerms {
    <(Address, U256, U256, Bytes)>::abi_decode_params(payload)
        .map(|(_, native_value, gas_limit, _)| EnvelopeTerms {
            native_value,
            gas_limit: Some(gas_limit),
        })
        .unwrap_or_default()
}

/// The `nativeCoinValue` an EVM `messagePayload` asks the dispatcher to forward, or zero when the
/// payload is not the four-field envelope. Test-side shorthand for [`envelope_terms`].
#[cfg(test)]
fn envelope_native_value(payload: &[u8]) -> U256 {
    envelope_terms(payload).native_value
}

/// Upper bound on waiting for a delivery receipt. Without it, one stuck (e.g. underpriced) tx
/// blocks the route's serial worker — and every message queued behind it — indefinitely. On
/// timeout the job returns to the pool's bounded retry; if the stuck tx mines later, the next
/// attempt's simulate detects the duplicate ("Already validated") and resolves idempotently.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Cadence of the delivery worker's liveness heartbeat. Must stay comfortably under the health
/// watchdog's staleness deadline so an idle route — one with no messages to deliver — is never
/// mistaken for a wedged one.
const HEALTH_TICK: Duration = Duration::from_secs(15);

/// Upper bound on the per-job funded-gas RPC reads (`RelayerContract.getMessageInfo` on the
/// source, the under-funding `estimate_gas` on the destination, and the mined-revert replay). All
/// sit in the serial worker's critical path, so a stalled RPC must not park the route — on timeout
/// the job degrades gracefully (estimation fallback / bounded retry) instead of wedging.
const FUNDED_GAS_READ_TIMEOUT: Duration = Duration::from_secs(20);

/// Upper bound on a single `send()` — the gas/fee/nonce reads plus `eth_sendRawTransaction`. Alloy's
/// HTTP transport has no timeout of its own, so without this a black-holed RPC parks the route (and
/// starves the cancel branch, so SIGTERM is ignored) forever. Generous enough that a merely slow
/// endpoint still succeeds.
///
/// Abandoning a send here no longer costs a nonce: sends go through
/// [`crate::broadcast::BroadcastLocks`] against a chain-read nonce, so a broadcast that never reached
/// the node leaves the pending count untouched and the next attempt re-reads the same nonce. What a
/// timeout here *does* leave is genuine ambiguity about whether the tx landed — resolved
/// idempotently, since the next attempt's simulate detects an already-validated message.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Sanity ceiling on a funded gasLimit read from the vault. Real per-tx gas is far below this; a
/// value above it means a misconfigured `--relayer-fee-vault-address` (an unrelated contract whose
/// `getMessageInfo` ABI-decodes to junk), so we ignore it and estimate rather than pin an
/// unincludable `.gas()` on every delivery for the route.
const MAX_FUNDED_GAS: u64 = 100_000_000;

/// How far past `deliveryDeadline` local time must be before the top-up window counts as closed.
///
/// `RelayerContract._checkTopUp` compares the deadline against the *source chain's*
/// `block.timestamp`, and this worker has no source-chain clock on the delivery path, so the margin
/// absorbs host-to-chain skew. The asymmetry is deliberate: being late to give up costs a handful of
/// extra retries, whereas being early would strand a message that could still have been rescued.
const TOP_UP_DEADLINE_GRACE: Duration = Duration::from_secs(900);

/// Capped backoff shared by pending and failed execution retries. The last delay repeats
/// indefinitely while durable work remains unfinished. When the previous attempt reverted
/// `RetryDeferred(retryAfter)` with a usable timestamp — the same error both entrypoints revert —
/// that timestamp (plus [`RETRY_DEFERRED_MARGIN`]) replaces the fixed delay — see
/// [`pending_retry_delay`].
const PENDING_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(15),
    Duration::from_secs(60),
    Duration::from_secs(240),
];

/// Slack added on top of a `RetryDeferred.retryAfter` hint: the dispatcher's window opens at that
/// second on the *destination chain's* clock, and the retry tx also has to be mined after it, so
/// aiming exactly at the boundary would revert again on any skew.
const RETRY_DEFERRED_MARGIN: Duration = Duration::from_secs(5);

/// Longest the pool honors a `retryAfter` hint before reconciling again. A far-future dispatcher
/// hint must not suppress observation of execution by another party indefinitely.
const MAX_RETRY_DEFERRED_WAIT: Duration = Duration::from_secs(6 * 3600);

/// Job dispatched by the pool when a `messageId` (also the signed digest since asc-contracts #54)
/// clears the threshold.
#[derive(Clone, Debug)]
pub struct DeliveryJob {
    pub chain_key: u64,
    pub message_id: B256,
    pub emitter: Address,
    /// Source Outbox the message was scanned from; second `deliverMessage` argument (#45).
    pub outbox: Address,
    /// Per-emitter Outbox sequence `messageId` was derived from (asc-contracts #54) — the fourth
    /// `deliverMessage` argument.
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub votes_calldata: Vec<u8>,
    pub signer_count: usize,
    pub indexed_at: Instant,
    /// Reconcile previously accepted execution (or probe restored work) without submitting votes.
    pub reconcile_only: bool,
}

#[derive(Clone, Debug)]
pub struct DeliveryResult {
    pub chain_key: u64,
    pub message_id: B256,
    pub outcome: DeliveryResultKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryResultKind {
    Delivered,
    Terminal,
    Retryable,
    /// No on-chain acceptance was found; return to aggregation until a quorum is available.
    AwaitingVotes,
    /// Votes are already accepted. Keep retrying execution without requiring another quorum.
    AwaitingExecution {
        retry_after: Option<u64>,
    },
}

/// Spawn the delivery worker for one route. Exits on `cancel` or unrecoverable channel close.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    route: ChainRoute,
    delivery_config: DeliveryConfig,
    creditcoin_eth_rpc_url: String,
    mut job_rx: mpsc::Receiver<DeliveryJob>,
    result_tx: mpsc::Sender<DeliveryResult>,
    metrics: Metrics,
    health: Arc<crate::health::Health>,
    broadcast_locks: Arc<crate::broadcast::BroadcastLocks>,
    outcomes: Arc<OutcomeStore>,
    work: Option<Arc<crate::work::WorkStore>>,
    cancel: CancellationToken,
) -> Result<()> {
    let chain_key = route.chain_key;
    let health_key = format!("delivery:{chain_key}");
    let failed_retries = FailedRetries::new(chain_key, work);

    // Register with the health watchdog BEFORE any fallible or blocking setup, because
    // `Health::status` only inspects components that have registered: a worker that never called
    // `heartbeat` is invisible to it and therefore counts as healthy. Registering after the RPC
    // connects would mean a connect that hangs (black-holed endpoint, TCP with no RST) leaves this
    // route permanently dead while `/health` keeps answering 200 and Kubernetes never restarts the
    // pod — the exact failure class the watchdog exists to catch. The outbox watcher orders it the
    // same way; keep them consistent.
    health.heartbeat(&health_key);

    let signer_key = route
        .signer_key
        .clone()
        .with_context(|| format!("chain_key {chain_key}: signer_key is required to deliver"))?;
    let signer: PrivateKeySigner = signer_key
        .trim()
        .parse()
        .with_context(|| format!("chain_key {chain_key}: invalid signer_key"))?;

    let signer_address = signer.address();
    let wallet = EthereumWallet::from(signer);
    // Chain-read nonces, so a broadcast that fails after `prepare` (RPC 502, SEND_TIMEOUT
    // abandonment, LB failover) does not consume a nonce the chain never saw and wedge the route
    // until restart. Every send from this signer, including supervised execution retries and
    // the set-update submitter sharing `route.signer_key`, serializes through `broadcast_locks`
    // instead of through a
    // per-provider local counter. The two halves are only correct together; see `crate::broadcast`.
    let provider = crate::broadcast::chain_nonce_builder()
        .wallet(wallet)
        .connect(&route.destination_rpc_url)
        .await
        .with_context(|| {
            format!(
                "chain_key {chain_key}: failed to connect to destination RPC at {}",
                route.destination_rpc_url
            )
        })?;

    // Read-only source-chain provider, only when the relayer contract is configured: used to look
    // up each message's funded `gasLimit` so the delivery tx is pinned to it (see `funded_gas_limit`).
    let source_provider = match route.relayer_contract_address {
        Some(_) => Some(
            ProviderBuilder::new()
                .connect(&creditcoin_eth_rpc_url)
                .await
                .with_context(|| {
                    format!(
                        "chain_key {chain_key}: failed to connect to source EVM RPC at {creditcoin_eth_rpc_url} \
                         (needed to read funded gasLimit from the RelayerContract ledger)"
                    )
                })?,
        ),
        None => None,
    };

    // Opt-in `requestTopUp` sender (source chain, signed by the ack/claim key). Built here, once,
    // so a bad key fails the route at startup instead of on the first under-funded message.
    let mut top_up = match (route.auto_request_top_up, route.relayer_contract_address) {
        (true, Some(relayer_contract)) => Some(
            TopUpRequester::connect(
                &route,
                relayer_contract,
                &creditcoin_eth_rpc_url,
                broadcast_locks.clone(),
            )
            .await?,
        ),
        _ => None,
    };

    info!(
        chain_key,
        signer = %signer_address,
        inbox = %route.inbox_address,
        relayer_contract = ?route.relayer_contract_address,
        max_native_coin_value_wei = %route.max_native_coin_value_wei,
        max_gas_limit = route.max_gas_limit,
        auto_request_top_up = route.auto_request_top_up,
        "🚚 delivery worker online"
    );

    // Liveness tick. This worker is idle-driven: it blocks on `job_rx.recv()`, so a route with no
    // traffic would otherwise never heartbeat and would be reported stale purely for being quiet.
    // Beating on this interval means "the select loop is still turning" — but only when a job
    // hasn't reported that same signal more recently: once traffic is flowing, per-job
    // success/failure (below) is the authoritative signal, and this ticker must stand down. If it
    // heartbeat unconditionally on every tick, a route whose every job hits the `Err` arm would
    // still look perfectly healthy — `Health::status` only ever consults `last_err` once
    // `last_ok` is stale, so a heartbeat every `HEALTH_TICK` keeps a permanently failing worker
    // green forever (see `idle_ticker_should_heartbeat`).
    let mut liveness = tokio::time::interval(HEALTH_TICK);
    liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_job_at: Option<Instant> = None;
    // Set on every `Err` from `handle_job`, cleared on the next success. Gates how long the ticker
    // stands down for; see `idle_ticker_should_heartbeat`.
    let mut last_error_at: Option<Instant> = None;
    // A retryable job isn't redispatched the instant its backoff elapses — the pool only scans for
    // ready retries on its own `PRUNE_TICK_INTERVAL` — so the true worst-case gap between attempts
    // is the backoff cap plus that scan period, not `DELIVERY_RETRY_MAX` alone.
    let error_grace_period = crate::pool::DELIVERY_RETRY_MAX + crate::pool::PRUNE_TICK_INTERVAL;
    // `Health::status` ages `last_err` out on its own `PROGRESS_DEADLINE`, independently of this
    // ticker. If that deadline were shorter than our own grace period, a still-retrying route would
    // read `stale` instead of `degraded` right at the tail of a max backoff — catch that drift here
    // rather than let the two constants silently fall out of sync again.
    debug_assert!(
        error_grace_period <= crate::health::PROGRESS_DEADLINE,
        "delivery's worst-case retry gap ({error_grace_period:?}) exceeds the health watchdog's \
         PROGRESS_DEADLINE ({:?}); a still-retrying route can misreport as stale",
        crate::health::PROGRESS_DEADLINE,
    );

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!(chain_key, "🛑 delivery worker exiting on cancel");
                return Ok(());
            }
            _ = liveness.tick() => {
                if idle_ticker_should_heartbeat(
                    last_job_at.map(|t| t.elapsed()),
                    last_error_at.map(|t| t.elapsed()),
                    HEALTH_TICK,
                    error_grace_period,
                ) {
                    health.heartbeat(&health_key);
                }
            }
            maybe = job_rx.recv() => {
                let Some(job) = maybe else {
                    info!(chain_key, "delivery channel closed; worker exiting");
                    return Ok(());
                };
                // Pin the delivery tx to the message's funded gasLimit so the relayer can claim its
                // fee later (the vault only pays when the proven delivery gasLimit matches a funded
                // tier). `None` (no vault, unfunded message, read error, or read timeout) falls back
                // to estimation. The read is bounded by FUNDED_GAS_READ_TIMEOUT: it runs in this
                // serial worker's critical path, so an unbounded await on a stalled source RPC would
                // wedge the whole route (and starve the cancel branch) — the same hazard RECEIPT_TIMEOUT guards.
                let funding = tokio::select! {
                    () = cancel.cancelled() => return Ok(()),
                    funding = async { match (&source_provider, route.relayer_contract_address) {
                    (Some(p), Some(relayer_contract)) if !job.reconcile_only => {
                        match tokio::time::timeout(
                            FUNDED_GAS_READ_TIMEOUT,
                            read_message_funding(p, relayer_contract, job.message_id),
                        ).await {
                            Ok(Ok(f)) => f,
                            Ok(Err(err)) => {
                                warn!(chain_key, message_id = %job.message_id, %err,
                                    "could not read funded gasLimit; falling back to gas estimation (fee may be unclaimable)");
                                MessageFunding::unknown()
                            }
                            Err(_) => {
                                warn!(chain_key, message_id = %job.message_id, timeout_secs = FUNDED_GAS_READ_TIMEOUT.as_secs(),
                                    "funded gasLimit read timed out; falling back to gas estimation (fee may be unclaimable)");
                                MessageFunding::unknown()
                            }
                        }
                    }
                    _ => MessageFunding::unknown(),
                    }} => funding,
                };
                let result = tokio::select! {
                    () = cancel.cancelled() => return Ok(()),
                    result = handle_job(
                    &route,
                    &delivery_config,
                    &provider,
                    signer_address,
                    &broadcast_locks,
                    &job,
                    funding,
                    metrics.as_ref(),
                    top_up.as_mut(),
                    &outcomes,
                    &failed_retries,
                    ) => result,
                };
                let outcome = match result {
                    Ok(outcome) => {
                        // The job ran to a classified business outcome (delivered, terminal, or a
                        // deliberate retryable — e.g. a transport blip `handle_job` already caught
                        // and mapped to `Ok`) — real forward progress for this worker.
                        health.heartbeat(&health_key);
                        last_error_at = None;
                        outcome
                    }
                    Err(err) => {
                        // `handle_job` itself failed unexpectedly, outside the outcomes it already
                        // classifies internally — the same "the iteration ran and failed" signal
                        // `ack`/`claim`/`events` report via `health.error`, not progress.
                        error!(chain_key, message_id = %job.message_id, %err, "❌ delivery job failed");
                        health.error(&health_key);
                        last_error_at = Some(Instant::now());
                        DeliveryResultKind::Retryable
                    }
                };
                last_job_at = Some(Instant::now());
                let sent = tokio::select! {
                    () = cancel.cancelled() => return Ok(()),
                    sent = result_tx.send(DeliveryResult {
                        chain_key: job.chain_key,
                        message_id: job.message_id,
                        outcome,
                    }) => sent,
                };
                if sent.is_err() {
                    warn!(chain_key, "delivery result channel closed; worker exiting");
                    return Ok(());
                }
            }
        }
    }
}

/// Whether the idle-liveness ticker should heartbeat this tick.
///
/// `elapsed_since_last_job` is `None` when no job has been processed yet this run
/// (registration-time silence — the ticker must heartbeat so an idle route is never mistaken for
/// wedged); otherwise the ticker stands down for one `tick_interval` right after *any* job so a
/// busy route lets its own per-job heartbeat/error calls be the authoritative signal instead of
/// being doubled up by this timer.
///
/// `elapsed_since_last_error` is `None` once the worker has never failed, or a job has since
/// succeeded (which clears it directly via its own `health.heartbeat` call); otherwise the ticker
/// keeps standing down until `error_grace_period` has passed with no further failure. A grace
/// period too short would let the ticker resume mid-backoff and refresh `last_ok` while the worker
/// is still actively retrying-and-failing — exactly the masking this gate exists to prevent — so
/// the caller must pass an upper bound on how long a legitimate retry gap can be. That is *not*
/// `pool::DELIVERY_RETRY_MAX` alone: a message only gets redispatched once its backoff has elapsed
/// **and** the pool's own `collect_ready_deliveries` next runs, which happens solely on
/// `pool::PRUNE_TICK_INTERVAL` (not the instant the backoff expires) — so the true worst-case gap is
/// the sum of both. Once genuinely nothing has failed *or* succeeded for that long — the backlog
/// cleared, or the failing message was evicted — the ticker resumes and reports the route
/// healthy-but-idle rather than leaving it permanently wedged in `degraded` over a failure that no
/// longer has anything left to retry.
fn idle_ticker_should_heartbeat(
    elapsed_since_last_job: Option<Duration>,
    elapsed_since_last_error: Option<Duration>,
    tick_interval: Duration,
    error_grace_period: Duration,
) -> bool {
    let past_error_grace =
        elapsed_since_last_error.is_none_or(|elapsed| elapsed >= error_grace_period);
    match elapsed_since_last_job {
        None => true,
        Some(elapsed) => past_error_grace && elapsed >= tick_interval,
    }
}

/// Read a message's funded `gasLimit` from the source `RelayerContract` ledger. `Ok(None)` when the
/// message has no funded route (payer unset / gasLimit 0) or the value is out of sane range, so
/// delivery falls back to estimation; `Err` only on an RPC/transport failure (the caller logs and
/// also falls back).
async fn read_message_funding<P: Provider>(
    source_provider: &P,
    relayer_contract: Address,
    message_id: B256,
) -> Result<MessageFunding> {
    let ledger = IRelayerContract::new(relayer_contract, source_provider);
    let info = ledger
        .getMessageInfo(message_id)
        .call()
        .await
        .context("RelayerContract.getMessageInfo failed")?;

    // Read from the same struct rather than a second call: `deliveryDeadline` and `relaySettled`
    // arrive alongside `gasLimit` and were previously discarded, which is why an unrescuable
    // message could be retried forever at no apparent cost.
    let delivery_deadline = Some(info.deliveryDeadline.saturating_to::<u64>());
    let relay_settled = info.relaySettled;

    if info.gasLimit.is_zero() {
        return Ok(MessageFunding {
            gas: None,
            delivery_deadline,
            relay_settled,
        });
    }
    // Guard against a misconfigured contract address decoding to junk: an absurd gasLimit would
    // otherwise pin an unincludable `.gas()` on every delivery. Ignore it and estimate instead.
    // The other fields decoded from the same junk are not trustworthy either, so drop them too and
    // stay permissive — never terminate a delivery on the strength of a bad read.
    if info.gasLimit > alloy::primitives::U256::from(MAX_FUNDED_GAS) {
        tracing::warn!(%relayer_contract, gas_limit = %info.gasLimit,
            "RelayerContract.getMessageInfo returned an implausible gasLimit; ignoring (will estimate)");
        return Ok(MessageFunding::unknown());
    }
    Ok(MessageFunding {
        gas: Some(info.gasLimit.saturating_to::<u64>()),
        delivery_deadline,
        relay_settled,
    })
}

/// The source-chain fee-ledger state a delivery attempt needs: how much gas is funded, and whether
/// a `topUpGasLimit` could still raise it.
#[derive(Debug, Clone, Copy, Default)]
struct MessageFunding {
    /// Funded `gasLimit` to pin the delivery tx to, when it is non-zero and plausible.
    gas: Option<u64>,
    /// `MessageInfo.deliveryDeadline`, or `None` when the ledger could not be read.
    delivery_deadline: Option<u64>,
    /// `MessageInfo.relaySettled`.
    relay_settled: bool,
}

impl MessageFunding {
    /// Ledger state could not be established (no relayer contract configured, read error, read
    /// timeout, or a junk decode). Deliberately permissive on every field: an unknown ledger must
    /// behave exactly as it did before this tracking existed.
    fn unknown() -> Self {
        Self::default()
    }

    /// Why a `topUpGasLimit` can no longer rescue this message, or `None` if one could still land.
    ///
    /// Both conditions are hard reverts in `RelayerContract._checkTopUp`, so an under-funded
    /// message in either state is undeliverable for good — no amount of retrying changes that.
    fn top_up_foreclosed(&self, now: Option<u64>) -> Option<&'static str> {
        if self.relay_settled {
            // Clock-free and definitive: `_checkTopUp` reverts `RelayAlreadySettled` from here on.
            return Some("relay fee already settled (RelayAlreadySettled)");
        }
        let (deadline, now) = (self.delivery_deadline?, now?);
        let grace = TOP_UP_DEADLINE_GRACE.as_secs();
        (now > deadline.saturating_add(grace))
            .then_some("delivery deadline passed (DeliveryDeadlineReached)")
    }
}

/// Local wall-clock as a unix timestamp, or `None` if the clock is before the epoch — in which case
/// callers stay permissive rather than guessing.
fn now_unix() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

// ---------------------------------------------------------------------------------------------
// requestTopUp (opt-in)
// ---------------------------------------------------------------------------------------------

/// Most `requestTopUp` sends attempted per message before giving up on the signal. Each attempt
/// only happens when the delivery is refused as under-funded again, so this is bounded by the
/// pool's own retry cadence, not a hot loop.
const MAX_TOP_UP_ATTEMPTS: u8 = 3;

/// Per-message state of the `requestTopUp` signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TopUpMark {
    /// A send is in progress (detached task running); do not double-send.
    InFlight { attempts: u8 },
    /// The signal landed (mined), or the contract rejected it deterministically (a top-up could
    /// not help anyway). Nothing more to send for this message.
    Settled,
    /// The last send did not complete (stalled broadcast, receipt error/timeout). Eligible for
    /// another attempt on the next under-funded refusal, up to [`MAX_TOP_UP_ATTEMPTS`].
    Failed { attempts: u8 },
}

/// Idempotency + retry bookkeeping for `requestTopUp`, one entry per message id. Only a mined or
/// deterministically rejected request settles a message; a transport failure leaves it eligible
/// for a bounded retry — recording the id before the send completed meant one timeout suppressed
/// the signal for the life of the process (Bugbot, PR #63). Restarts forget the ledger, so a
/// message still under-funded across a restart is requested again: one duplicate event, harmless.
#[derive(Debug, Default)]
struct TopUpLedger {
    marks: HashMap<B256, TopUpMark>,
}

impl TopUpLedger {
    /// Whether a request for `id` should go out now; if so, marks it in flight and returns the
    /// attempt number (1-based). `Err` names why not.
    fn begin(&mut self, id: B256) -> Result<u8, &'static str> {
        let attempts = match self.marks.get(&id) {
            Some(TopUpMark::InFlight { .. }) => return Err("a request is already in flight"),
            Some(TopUpMark::Settled) => return Err("already requested"),
            Some(TopUpMark::Failed { attempts }) if *attempts >= MAX_TOP_UP_ATTEMPTS => {
                return Err("attempts exhausted")
            }
            Some(TopUpMark::Failed { attempts }) => attempts + 1,
            None => 1,
        };
        self.marks.insert(id, TopUpMark::InFlight { attempts });
        Ok(attempts)
    }

    /// The in-flight request for `id` landed or was deterministically rejected.
    fn settle(&mut self, id: B256) {
        self.marks.insert(id, TopUpMark::Settled);
    }

    /// The in-flight request for `id` did not complete; keep the attempt count for the cap.
    fn fail(&mut self, id: B256) {
        let attempts = match self.marks.get(&id) {
            Some(TopUpMark::InFlight { attempts }) | Some(TopUpMark::Failed { attempts }) => {
                *attempts
            }
            Some(TopUpMark::Settled) => return,
            None => 1,
        };
        self.marks.insert(id, TopUpMark::Failed { attempts });
    }
}

/// Sends `RelayerContract(Lite).requestTopUp(messageId, additionalGasNeeded)` on Creditcoin when a
/// delivery is refused for being under-funded, once per message (retried a bounded number of
/// times only if the send itself failed — see [`TopUpLedger`]). Signed by the route's ack (else
/// claim) key — the same key that already talks to the RelayerContract for `claimDelivery` — and
/// serialized through the shared [`crate::broadcast::BroadcastLocks`] so it cannot race the ack
/// worker for that key's nonce.
///
/// The call is a pure on-chain signal (`TopUpRequested` event; no state change) for the payer /
/// quoter to act on with `topUpGasLimit`. It is permissionless, so whether to send it at all is
/// relayer policy: `ChainRoute::auto_request_top_up`, default off.
struct TopUpRequester {
    provider: DynProvider,
    relayer_contract: Address,
    signer_address: Address,
    broadcast_locks: Arc<crate::broadcast::BroadcastLocks>,
    /// Shared with the detached send tasks, which report their outcome back into it.
    ledger: Arc<Mutex<TopUpLedger>>,
}

impl TopUpRequester {
    async fn connect(
        route: &ChainRoute,
        relayer_contract: Address,
        creditcoin_eth_rpc_url: &str,
        broadcast_locks: Arc<crate::broadcast::BroadcastLocks>,
    ) -> Result<Self> {
        let chain_key = route.chain_key;
        let key = route.top_up_signer_key().with_context(|| {
            format!(
                "chain_key {chain_key}: auto_request_top_up needs an ack or claim signer_key \
                 (validated by config; this is a wiring bug)"
            )
        })?;
        let signer: PrivateKeySigner = key.trim().parse().with_context(|| {
            format!("chain_key {chain_key}: invalid ack/claim signer_key for auto_request_top_up")
        })?;
        let signer_address = signer.address();
        let provider = crate::broadcast::chain_nonce_builder()
            .wallet(EthereumWallet::from(signer))
            .connect(creditcoin_eth_rpc_url)
            .await
            .with_context(|| {
                format!(
                    "chain_key {chain_key}: failed to connect to source EVM RPC at \
                     {creditcoin_eth_rpc_url} (needed for requestTopUp)"
                )
            })?
            .erased();
        info!(
            chain_key,
            signer = %signer_address,
            %relayer_contract,
            "🪙 auto_request_top_up enabled — under-funded deliveries will emit requestTopUp"
        );
        Ok(Self {
            provider,
            relayer_contract,
            signer_address,
            broadcast_locks,
            ledger: Arc::new(Mutex::new(TopUpLedger::default())),
        })
    }

    /// Request a top-up of `additional_gas` for `message_id`, unless one already landed, is in
    /// flight, or the bounded attempt budget is spent. Detached: the send + receipt wait must not
    /// sit in the serial delivery worker's critical path (it is a side signal, not part of
    /// delivering anything). The in-flight mark is taken *before* spawning so a second refusal of
    /// the same message while the first request is still pending does not double-send; the task
    /// reports back so a send that never completed can be retried on the next refusal.
    fn request(&mut self, chain_key: u64, message_id: B256, additional_gas: u64) {
        let attempt = match self
            .ledger
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .begin(message_id)
        {
            Ok(n) => n,
            Err(why) => {
                debug!(chain_key, %message_id, why, "requestTopUp not (re)sent");
                return;
            }
        };
        let locks = self.broadcast_locks.clone();
        let provider = self.provider.clone();
        let relayer_contract = self.relayer_contract;
        let signer_address = self.signer_address;
        let ledger = self.ledger.clone();
        tokio::spawn(async move {
            let landed = send_top_up_request(
                &provider,
                &locks,
                relayer_contract,
                signer_address,
                chain_key,
                message_id,
                additional_gas,
                attempt,
            )
            .await;
            let mut ledger = ledger.lock().unwrap_or_else(|p| p.into_inner());
            if landed {
                ledger.settle(message_id);
            } else {
                ledger.fail(message_id);
            }
        });
    }
}

/// One `requestTopUp` send + receipt wait. `true` when the message is settled from the relayer's
/// point of view (mined, or deterministically rejected so a top-up could not help anyway); `false`
/// when the send did not complete and may be retried.
#[allow(clippy::too_many_arguments)]
async fn send_top_up_request(
    provider: &DynProvider,
    locks: &crate::broadcast::BroadcastLocks,
    relayer_contract: Address,
    signer_address: Address,
    chain_key: u64,
    message_id: B256,
    additional_gas: u64,
    attempt: u8,
) -> bool {
    let ledger = IRelayerContract::new(relayer_contract, provider);
    let call = ledger.requestTopUp(message_id, U256::from(additional_gas));
    let sent = match locks
        .broadcast(signer_address, SEND_TIMEOUT, call.send())
        .await
    {
        Ok(res) => res,
        Err(stalled) => {
            warn!(chain_key, %message_id, attempt, %stalled,
                "requestTopUp send did not complete; will retry on the next under-funded refusal");
            return false;
        }
    };
    match sent {
        Ok(builder) => {
            match tokio::time::timeout(RECEIPT_TIMEOUT, crate::receipt::await_receipt(&builder))
                .await
            {
                Ok(Ok(receipt)) if receipt.status() => {
                    info!(chain_key, %message_id, additional_gas, attempt, tx = %receipt.transaction_hash,
                        "🪙 requestTopUp emitted (TopUpRequested) — awaiting the payer's topUpGasLimit");
                    true
                }
                Ok(Ok(receipt)) => {
                    // Mined and reverted: the same state-dependent rejection as the send-time
                    // revert below; resending would revert identically.
                    warn!(chain_key, %message_id, attempt, tx = %receipt.transaction_hash,
                        "requestTopUp tx mined but reverted; not retrying");
                    true
                }
                Ok(Err(err)) => {
                    warn!(chain_key, %message_id, attempt, %err,
                        "requestTopUp receipt failed; will retry on the next under-funded refusal");
                    false
                }
                Err(_) => {
                    // The tx may still land later (one duplicate TopUpRequested event, harmless).
                    warn!(chain_key, %message_id, attempt,
                        "requestTopUp receipt timed out; will retry on the next under-funded refusal");
                    false
                }
            }
        }
        // A revert here (UnknownOperation / RelayAlreadySettled / DeliveryDeadlineReached) means
        // a top-up could not help anyway; the delivery path reaches the same conclusion through
        // `top_up_foreclosed` on its next pass. A transport failure at send is retryable.
        Err(err) => {
            if is_revert(&err.to_string()) || err.as_revert_data().is_some() {
                warn!(chain_key, %message_id, attempt, %err, "requestTopUp rejected; not retrying");
                true
            } else {
                warn!(chain_key, %message_id, attempt, %err,
                    "requestTopUp send failed; will retry on the next under-funded refusal");
                false
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Revert / receipt classification
// ---------------------------------------------------------------------------------------------

/// What a `deliverMessage` revert means for the job. Selectors are matched node-agnostically
/// (raw revert data, the `data: "0x…"` field Creditcoin-style nodes print, or a decoded name), see
/// [`crate::revert`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeliveryRevert {
    /// The Inbox or the receiver already processed this message — idempotent success (lost a race
    /// to another relayer, or a previous stuck attempt mined).
    Duplicate,
    /// Votes failed validation while native value was attached. Retry with the current committee.
    ValidationFailedWithNativeValue,
    /// The Inbox's dispatcher has no code (value attached). Retry after reconfiguration.
    InvalidMessageDispatcher,
    /// #36: the destination call failed with too little gas to prove the attested `gasLimit` was
    /// forwarded. Retryable with a higher tx gas limit.
    InsufficientGasForDestination,
    /// An unrecognized revert may depend on mutable contract state (pause, allowlists, votes).
    Other,
}

/// Classify an error from a `deliverMessage` simulate / estimate / send. `None` means it is not a
/// contract revert at all (transport, timeout, funds, nonce) and should be retried.
fn classify_delivery_revert(err: &alloy::contract::Error) -> Option<DeliveryRevert> {
    // Structured revert data first (geth-style nodes return it as the JSON-RPC error `data`),
    // then the string dialects.
    let sel = err
        .as_revert_data()
        .filter(|d| d.len() >= 4)
        .map(|d| [d[0], d[1], d[2], d[3]]);
    let s = err.to_string();
    classify_revert_str(&s, sel)
}

/// String-side classification shared by [`classify_delivery_revert`] and the mined-revert replay
/// (whose reason only exists as an error string). `sel` is a selector already extracted from
/// structured revert data, if any; the `data: "0x…"` field of the string is used otherwise.
fn classify_revert_str(s: &str, sel: Option<[u8; 4]>) -> Option<DeliveryRevert> {
    let sel = sel.or_else(|| revert_selector(s));
    let is = |selector: [u8; 4], name: &str| sel == Some(selector) || s.contains(name);

    if revert_duplicate_delivery(&s) {
        return Some(DeliveryRevert::Duplicate);
    }
    if is(
        IInbox::ValidationFailedWithNativeValue::SELECTOR,
        "ValidationFailedWithNativeValue",
    ) {
        return Some(DeliveryRevert::ValidationFailedWithNativeValue);
    }
    if is(
        IInbox::InvalidMessageDispatcher::SELECTOR,
        "InvalidMessageDispatcher",
    ) {
        return Some(DeliveryRevert::InvalidMessageDispatcher);
    }
    if is(
        IMessageDispatcher::InsufficientGasForDestination::SELECTOR,
        "InsufficientGasForDestination",
    ) {
        return Some(DeliveryRevert::InsufficientGasForDestination);
    }
    if is_revert(s) || sel.is_some() {
        return Some(DeliveryRevert::Other);
    }
    None
}

/// Whether a `deliverMessage` error means the inbox already accepted this message (idempotent
/// success — we lost the race to another relayer, or a previous stuck attempt mined).
///
/// Two guards can say so, and both must be matched:
///
///  * the **Inbox** duplicate guard — `MessageAlreadyValidated` on current inboxes, or the deployed
///    `SimpleInbox`'s `require(..., "Already validated")` string revert;
///  * the **receiver** duplicate guard — `MessageReceiverBase.MessageAlreadyProcessed`, which fires
///    when the callback already ran for this messageId. A restart replaying the checkpoint hit this
///    on usc-devnet (2026-09-01): the delivery was long since processed, but because only the Inbox
///    guard was matched here it logged a terminal ERROR and counted as `Reverted`.
///
/// Each is matched three ways because node dialects differ: the revert *string*, the decoded
/// custom-error *name*, and the raw 4-byte *selector* (see [`crate::revert`]).
fn revert_duplicate_delivery(err: &impl std::fmt::Display) -> bool {
    let s = err.to_string();
    let sel = revert_selector(&s);
    s.contains("Already validated")
        || s.contains("MessageAlreadyValidated")
        || sel == Some(IInbox::MessageAlreadyValidated::SELECTOR)
        || s.contains("MessageAlreadyProcessed")
        || sel == Some(IMessageReceiver::MessageAlreadyProcessed::SELECTOR)
}

/// What the logs of a **successful** `deliverMessage` receipt say happened. Precedence matters:
/// `DestinationFailed` is emitted together with `MessageReceived`; only the expected Inbox's
/// `MessageExecuted` for this exact message proves completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiptClass {
    /// An authenticated `MessageExecuted` for the expected message: destination executed.
    Delivered,
    /// `DestinationFailed` + `MessageReceived`: NOT consumed, but also NOT re-deliverable via
    /// `deliverMessage` (Inbox marks it `isRetryable`; a second `deliverMessage` for the same id
    /// reverts `MessageAlreadyValidated`) — retryable via the permissionless `retryFailedMessage`
    /// instead (asc-contracts #54; the old `MessageExecutionFailed` shape this replaces WAS
    /// terminal, so this is a genuine retry-semantics change, not just a rename).
    DestinationFailed { dispatcher: Address },
    /// `MessageQueued` or `MessageDeferred`: dispatcher queued/deferred; `retryPendingMessage`
    /// applies to either (same shape, different topic0 — asc-contracts #54 split the old single
    /// `MessagePending`).
    Pending,
    /// A successful EVM transaction is not itself evidence of message execution.
    Unknown,
}

fn classify_success_logs<'a>(
    inbox: Address,
    message_id: B256,
    logs: impl IntoIterator<Item = &'a Log>,
) -> ReceiptClass {
    let mut pending = false;
    let mut executed = false;
    for log in logs {
        if log.address() != inbox || log.topics().get(1) != Some(&message_id) {
            continue;
        }
        match log.topics().first() {
            Some(t) if *t == IInbox::DestinationFailed::SIGNATURE_HASH => {
                // `dispatcher` is a NON-indexed field on the new 6-field DestinationFailed event
                // (messageId/emitterAddress/destination are indexed; dispatcher/relayer/
                // messagePayload are not) — unlike the retired 3-indexed-arg
                // MessageExecutionFailed, it is NOT at a fixed topic index. A naive
                // `topics().get(2)` here would silently read `destination` instead (same topic
                // count, different field) and misattribute the wrong address. Decode properly.
                let dispatcher = IInbox::DestinationFailed::decode_log(&log.inner)
                    .map(|decoded| decoded.data.dispatcher)
                    .unwrap_or_default();
                return ReceiptClass::DestinationFailed { dispatcher };
            }
            Some(t)
                if *t == IInbox::MessageQueued::SIGNATURE_HASH
                    || *t == IInbox::MessageDeferred::SIGNATURE_HASH =>
            {
                pending = true;
            }
            Some(t) if *t == IInbox::MessageExecuted::SIGNATURE_HASH => {
                executed = IInbox::MessageExecuted::decode_log(&log.inner).is_ok();
            }
            _ => {}
        }
    }
    if pending {
        ReceiptClass::Pending
    } else if executed {
        ReceiptClass::Delivered
    } else {
        ReceiptClass::Unknown
    }
}

/// Next tx gas limit to try after `InsufficientGasForDestination`: 25% over the gas the reverted
/// attempt ran with (or over the attested envelope `gasLimit` when nothing was pinned — the
/// destination needs at least that, plus Inbox/router overhead), never above `cap`. `None` when
/// the cap is already reached (or there is nothing to bump from), i.e. give up.
fn bumped_gas_limit(current: Option<u64>, envelope_gas: Option<u64>, cap: u64) -> Option<u64> {
    let base = current.or(envelope_gas)?;
    if base >= cap {
        return None;
    }
    let bumped = (base.saturating_mul(5) / 4).max(base.saturating_add(1));
    Some(bumped.min(cap))
}

/// Delay before pending-retry `attempt` (0-based). The fixed schedule unless the previous attempt
/// reverted `RetryDeferred(retryAfter)` with a timestamp still in the future — then wait until
/// that moment plus [`RETRY_DEFERRED_MARGIN`], capped by [`MAX_RETRY_DEFERRED_WAIT`]. `retryAfter
/// == 0` (dispatcher exposes no schedule) and past timestamps fall back to the fixed schedule.
pub(crate) fn pending_retry_delay(
    attempt: usize,
    retry_after: Option<u64>,
    now: Option<u64>,
) -> Duration {
    let fixed = PENDING_RETRY_DELAYS[attempt.min(PENDING_RETRY_DELAYS.len() - 1)];
    match (retry_after, now) {
        (Some(ts), Some(now)) if ts > now => {
            (Duration::from_secs(ts - now) + RETRY_DEFERRED_MARGIN).min(MAX_RETRY_DEFERRED_WAIT)
        }
        _ => fixed,
    }
}

/// `Some(retryAfter)` when `err` is a `RetryDeferred(messageId, retryAfter)` revert from
/// `retryPendingMessage` or `retryFailedMessage` (same error, both entrypoints). Structured revert
/// data first, then the `data: "0x…"` field of the error string (Creditcoin-style nodes).
fn decode_retry_deferred(err: &alloy::contract::Error) -> Option<u64> {
    err.as_decoded_error::<IInbox::RetryDeferred>()
        .map(|e| e.retryAfter)
        .or_else(|| decode_retry_deferred_str(&err.to_string()))
}

fn decode_retry_deferred_str(s: &str) -> Option<u64> {
    let data = revert_data(s)?;
    IInbox::RetryDeferred::abi_decode(&data)
        .ok()
        .map(|e| e.retryAfter)
}

// ---------------------------------------------------------------------------------------------
// The job
// ---------------------------------------------------------------------------------------------

/// Where a pre-send check ends: hand back a result, or carry on to the send loop.
enum Stage {
    Done(DeliveryResultKind),
    Proceed,
}

/// Log + count a revert seen before the send (simulate / estimate) and decide the
/// job's fate. `InsufficientGasForDestination` is not terminal — the send loop bumps gas — so it
/// proceeds; everything else that reverts is settled here.
fn settle_pre_send_revert(
    route: &ChainRoute,
    job: &DeliveryJob,
    metrics: &dyn crate::prom::MetricsTrait,
    _outcomes: &OutcomeStore,
    stage: &str,
    revert: DeliveryRevert,
    err: &alloy::contract::Error,
) -> Stage {
    let chain_key = route.chain_key;
    let message_id = job.message_id;
    match revert {
        // Duplicate callers reconcile execution asynchronously; its selector alone proves no completion.
        DeliveryRevert::Duplicate => Stage::Done(DeliveryResultKind::Retryable),
        DeliveryRevert::InsufficientGasForDestination => {
            warn!(chain_key, %message_id, %err,
                "{stage}(deliverMessage) reverted InsufficientGasForDestination; proceeding to send \
                 with a higher gas limit");
            Stage::Proceed
        }
        _ => Stage::Done(retry_delivery_revert(
            route,
            job.message_id,
            metrics,
            Some(revert),
            &format!("{stage}: {}", describe_unknown_revert(err, &job.payload)),
        )),
    }
}

/// A revert proves only that this attempt failed against the current state. Pauses, dispatcher
/// configuration and validator membership can change without changing the publication. Even a
/// seemingly permanent error can be bubbled up by a configurable validator/dispatcher; a selector
/// alone does not prove a bad publication. Keep the work in the pool for capped backoff and fresh
/// votes. Known local policy/funding limits are checked separately before sending.
fn retry_delivery_revert(
    route: &ChainRoute,
    message_id: B256,
    metrics: &dyn crate::prom::MetricsTrait,
    revert: Option<DeliveryRevert>,
    reason: &str,
) -> DeliveryResultKind {
    let chain_key = route.chain_key;
    metrics.inc_deliver_tx(chain_key, revert_status(revert));
    warn!(chain_key, %message_id, ?revert, %reason,
        "delivery reverted; returning to pool for retry after contract state or votes change");
    DeliveryResultKind::Retryable
}

/// Reconcile accepted execution instead of assuming that a duplicate was delivered.
#[allow(clippy::too_many_arguments)]
async fn settle_duplicate_revert<P: Provider + Clone + 'static>(
    provider: &P,
    signer_address: Address,
    broadcast_locks: &Arc<crate::broadcast::BroadcastLocks>,
    route: &ChainRoute,
    message_id: B256,
    outcomes: &Arc<OutcomeStore>,
    failed_retries: &FailedRetries,
    metrics: &dyn crate::prom::MetricsTrait,
) -> DeliveryResultKind {
    let result = reconcile_execution(
        provider,
        signer_address,
        broadcast_locks,
        route,
        message_id,
        outcomes,
        failed_retries,
        metrics,
    )
    .await;
    // A duplicate with no observable execution state is ambiguous, never proof of delivery.
    match result {
        DeliveryResultKind::AwaitingVotes => DeliveryResultKind::Retryable,
        result => result,
    }
}

/// Make an unclassified pre-send revert readable. The RPC's error string carries the revert data
/// when there is any; a `data`-less "execution reverted" from `deliverMessage` means the Inbox
/// reverted before reaching the dispatcher, which since asc-contracts #36 is almost always the
/// envelope decode: the payload is not `abi.encode(address destination, uint256 nativeCoinValue,
/// uint256 gasLimit, bytes payloadData)`. Say so, instead of leaving the operator with
/// "execution reverted" (usc-devnet, 15 Sep 2026: eight such messages, a day of head-scratching).
fn describe_unknown_revert(err: &alloy::contract::Error, payload: &[u8]) -> String {
    // Structured revert data first (geth-style nodes return it as the JSON-RPC error `data`),
    // then the `data: "0x…"` field of the string dialects — the same order as
    // `classify_delivery_revert`.
    let data = err
        .as_revert_data()
        .map(|d| d.to_vec())
        .or_else(|| revert_data(&err.to_string()));
    match data {
        // Decode what we can (Error(string), Panic, the OZ custom errors, our own); an unknown
        // selector still comes out as `custom error 0x… (N bytes)`.
        Some(data) if data.len() >= 4 => crate::dest_revert::describe_revert_data(&data),
        _ => {
            let looks_like_envelope = envelope_terms(payload).gas_limit.is_some();
            if looks_like_envelope {
                "reverted with empty data".to_string()
            } else {
                format!(
                    "reverted with empty data before dispatch; the {}-byte payload does not decode as \
                     the abi.encode(address,uint256,uint256,bytes) envelope the Inbox requires",
                    payload.len()
                )
            }
        }
    }
}

/// Note on liveness: this function deliberately does **not** heartbeat. The caller's tick cannot
/// fire while this future is awaited from inside its `select!` branch, so a job that retries for
/// longer than [`crate::health::PROGRESS_DEADLINE`] does report the route stale. That is the lesser
/// evil: no signal available in here distinguishes "slow but working" from "permanently wedged", so
/// beating per attempt (or per accepted send) could report a dead route as healthy forever, which is
/// the exact failure class the watchdog exists to catch. The stale-local-nonce instance of that is
/// now fixed at the source (see [`crate::broadcast`]), but an underpriced tx still gets *accepted*
/// into the mempool and never mines, so the reasoning stands. See the PR notes: the worst-case job
/// wall time vs. `PROGRESS_DEADLINE` needs settling before a `livenessProbe` is added to the chart,
/// or a slow destination chain will restart pods that are merely waiting.
#[allow(clippy::too_many_arguments)]
async fn handle_job<P: Provider + Clone + 'static>(
    route: &ChainRoute,
    delivery_config: &DeliveryConfig,
    provider: &P,
    signer_address: Address,
    broadcast_locks: &Arc<crate::broadcast::BroadcastLocks>,
    job: &DeliveryJob,
    funding: MessageFunding,
    metrics: &dyn crate::prom::MetricsTrait,
    top_up: Option<&mut TopUpRequester>,
    outcomes: &Arc<OutcomeStore>,
    failed_retries: &FailedRetries,
) -> Result<DeliveryResultKind> {
    let inbox = IInbox::new(route.inbox_address, provider);
    if job.reconcile_only {
        return Ok(reconcile_execution(
            provider,
            signer_address,
            broadcast_locks,
            route,
            job.message_id,
            outcomes,
            failed_retries,
            metrics,
        )
        .await);
    }

    // Since asc-contracts #36/#45 `deliverMessage` is `payable`: the relayer fronts the envelope's
    // `nativeCoinValue` as `msg.value` and recovers it through the fee claim. The router reverts
    // `InvalidNativeCoinValue` if the two differ, so read it from the payload rather than guess.
    // A payload that is not a four-field envelope (legacy dApps, raw bytes) carries no value.
    let terms = envelope_terms(&job.payload);
    let native_value = terms.native_value;
    if native_value > route.max_native_coin_value_wei {
        metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::RefusedNativeValue);
        warn!(
            chain_key = route.chain_key,
            message_id = %job.message_id,
            %native_value,
            cap = %route.max_native_coin_value_wei,
            "envelope asks the relayer to front more native value than the route's \
             max_native_coin_value_wei; refusing (terminal — a quoter/publisher-side limit)"
        );
        outcomes.record(
            job.message_id,
            DeliveryOutcome::new(OutcomeKind::Undeliverable, route.chain_key).with_reason(format!(
                "envelope nativeCoinValue {native_value} wei exceeds the route cap {} wei",
                route.max_native_coin_value_wei
            )),
        );
        return Ok(DeliveryResultKind::Terminal);
    }
    // The router only rejects gasLimit == 0; an attested gasLimit larger than a destination block
    // can hold is undeliverable by anyone, forever. Refuse it now rather than retry an unincludable
    // tx until the pool's LRU evicts it.
    let envelope_gas: Option<u64> = terms.gas_limit.map(|g| g.saturating_to::<u64>());
    if let Some(gas_limit) = terms.gas_limit {
        if gas_limit > U256::from(route.max_gas_limit) {
            metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::RefusedGasLimit);
            error!(
                chain_key = route.chain_key,
                message_id = %job.message_id,
                attested_gas_limit = %gas_limit,
                cap = route.max_gas_limit,
                "❌ envelope's attested gasLimit exceeds the route's max_gas_limit — it can never be \
                 delivered; refusing (terminal). Fix on the publisher/quoter side."
            );
            outcomes.record(
                job.message_id,
                DeliveryOutcome::new(OutcomeKind::Undeliverable, route.chain_key).with_reason(
                    format!(
                        "envelope gasLimit {gas_limit} exceeds the route cap {}",
                        route.max_gas_limit
                    ),
                ),
            );
            return Ok(DeliveryResultKind::Terminal);
        }
    }

    if delivery_config.simulate_before_send {
        // Validity check only — do NOT pin `.gas()` here. The simulate exists to catch
        // `validateVotes` logic reverts; constraining it to the funded gas would conflate an
        // under-funded message (out-of-gas) with a genuine revert and add head-vs-mined-block
        // boundary nondeterminism. Gas is pinned on the real send below.
        let simulation = tokio::time::timeout(
            FUNDED_GAS_READ_TIMEOUT,
            inbox
                .deliverMessage(
                    job.message_id,
                    job.outbox,
                    job.emitter,
                    job.sequence,
                    Bytes::from(job.payload.clone()),
                    Bytes::from(job.votes_calldata.clone()),
                )
                .value(native_value)
                .call(),
        )
        .await;
        let simulation = match simulation {
            Ok(result) => result,
            Err(_) => return Ok(DeliveryResultKind::Retryable),
        };
        if matches!(simulation, Ok(false)) {
            warn!(chain_key = route.chain_key, message_id = %job.message_id,
                "Inbox rejected votes without reverting; retaining work without broadcasting");
            return Ok(DeliveryResultKind::Retryable);
        }
        if let Err(err) = simulation {
            // If the inbox already accepted this message we treat it as success (idempotent —
            // PoC §6.5). Other reverts may be state-dependent; return to the pool
            // without burning gas while the destination is paused or its configuration/committee
            // is changing. Transport failures likewise preserve the message for retry.
            match classify_delivery_revert(&err) {
                Some(DeliveryRevert::Duplicate) => {
                    return Ok(settle_duplicate_revert(
                        provider,
                        signer_address,
                        broadcast_locks,
                        route,
                        job.message_id,
                        outcomes,
                        failed_retries,
                        metrics,
                    )
                    .await);
                }
                Some(revert) => {
                    if let Stage::Done(kind) = settle_pre_send_revert(
                        route, job, metrics, outcomes, "simulate", revert, &err,
                    ) {
                        return Ok(kind);
                    }
                }
                None => {
                    warn!(
                        chain_key = route.chain_key,
                        message_id = %job.message_id,
                        %err,
                        "simulate(deliverMessage) failed at transport level; returning to pool for retry"
                    );
                    return Ok(DeliveryResultKind::Retryable);
                }
            }
        }
    }

    // Under-funding guard. When we have a funded gasLimit, the send is pinned to it (so the proven
    // delivery gasLimit matches the funded tier and `claimDelivery` can pay). But if the message
    // actually needs MORE gas than was funded, pinning would guarantee an out-of-gas revert —
    // burning the relayer's gas for no claimable delivery. Estimate first; if the funded gas can't
    // cover it, don't submit — return non-terminally so the pool retries (leaving a window for a
    // `topUpGasLimit`) rather than dropping a message that becomes deliverable once topped up.
    if let Some(gas) = funding.gas {
        // Bounded like the getMessageInfo read: this estimate sits on the same serial critical
        // path, so an unbounded await on a stalled destination RPC would wedge the route.
        let est = tokio::time::timeout(
            FUNDED_GAS_READ_TIMEOUT,
            inbox
                .deliverMessage(
                    job.message_id,
                    job.outbox,
                    job.emitter,
                    job.sequence,
                    Bytes::from(job.payload.clone()),
                    Bytes::from(job.votes_calldata.clone()),
                )
                .value(native_value)
                .estimate_gas(),
        )
        .await;
        match est {
            Ok(Ok(est)) if est > gas => {
                // Retrying only makes sense while a `topUpGasLimit` could still raise the funded
                // gas. Once the delivery deadline has passed or the relay fee is settled, a top-up
                // reverts, so the message is undeliverable for good and the retry is pure waste —
                // observed on usc-devnet as one message retried 469 times over 2.5 days, holding
                // `pool_messages_pending` at 1 the whole time and drowning the stuck-pool signal.
                if let Some(reason) = funding.top_up_foreclosed(now_unix()) {
                    warn!(
                        chain_key = route.chain_key,
                        message_id = %job.message_id,
                        estimate = est,
                        funded = gas,
                        reason,
                        "delivery is under-funded and can no longer be topped up — giving up. The \
                         funded gasLimit was set at publish time and cannot now be raised; this \
                         needs fixing on the publisher/quoter side, not here."
                    );
                    outcomes.record(
                        job.message_id,
                        DeliveryOutcome::new(OutcomeKind::Terminal, route.chain_key).with_reason(
                            format!(
                                "under-funded: estimate {est} > funded gasLimit {gas}, top-up no \
                                 longer possible ({reason})"
                            ),
                        ),
                    );
                    return Ok(DeliveryResultKind::Terminal);
                }
                let additional = est.saturating_sub(gas);
                warn!(
                    chain_key = route.chain_key,
                    message_id = %job.message_id,
                    estimate = est,
                    funded = gas,
                    additional_gas_needed = additional,
                    auto_request_top_up = top_up.is_some(),
                    "delivery is under-funded — estimated gas exceeds the funded gasLimit; not \
                     delivering (awaiting a topUpGasLimit). Retrying with backoff."
                );
                // Opt-in: tell the payer/quoter on-chain how much more gas is needed, once.
                if let Some(requester) = top_up {
                    requester.request(route.chain_key, job.message_id, additional);
                }
                return Ok(DeliveryResultKind::Retryable);
            }
            // Funded gas covers the estimate — proceed to send pinned at the funded gas.
            Ok(Ok(_)) => {}
            // The estimate itself failed. Classify like the simulate does: when
            // `simulate_before_send` is off, this is where a state-dependent revert first surfaces.
            // Return recoverable failures to the pool rather than sending an unverified attempt
            // or permanently discarding a publication during a temporary contract-state change.
            Ok(Err(err)) => match classify_delivery_revert(&err) {
                Some(DeliveryRevert::Duplicate) => {
                    return Ok(settle_duplicate_revert(
                        provider,
                        signer_address,
                        broadcast_locks,
                        route,
                        job.message_id,
                        outcomes,
                        failed_retries,
                        metrics,
                    )
                    .await);
                }
                Some(revert) => {
                    if let Stage::Done(kind) = settle_pre_send_revert(
                        route, job, metrics, outcomes, "estimate", revert, &err,
                    ) {
                        return Ok(kind);
                    }
                }
                None => {
                    warn!(
                        chain_key = route.chain_key,
                        message_id = %job.message_id,
                        %err,
                        "could not estimate delivery gas to verify funding (transport); retrying \
                         rather than risking an out-of-gas send on a possibly under-funded message"
                    );
                    return Ok(DeliveryResultKind::Retryable);
                }
            },
            Err(_elapsed) => {
                warn!(
                    chain_key = route.chain_key,
                    message_id = %job.message_id,
                    timeout_secs = FUNDED_GAS_READ_TIMEOUT.as_secs(),
                    "gas estimate timed out; retrying rather than risking an out-of-gas send"
                );
                return Ok(DeliveryResultKind::Retryable);
            }
        }
    }

    metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::Submitted);
    let started = Instant::now();

    let mut backoff = INITIAL_BACKOFF;
    let mut attempts = 0u32;
    // Gas the send is pinned to: the funded gasLimit when known (so the fee is claimable), else
    // the node's estimate. Raised in 25% steps — up to `route.max_gas_limit` — when an attempt
    // reverts `InsufficientGasForDestination` (#36: the destination failed AND the tx gas was too
    // low to prove the attested gasLimit was forwarded, so the failure may be ours to fix).
    let mut gas_limit: Option<u64> = funding.gas;
    let outcome = loop {
        attempts += 1;
        let mut tx = inbox
            .deliverMessage(
                job.message_id,
                job.outbox,
                job.emitter,
                job.sequence,
                Bytes::from(job.payload.clone()),
                Bytes::from(job.votes_calldata.clone()),
            )
            .value(native_value);
        if let Some(gas) = gas_limit {
            tx = tx.gas(gas);
        }
        // A pinned gas limit bypasses the wallet's estimate. Check that exact limit before
        // spending it, including every bump and every later pool retry. Otherwise reaching the
        // cap once would repeatedly restart the same sequence of paid, reverting transactions.
        // Keep failed work retryable: a dispatcher/configuration change can make it executable.
        // Also decode the Inbox's boolean result when unpinned: estimation accepts a successful
        // EVM call returning false, but paying for that transaction would never deliver anything.
        let preflight = match tokio::time::timeout(
            FUNDED_GAS_READ_TIMEOUT,
            tx.clone().from(signer_address).call(),
        )
        .await
        {
            Ok(Ok(true)) => None,
            Ok(Ok(false)) => break SendOutcome::Failed("Inbox rejected votes in preflight".into()),
            Ok(Err(err)) => Some(Err(err)),
            Err(_) => break SendOutcome::Failed("delivery preflight timed out".into()),
        };
        // `send()` is several RPC round trips (gas, fee, nonce, `eth_sendRawTransaction`) and alloy's
        // HTTP transport sets no timeout, so on a black-holed endpoint this await never returns and
        // parks the route — the same hazard FUNDED_GAS_READ_TIMEOUT and RECEIPT_TIMEOUT guard.
        //
        // Serialized on the signer so the chain-read nonce this send is about to fetch already
        // reflects every earlier broadcast from the same key, including supervised execution
        // retries and the set-update submitter. The guard covers only the
        // broadcast; the receipt is awaited below, outside it, or a single confirmation would block
        // every other sender on the key. Either stall is retryable and consumes no nonce.
        let pending = if let Some(result) = preflight {
            result
        } else {
            match broadcast_locks
                .broadcast(signer_address, SEND_TIMEOUT, tx.send())
                .await
            {
                Ok(res) => res,
                Err(stalled) => {
                    if attempts <= delivery_config.max_retries {
                        warn!(
                            chain_key = route.chain_key,
                            message_id = %job.message_id,
                            attempts,
                            %stalled,
                            "send did not complete; retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        continue;
                    }
                    break SendOutcome::Failed(stalled.to_string());
                }
            }
        };

        match pending {
            // Poll-based receipt wait — alloy's `get_receipt()` heartbeat wedges against
            // Frontier's mixHash-less blocks (see the `receipt` module docs). Sepolia is fine
            // today, but routes are chain-agnostic and a Frontier destination would not be.
            Ok(builder) => {
                match tokio::time::timeout(RECEIPT_TIMEOUT, crate::receipt::await_receipt(&builder))
                    .await
                {
                    Ok(Ok(receipt)) => {
                        if receipt.status() {
                            // `deliverMessage` succeeds even when the destination does not
                            // execute: the Inbox emits `MessageQueued`/`MessageDeferred`
                            // (deferred/queued — stored for `retryPendingMessage`) or, since
                            // asc-contracts #54, `DestinationFailed` alongside `MessageReceived`
                            // (destination call failed, message NOT consumed — retryable via
                            // `retryFailedMessage`). Both are detected from the receipt logs, not a
                            // revert.
                            break match classify_success_logs(
                                route.inbox_address,
                                job.message_id,
                                receipt.inner.logs(),
                            ) {
                                ReceiptClass::Unknown => SendOutcome::Failed(
                                    "receipt has no execution-state event for this message".into(),
                                ),
                                ReceiptClass::Delivered => SendOutcome::Succeeded {
                                    tx_hash: receipt.transaction_hash,
                                },
                                ReceiptClass::Pending => SendOutcome::Pending {
                                    tx_hash: receipt.transaction_hash,
                                },
                                ReceiptClass::DestinationFailed { dispatcher } => {
                                    SendOutcome::DestinationFailed {
                                        dispatcher,
                                        tx_hash: receipt.transaction_hash,
                                        block_number: receipt.block_number,
                                    }
                                }
                            };
                        }
                        // Mined but reverted. Replay the exact call at that block to learn why: an
                        // `InsufficientGasForDestination` is ours to fix by resending with more gas;
                        // a duplicate means another relayer's tx landed in the same block (success);
                        // other reverts return to the pool because contract state may change.
                        let (class, reason) = replay_revert_reason(
                            &inbox,
                            job,
                            native_value,
                            gas_limit,
                            receipt.block_number,
                        )
                        .await
                        .unwrap_or_else(|| (None, "tx mined but reverted".into()));
                        match class {
                            Some(DeliveryRevert::Duplicate) => break SendOutcome::AlreadyValidated,
                            Some(DeliveryRevert::InsufficientGasForDestination)
                                if attempts <= delivery_config.max_retries =>
                            {
                                match bumped_gas_limit(gas_limit, envelope_gas, route.max_gas_limit)
                                {
                                    Some(next) => {
                                        warn!(
                                            chain_key = route.chain_key,
                                            message_id = %job.message_id,
                                            attempts,
                                            tx = %receipt.transaction_hash,
                                            previous_gas = ?gas_limit,
                                            next_gas = next,
                                            cap = route.max_gas_limit,
                                            funded = ?funding.gas,
                                            "delivery reverted InsufficientGasForDestination; \
                                             retrying with more gas (above the funded gasLimit the \
                                             fee may be unclaimable)"
                                        );
                                        gas_limit = Some(next);
                                    }
                                    None => {
                                        break SendOutcome::Reverted {
                                            revert: class,
                                            reason: format!(
                                                "InsufficientGasForDestination at the route's \
                                                 max_gas_limit ({}): {reason}",
                                                route.max_gas_limit
                                            ),
                                        };
                                    }
                                }
                            }
                            _ => {
                                break SendOutcome::Reverted {
                                    revert: class,
                                    reason,
                                }
                            }
                        }
                    }
                    Ok(Err(err)) if attempts <= delivery_config.max_retries => {
                        warn!(
                            chain_key = route.chain_key,
                            message_id = %job.message_id,
                            attempts,
                            %err,
                            "receipt fetch failed; retrying"
                        );
                    }
                    Ok(Err(err)) => break SendOutcome::Failed(format!("receipt: {err}")),
                    Err(_elapsed) => {
                        // Stuck / underpriced tx: stop blocking the route. The pool retries with
                        // backoff; if this tx mines meanwhile, the next simulate resolves it as
                        // already-validated.
                        break SendOutcome::Failed(format!(
                            "no receipt within {RECEIPT_TIMEOUT:?} (tx possibly stuck)"
                        ));
                    }
                }
            }
            Err(err) => match classify_delivery_revert(&err) {
                // Lost the race to another relayer (PoC §6.5). Treat as success.
                Some(DeliveryRevert::Duplicate) => break SendOutcome::AlreadyValidated,
                // Surfaced at the node's gas estimation (nothing pinned): resend pinned higher.
                Some(DeliveryRevert::InsufficientGasForDestination)
                    if attempts <= delivery_config.max_retries =>
                {
                    match bumped_gas_limit(gas_limit, envelope_gas, route.max_gas_limit) {
                        Some(next) => {
                            warn!(
                                chain_key = route.chain_key,
                                message_id = %job.message_id,
                                attempts,
                                previous_gas = ?gas_limit,
                                next_gas = next,
                                cap = route.max_gas_limit,
                                "send reverted InsufficientGasForDestination; retrying with more gas"
                            );
                            gas_limit = Some(next);
                        }
                        None => {
                            break SendOutcome::Reverted {
                                revert: Some(DeliveryRevert::InsufficientGasForDestination),
                                reason: format!(
                                    "InsufficientGasForDestination at the route's max_gas_limit ({}): {err}",
                                    route.max_gas_limit
                                ),
                            };
                        }
                    }
                }
                // Contract revert at send / gas-estimation time. Hand it back to the pool
                // instead of burning worker retries against unchanged contract state. The class
                // also preserves specific metric labels for configuration and validation errors.
                Some(revert) => {
                    break SendOutcome::Reverted {
                        revert: Some(revert),
                        reason: revert_summary(revert, &err),
                    }
                }
                None if attempts <= delivery_config.max_retries => {
                    warn!(
                        chain_key = route.chain_key,
                        message_id = %job.message_id,
                        attempts,
                        backoff_ms = backoff.as_millis() as u64,
                        %err,
                        "send failed; retrying"
                    );
                }
                None => break SendOutcome::Failed(err.to_string()),
            },
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    };

    match outcome {
        SendOutcome::Succeeded { tx_hash } => {
            metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::Succeeded);
            metrics.observe_time_to_deliver(started.elapsed());
            info!(
                chain_key = route.chain_key,
                message_id = %job.message_id,
                tx = %tx_hash,
                signer_count = job.signer_count,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "✅ message delivered"
            );
            outcomes.record(
                job.message_id,
                DeliveryOutcome::new(
                    if route.block_confirmation_depth == 0 {
                        OutcomeKind::Delivered
                    } else {
                        OutcomeKind::Pending
                    },
                    route.chain_key,
                )
                .with_tx(tx_hash),
            );
            Ok(if route.block_confirmation_depth == 0 {
                DeliveryResultKind::Delivered
            } else {
                DeliveryResultKind::AwaitingExecution { retry_after: None }
            })
        }
        SendOutcome::DestinationFailed {
            dispatcher,
            tx_hash,
            block_number,
        } => {
            // asc-contracts #54: DestinationFailed does NOT set processedAt — the messageId is not
            // consumed — but it also does NOT leave the message re-deliverable via deliverMessage:
            // Inbox now marks it isRetryable and a second deliverMessage for the same id reverts
            // MessageAlreadyValidated. The permissionless retryFailedMessage takes over instead
            // (no fresh votes needed). The pool retains ownership until execution succeeds.
            // MessageReceived still fired, so fee settlement remains independent of execution.
            metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::DestinationFailed);
            metrics.observe_time_to_deliver(started.elapsed());
            // The receipt does not say why the dApp reverted (the dispatcher swallowed the revert
            // bytes), so replay the destination call at the delivery block and decode what comes
            // back. Best-effort and bounded: a silent RPC leaves the reason at the generic text.
            let detail = tokio::time::timeout(
                FUNDED_GAS_READ_TIMEOUT,
                crate::dest_revert::probe_destination_revert(
                    provider,
                    dispatcher,
                    job.emitter,
                    &job.payload,
                    block_number,
                ),
            )
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "revert reason not recoverable (replay failed or timed out)".into());
            warn!(
                chain_key = route.chain_key,
                message_id = %job.message_id,
                %dispatcher,
                tx = %tx_hash,
                revert = %detail,
                signer_count = job.signer_count,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "⚠️ destination call FAILED (DestinationFailed) — not consumed on-chain; \
                 retaining work for supervised retryFailedMessage"
            );
            outcomes.record(
                job.message_id,
                DeliveryOutcome::new(OutcomeKind::DestinationFailed, route.chain_key)
                    .with_tx(tx_hash)
                    .with_reason(format!(
                        "DestinationFailed (dispatcher {dispatcher}): {detail}; \
                         retryFailedMessage scheduled"
                    )),
            );
            let state = failed_retries
                .start(
                    job.message_id,
                    &route.failed_retry,
                    now_unix().unwrap_or_default(),
                )
                .await;
            if state.attempts >= route.failed_retry.max_attempts {
                return Ok(give_up_failed_retries(
                    route,
                    job.message_id,
                    state,
                    failed_retries,
                    outcomes,
                    metrics,
                )
                .await);
            }
            Ok(DeliveryResultKind::AwaitingExecution {
                retry_after: Some(state.next_attempt_at),
            })
        }
        SendOutcome::AlreadyValidated => {
            metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::AlreadyValidated);
            Ok(settle_duplicate_revert(
                provider,
                signer_address,
                broadcast_locks,
                route,
                job.message_id,
                outcomes,
                failed_retries,
                metrics,
            )
            .await)
        }
        SendOutcome::Pending { tx_hash } => {
            metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::Pending);
            warn!(
                chain_key = route.chain_key,
                message_id = %job.message_id,
                "⚠️ votes validated but the dispatcher deferred/queued the message — left pending; \
                 retaining work for supervised retryPendingMessage"
            );
            outcomes.record(
                job.message_id,
                DeliveryOutcome::new(OutcomeKind::Pending, route.chain_key)
                    .with_tx(tx_hash)
                    .with_reason(
                        "dispatcher queued/deferred the message (MessageQueued/MessageDeferred)",
                    ),
            );
            Ok(DeliveryResultKind::AwaitingExecution { retry_after: None })
        }
        SendOutcome::Reverted { revert, reason } => Ok(retry_delivery_revert(
            route,
            job.message_id,
            metrics,
            revert,
            &reason,
        )),
        SendOutcome::Failed(err_str) => {
            metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::Reverted);
            warn!(
                chain_key = route.chain_key,
                message_id = %job.message_id,
                err = %err_str,
                "send exhausted delivery worker retries; returning to pool for bounded retry"
            );
            Ok(DeliveryResultKind::Retryable)
        }
    }
}

/// The `relayer_deliver_tx` label for a revert, whichever stage surfaced it (simulate,
/// estimate, send, or the mined-revert replay). The #36 hard failures get their own series; a
/// revert `classify_delivery_revert` could not recognize gets `Unclassified` (distinct from the
/// generic `Reverted`, which also covers `InsufficientGasForDestination` and non-revert failures —
/// see the label's doc) so a new node-dialect revert shape is visible as its own series rather than
/// hiding inside `Reverted`. Single source of truth so the send-time path cannot drift from the
/// pre-send one (Bugbot, PR #63).
fn revert_status(revert: Option<DeliveryRevert>) -> DeliveryStatus {
    match revert {
        Some(DeliveryRevert::ValidationFailedWithNativeValue) => {
            DeliveryStatus::ValidationFailedWithNativeValue
        }
        Some(DeliveryRevert::InvalidMessageDispatcher) => DeliveryStatus::InvalidDispatcher,
        Some(DeliveryRevert::Duplicate) => DeliveryStatus::AlreadyValidated,
        Some(DeliveryRevert::Other) => DeliveryStatus::Unclassified,
        Some(DeliveryRevert::InsufficientGasForDestination) | None => DeliveryStatus::Reverted,
    }
}

/// Human-readable reason for a send-time revert, naming the #36 errors that would
/// otherwise only show as a selector on Creditcoin-style nodes.
fn revert_summary(revert: DeliveryRevert, err: &alloy::contract::Error) -> String {
    match revert {
        DeliveryRevert::ValidationFailedWithNativeValue => {
            format!("ValidationFailedWithNativeValue (votes invalid, value attached): {err}")
        }
        DeliveryRevert::InvalidMessageDispatcher => {
            format!("InvalidMessageDispatcher (Inbox dispatcher has no code): {err}")
        }
        DeliveryRevert::InsufficientGasForDestination => {
            format!("InsufficientGasForDestination (retry budget exhausted): {err}")
        }
        DeliveryRevert::Duplicate | DeliveryRevert::Other => err.to_string(),
    }
}

/// Replay a mined-but-reverted `deliverMessage` as an `eth_call` at the block it mined in, with the
/// same `msg.value` and gas, to recover the revert reason the receipt does not carry. Returns the
/// classification made from the *structured* error (selector from `as_revert_data()` first, the
/// string dialects second — geth-style nodes put the selector only in the JSON-RPC error `data`,
/// which a plain `to_string()` does not reliably carry; Bugbot, PR #63) plus the printable reason.
/// Best-effort and bounded: `None` when the replay succeeds (state moved on) or cannot be made in
/// time — the caller keeps the message retryable rather than treating missing evidence as a
/// permanent publication failure.
async fn replay_revert_reason<P: Provider>(
    inbox: &IInbox::IInboxInstance<P>,
    job: &DeliveryJob,
    native_value: U256,
    gas_limit: Option<u64>,
    block_number: Option<u64>,
) -> Option<(Option<DeliveryRevert>, String)> {
    let mut call = inbox
        .deliverMessage(
            job.message_id,
            job.outbox,
            job.emitter,
            job.sequence,
            Bytes::from(job.payload.clone()),
            Bytes::from(job.votes_calldata.clone()),
        )
        .value(native_value);
    if let Some(gas) = gas_limit {
        call = call.gas(gas);
    }
    if let Some(n) = block_number {
        call = call.block(BlockId::number(n));
    }
    match tokio::time::timeout(FUNDED_GAS_READ_TIMEOUT, call.call()).await {
        Ok(Err(err)) => Some((classify_delivery_revert(&err), err.to_string())),
        Ok(Ok(_)) => None,
        Err(_elapsed) => None,
    }
}

#[derive(Debug)]
enum SendOutcome {
    Succeeded {
        tx_hash: B256,
    },
    AlreadyValidated,
    /// Tx succeeded but the receipt carries `MessageQueued`/`MessageDeferred` — the dispatcher
    /// deferred/queued the message and it is stored for `retryPendingMessage`.
    Pending {
        tx_hash: B256,
    },
    /// Tx succeeded and the receipt carries `DestinationFailed` (asc-contracts #54): the
    /// destination call failed, but the message is NOT consumed — retryable via
    /// `retryFailedMessage`. `block_number` is where it mined, so the destination call can be
    /// replayed against that state to learn *why* it failed.
    DestinationFailed {
        dispatcher: Address,
        tx_hash: B256,
        block_number: Option<u64>,
    },
    /// Deterministic revert (mined-and-reverted, or revert at send/estimation time). `revert` is
    /// the classification when one was possible; it selects the metric label.
    Reverted {
        revert: Option<DeliveryRevert>,
        reason: String,
    },
    /// Transient infrastructure failure — returned to the pool's bounded retry.
    Failed(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutionState {
    Executed,
    Confirming,
    Pending,
    Failed,
    Unaccepted,
}

/// One supervised execution attempt. The pool owns durable retention and scheduling. All RPCs
/// are bounded; accepted work survives outages, gas-cap refusals and destination reorganizations.
/// `retryFailedMessage` additionally goes through `failed_retries`: it is only sent once its
/// backoff has elapsed, and the work is given up (`Terminal`) once the route's budget is spent.
#[allow(clippy::too_many_arguments)]
async fn reconcile_execution<P: Provider>(
    provider: &P,
    signer_address: Address,
    broadcast_locks: &Arc<crate::broadcast::BroadcastLocks>,
    route: &ChainRoute,
    message_id: B256,
    outcomes: &OutcomeStore,
    failed_retries: &FailedRetries,
    metrics: &dyn crate::prom::MetricsTrait,
) -> DeliveryResultKind {
    let chain_key = route.chain_key;
    let inbox_address = route.inbox_address;
    let inbox = IInbox::new(inbox_address, provider);
    let retry = DeliveryResultKind::AwaitingExecution { retry_after: None };
    let state = tokio::time::timeout(FUNDED_GAS_READ_TIMEOUT, async {
        let processed_at = inbox.processedAt(message_id).call().await?;
        if !processed_at.is_zero() {
            if route.block_confirmation_depth > 0 {
                let tip = provider.get_block_number().await?;
                let confirmed = tip.saturating_sub(route.block_confirmation_depth);
                if processed_at > U256::from(confirmed) {
                    return Ok::<_, anyhow::Error>(ExecutionState::Confirming);
                }
                // Latest-state and head reads can straddle a reorg. Require the execution in
                // the explicit confirmed block state before deleting its durable publication.
                if inbox
                    .processedAt(message_id)
                    .block(BlockId::number(confirmed))
                    .call()
                    .await?
                    .is_zero()
                {
                    return Ok(ExecutionState::Confirming);
                }
            }
            return Ok(ExecutionState::Executed);
        }
        if inbox.isPending(message_id).call().await? {
            return Ok(ExecutionState::Pending);
        }
        if inbox.isRetryable(message_id).call().await? {
            return Ok(ExecutionState::Failed);
        }
        Ok(ExecutionState::Unaccepted)
    })
    .await;
    let state = match state {
        Ok(Ok(ExecutionState::Executed)) => {
            failed_retries.forget(message_id).await;
            outcomes.record(
                message_id,
                DeliveryOutcome::new(OutcomeKind::Delivered, chain_key).with_reason(
                    "Inbox processedAt confirms execution at the configured confirmation depth",
                ),
            );
            return DeliveryResultKind::Delivered;
        }
        Ok(Ok(ExecutionState::Confirming)) => return retry,
        Ok(Ok(ExecutionState::Unaccepted)) => return DeliveryResultKind::AwaitingVotes,
        Ok(Ok(state)) => state,
        Ok(Err(err)) => {
            warn!(chain_key, %message_id, %err, "execution-state read failed; retaining work");
            return DeliveryResultKind::Retryable;
        }
        Err(_) => {
            warn!(chain_key, %message_id, "execution-state read timed out; retaining work");
            return DeliveryResultKind::Retryable;
        }
    };
    let pending = state == ExecutionState::Pending;
    // Bound only the failed-destination path: a pending (queued/deferred) message is waiting on the
    // dispatcher, not reverting, and keeps the existing `RetryDeferred`-driven schedule.
    if !pending {
        match failed_retries
            .gate(
                message_id,
                &route.failed_retry,
                now_unix().unwrap_or_default(),
            )
            .await
        {
            Gate::Proceed => {}
            Gate::Wait(at) => {
                return DeliveryResultKind::AwaitingExecution {
                    retry_after: Some(at),
                }
            }
            Gate::GiveUp(state) => {
                return give_up_failed_retries(
                    route,
                    message_id,
                    state,
                    failed_retries,
                    outcomes,
                    metrics,
                )
                .await
            }
        }
    }
    let estimate = tokio::time::timeout(FUNDED_GAS_READ_TIMEOUT, async {
        if pending {
            inbox
                .retryPendingMessage(message_id)
                .from(signer_address)
                .estimate_gas()
                .await
        } else {
            inbox
                .retryFailedMessage(message_id)
                .from(signer_address)
                .estimate_gas()
                .await
        }
    })
    .await;
    let gas = match estimate {
        Ok(Ok(gas)) if gas <= route.max_gas_limit => {
            gas.saturating_add(gas / 4).min(route.max_gas_limit)
        }
        Ok(Ok(gas)) => {
            warn!(chain_key, %message_id, gas, cap = route.max_gas_limit,
                "execution retry exceeds the route gas cap; retaining work");
            return retry;
        }
        Ok(Err(err)) => {
            return DeliveryResultKind::AwaitingExecution {
                retry_after: decode_retry_deferred(&err),
            }
        }
        Err(_) => return retry,
    };
    // Pin and preflight the exact gas limit so a low estimate or changing dispatcher cannot
    // repeatedly burn the cap on known-reverting retries. Stored native value is not fronted again.
    let preflight = tokio::time::timeout(FUNDED_GAS_READ_TIMEOUT, async {
        if pending {
            inbox
                .retryPendingMessage(message_id)
                .from(signer_address)
                .gas(gas)
                .call()
                .await
                .map(|_| ())
        } else {
            inbox
                .retryFailedMessage(message_id)
                .from(signer_address)
                .gas(gas)
                .call()
                .await
                .map(|_| ())
        }
    })
    .await;
    match preflight {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            return DeliveryResultKind::AwaitingExecution {
                retry_after: decode_retry_deferred(&err),
            }
        }
        Err(_) => return retry,
    }
    let sent = broadcast_locks
        .broadcast(signer_address, SEND_TIMEOUT, async {
            if pending {
                inbox
                    .retryPendingMessage(message_id)
                    .from(signer_address)
                    .gas(gas)
                    .send()
                    .await
            } else {
                inbox
                    .retryFailedMessage(message_id)
                    .from(signer_address)
                    .gas(gas)
                    .send()
                    .await
            }
        })
        .await;
    let builder = match sent {
        Ok(Ok(builder)) => builder,
        Ok(Err(err)) => {
            return DeliveryResultKind::AwaitingExecution {
                retry_after: decode_retry_deferred(&err),
            }
        }
        Err(err) => {
            warn!(chain_key, %message_id, %err, "execution retry broadcast timed out; retaining work");
            // The tx may still have reached the node; count it so ambiguity cannot be unbounded.
            if !pending {
                let spent = failed_retries
                    .record_attempt(
                        message_id,
                        &route.failed_retry,
                        now_unix().unwrap_or_default(),
                    )
                    .await;
                return after_failed_retry(
                    route,
                    message_id,
                    spent,
                    None,
                    failed_retries,
                    outcomes,
                    metrics,
                )
                .await;
            }
            return retry;
        }
    };
    // Count the attempt as soon as the node accepted it, before the receipt wait: a crash or a
    // receipt timeout must not forget gas that is (about to be) spent.
    let spent = if pending {
        None
    } else {
        Some(
            failed_retries
                .record_attempt(
                    message_id,
                    &route.failed_retry,
                    now_unix().unwrap_or_default(),
                )
                .await,
        )
    };
    // Whether the destination is still failing after this attempt (as opposed to executed or
    // handed to the dispatcher's queue), i.e. whether the attempt counts against the budget.
    let mut failed_again = true;
    // The receipt carried `DestinationFailed`. After a `retryPendingMessage` this is where the
    // failed-destination schedule starts.
    let mut destination_failed = false;
    let result = match tokio::time::timeout(
        RECEIPT_TIMEOUT,
        crate::receipt::await_receipt(&builder),
    )
    .await
    {
        Ok(Ok(receipt)) if receipt.status() => {
            let (kind, result) =
                match classify_success_logs(inbox_address, message_id, receipt.inner.logs()) {
                    ReceiptClass::Delivered if route.block_confirmation_depth == 0 => {
                        (Some(OutcomeKind::Delivered), DeliveryResultKind::Delivered)
                    }
                    ReceiptClass::Delivered | ReceiptClass::Pending => {
                        (Some(OutcomeKind::Pending), retry)
                    }
                    ReceiptClass::DestinationFailed { .. } => {
                        (Some(OutcomeKind::DestinationFailed), retry)
                    }
                    ReceiptClass::Unknown => (None, retry),
                };
            if let Some(kind) = kind {
                destination_failed = kind == OutcomeKind::DestinationFailed;
                failed_again = destination_failed;
                let reason = match spent {
                    Some(spent) if failed_again => format!(
                        "retryFailedMessage attempt {}/{} hit DestinationFailed again",
                        spent.attempts, route.failed_retry.max_attempts
                    ),
                    _ => "execution retry observed; completion follows configured confirmations"
                        .into(),
                };
                outcomes.record(
                    message_id,
                    DeliveryOutcome::new(kind, chain_key)
                        .with_tx(receipt.transaction_hash)
                        .with_reason(reason),
                );
            }
            if result == DeliveryResultKind::Delivered {
                failed_retries.forget(message_id).await;
            }
            result
        }
        Ok(Ok(receipt)) => {
            let retry_after = tokio::time::timeout(FUNDED_GAS_READ_TIMEOUT, async {
                let block = receipt
                    .block_number
                    .map(BlockId::number)
                    .unwrap_or_default();
                let replay = if pending {
                    inbox
                        .retryPendingMessage(message_id)
                        .from(signer_address)
                        .gas(gas)
                        .block(block)
                        .call()
                        .await
                        .map(|_| ())
                } else {
                    inbox
                        .retryFailedMessage(message_id)
                        .from(signer_address)
                        .gas(gas)
                        .block(block)
                        .call()
                        .await
                        .map(|_| ())
                };
                replay.err().and_then(|err| decode_retry_deferred(&err))
            })
            .await
            .ok()
            .flatten();
            DeliveryResultKind::AwaitingExecution { retry_after }
        }
        _ => retry,
    };
    match spent {
        Some(spent) if failed_again => {
            let hint = match result {
                DeliveryResultKind::AwaitingExecution { retry_after } => retry_after,
                _ => None,
            };
            after_failed_retry(
                route,
                message_id,
                spent,
                hint,
                failed_retries,
                outcomes,
                metrics,
            )
            .await
        }
        None if destination_failed => {
            // Queued/deferred dispatch ran and the destination call failed: from here on the
            // message is `isRetryable`, so its first `retryFailedMessage` waits like any other.
            let state = failed_retries
                .start(
                    message_id,
                    &route.failed_retry,
                    now_unix().unwrap_or_default(),
                )
                .await;
            if state.attempts >= route.failed_retry.max_attempts {
                return give_up_failed_retries(
                    route,
                    message_id,
                    state,
                    failed_retries,
                    outcomes,
                    metrics,
                )
                .await;
            }
            DeliveryResultKind::AwaitingExecution {
                retry_after: Some(state.next_attempt_at),
            }
        }
        _ => result,
    }
}

/// A `retryFailedMessage` was spent and the destination is (or may be) still failing: give up if
/// that was the last allowed attempt, otherwise wait for the later of our backoff and any
/// `RetryDeferred` hint.
async fn after_failed_retry(
    route: &ChainRoute,
    message_id: B256,
    spent: crate::work::FailedRetryState,
    retry_deferred: Option<u64>,
    failed_retries: &FailedRetries,
    outcomes: &OutcomeStore,
    metrics: &dyn crate::prom::MetricsTrait,
) -> DeliveryResultKind {
    if spent.attempts >= route.failed_retry.max_attempts {
        return give_up_failed_retries(route, message_id, spent, failed_retries, outcomes, metrics)
            .await;
    }
    DeliveryResultKind::AwaitingExecution {
        retry_after: Some(
            retry_deferred.map_or(spent.next_attempt_at, |at| at.max(spent.next_attempt_at)),
        ),
    }
}

/// Stop paying for a destination that keeps reverting. The work leaves the durable store (the pool
/// completes `Terminal` results) and a tombstone keeps a rescan from reopening the budget. Nothing
/// changes on-chain: the message stays `isRetryable` for anyone to `retryFailedMessage` later.
async fn give_up_failed_retries(
    route: &ChainRoute,
    message_id: B256,
    state: crate::work::FailedRetryState,
    failed_retries: &FailedRetries,
    outcomes: &OutcomeStore,
    metrics: &dyn crate::prom::MetricsTrait,
) -> DeliveryResultKind {
    let chain_key = route.chain_key;
    if state.gave_up_at.is_some() {
        // Abandoned before a restart and re-recorded by the startup rescan: already counted and
        // logged, so only restore the outcome and drop the work again.
        debug!(chain_key, %message_id, attempts = state.attempts,
            "retryFailedMessage budget already exhausted; dropping re-discovered work");
    } else {
        failed_retries
            .give_up(message_id, state, now_unix().unwrap_or_default())
            .await;
        metrics.inc_destination_failed_retries_exhausted(chain_key);
        warn!(
            chain_key,
            %message_id,
            attempts = state.attempts,
            max_attempts = route.failed_retry.max_attempts,
            "🛑 destination kept reverting; gave up on retryFailedMessage — message remains \
             retryable on-chain"
        );
    }
    let mut outcome =
        DeliveryOutcome::new(OutcomeKind::DestinationFailed, chain_key).with_reason(format!(
            "destination kept reverting; gave up after {} retryFailedMessage attempts; message \
             remains retryable on-chain",
            state.attempts
        ));
    // Keep pointing at the last destination tx we know of.
    outcome.tx_hash = outcomes.get(&message_id).and_then(|o| o.tx_hash);
    outcomes.record(message_id, outcome);
    DeliveryResultKind::Terminal
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{DELIVERY_RETRY_MAX, PRUNE_TICK_INTERVAL};
    use crate::prom::NoopMetrics;
    use alloy::primitives::LogData;
    use alloy::transports::mock::Asserter;
    fn execution_job_fixture() -> (ChainRoute, DeliveryJob) {
        let route = ChainRoute {
            chain_key: 2,
            creditcoin_chain_id: 42,
            destination_rpc_url: "http://unused.invalid".into(),
            inbox_address: Address::repeat_byte(0x11),
            signer_key: Some(format!("{:064x}", 1)),
            outbox_address: None,
            relayer_contract_address: None,
            block_confirmation_depth: 0,
            start_block: None,
            attestor_set: crate::config::AttestorSet::Static(vec![Address::repeat_byte(0x22)]),
            threshold_override: None,
            ack: None,
            claim: None,
            max_native_coin_value_wei: U256::ZERO,
            max_gas_limit: 5_000_000,
            auto_request_top_up: false,
            failed_retry: Default::default(),
        };
        let job = DeliveryJob {
            chain_key: 2,
            message_id: B256::repeat_byte(1),
            emitter: Address::repeat_byte(2),
            outbox: Address::repeat_byte(3),
            sequence: 1,
            payload: envelope(0, 100_000),
            votes_calldata: vec![],
            signer_count: 0,
            indexed_at: Instant::now(),
            reconcile_only: true,
        };
        (route, job)
    }

    fn mock_state(rpc: &Asserter, pending: bool, failed: bool) {
        rpc.push_success(&Bytes::from(U256::ZERO.abi_encode()));
        rpc.push_success(&Bytes::from(pending.abi_encode()));
        if !pending {
            rpc.push_success(&Bytes::from(failed.abi_encode()));
        }
    }

    fn mock_execution_receipt(rpc: &Asserter, logs: Vec<Log>, status: bool) {
        let hash = B256::repeat_byte(0x44);
        rpc.push_success(&hash);
        rpc.push_success(&serde_json::json!({
            "status": if status { "0x1" } else { "0x0" },
            "cumulativeGasUsed": "0x1",
            "logsBloom": format!("0x{}", "00".repeat(256)), "logs": logs,
            "transactionHash": hash, "transactionIndex": "0x0",
            "blockHash": B256::repeat_byte(0x55), "blockNumber": "0x1",
            "gasUsed": "0x1", "effectiveGasPrice": "0x1",
            "from": Address::repeat_byte(4), "to": Address::repeat_byte(0x11), "type": "0x2",
        }));
    }

    fn mock_retry_receipt(rpc: &Asserter, logs: Vec<Log>, status: bool) {
        rpc.push_success(&"0x186a0");
        rpc.push_success(&Bytes::new());
        mock_execution_receipt(rpc, logs, status);
    }

    #[tokio::test]
    async fn restart_reconciles_queued_and_failed_without_fresh_votes_or_retry_budget() {
        for pending in [true, false] {
            let rpc = Asserter::new();
            let provider = ProviderBuilder::new()
                .disable_recommended_fillers()
                .connect_mocked_client(rpc.clone());
            let (route, job) = execution_job_fixture();
            let outcomes = Arc::new(OutcomeStore::new(8));
            let locks = crate::broadcast::BroadcastLocks::new();
            for attempt in 0..5 {
                mock_state(&rpc, pending, !pending);
                rpc.push_failure_msg("execution reverted: EnforcedPause()");
                let result = handle_job(
                    &route,
                    &DeliveryConfig::default(),
                    &provider,
                    Address::repeat_byte(4),
                    &locks,
                    &job,
                    MessageFunding::unknown(),
                    NoopMetrics::new().as_ref(),
                    None,
                    &outcomes,
                    &FailedRetries::in_memory(2),
                )
                .await
                .unwrap();
                assert_eq!(
                    result,
                    DeliveryResultKind::AwaitingExecution { retry_after: None },
                    "lost accepted execution on attempt {attempt}"
                );
                assert!(outcomes.get(&job.message_id).is_none());
            }
            // Another relayer eventually executes it. Only processedAt is necessary to settle;
            // there is no new submit/nonce/vote read and no fresh committee quorum.
            rpc.push_success(&Bytes::from(U256::from(123).abi_encode()));
            assert_eq!(
                handle_job(
                    &route,
                    &DeliveryConfig::default(),
                    &provider,
                    Address::repeat_byte(4),
                    &locks,
                    &job,
                    MessageFunding::unknown(),
                    NoopMetrics::new().as_ref(),
                    None,
                    &outcomes,
                    &FailedRetries::in_memory(2),
                )
                .await
                .unwrap(),
                DeliveryResultKind::Delivered
            );
            assert_eq!(
                outcomes.get(&job.message_id).unwrap().kind,
                OutcomeKind::Delivered
            );
            assert!(rpc.read_q().is_empty());
        }
    }

    #[tokio::test]
    async fn duplicate_of_queued_message_retains_execution_work() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_mocked_client(rpc.clone());
        let (route, mut job) = execution_job_fixture();
        job.reconcile_only = false;
        rpc.push_failure_msg("execution reverted: MessageAlreadyValidated");
        mock_state(&rpc, true, false);
        rpc.push_failure_msg("execution reverted: RetryDeferred");
        let outcomes = Arc::new(OutcomeStore::new(8));
        assert_eq!(
            handle_job(
                &route,
                &DeliveryConfig {
                    simulate_before_send: true,
                    ..Default::default()
                },
                &provider,
                Address::repeat_byte(4),
                &crate::broadcast::BroadcastLocks::new(),
                &job,
                MessageFunding::unknown(),
                NoopMetrics::new().as_ref(),
                None,
                &outcomes,
                &FailedRetries::in_memory(2),
            )
            .await
            .unwrap(),
            DeliveryResultKind::AwaitingExecution { retry_after: None }
        );
        assert!(outcomes.get(&job.message_id).is_none());
        assert!(rpc.read_q().is_empty());
    }

    fn destination_failed_log(route: &ChainRoute, job: &DeliveryJob) -> Log {
        inbox_event_log(
            route.inbox_address,
            IInbox::DestinationFailed {
                messageId: job.message_id,
                emitterAddress: job.emitter,
                destination: Address::repeat_byte(5),
                dispatcher: Address::repeat_byte(6),
                relayer: Address::repeat_byte(4),
                messagePayload: Bytes::new(),
            }
            .encode_log_data(),
        )
    }

    /// asc-devnet, Oct 2026: probes aimed at an always-reverting destination were retried every
    /// ~10 min forever. retryFailedMessage is now spent at most `max_attempts` times, then the work
    /// is dropped (Terminal) with an outcome and a metric, and a later rescan does not reopen it.
    #[tokio::test]
    async fn failed_destination_retries_give_up_after_the_budget() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_mocked_client(rpc.clone());
        let (mut route, job) = execution_job_fixture();
        // No backoff, so consecutive calls are due; the schedule is covered separately.
        route.failed_retry = crate::config::FailedRetryPolicy {
            max_attempts: 2,
            initial_backoff_secs: 0,
            max_backoff_secs: 0,
        };
        let locks = crate::broadcast::BroadcastLocks::new();
        let outcomes = OutcomeStore::new(8);
        let retries = FailedRetries::in_memory(2);
        let metrics = crate::prom::RelayerMetrics::new(&[2]);
        let reconcile = || {
            reconcile_execution(
                &provider,
                Address::repeat_byte(4),
                &locks,
                &route,
                job.message_id,
                &outcomes,
                &retries,
                &metrics,
            )
        };

        mock_state(&rpc, false, true);
        mock_retry_receipt(&rpc, vec![destination_failed_log(&route, &job)], true);
        assert!(matches!(
            reconcile().await,
            DeliveryResultKind::AwaitingExecution {
                retry_after: Some(_)
            }
        ));
        let outcome = outcomes.get(&job.message_id).unwrap();
        assert_eq!(outcome.kind, OutcomeKind::DestinationFailed);
        assert!(outcome.reason.unwrap().contains("attempt 1/2"));
        assert!(rpc.read_q().is_empty());

        // The second failure is the last allowed one: give up without waiting another round.
        mock_state(&rpc, false, true);
        mock_retry_receipt(&rpc, vec![destination_failed_log(&route, &job)], true);
        assert_eq!(reconcile().await, DeliveryResultKind::Terminal);
        let outcome = outcomes.get(&job.message_id).unwrap();
        assert_eq!(outcome.kind, OutcomeKind::DestinationFailed);
        assert_eq!(outcome.tx_hash, Some(B256::repeat_byte(0x44)));
        let reason = outcome.reason.unwrap();
        assert!(
            reason.contains("gave up after 2 retryFailedMessage attempts")
                && reason.contains("remains retryable on-chain"),
            "{reason}"
        );
        assert!(rpc.read_q().is_empty());
        let exhausted = "relayer_destination_failed_retries_exhausted_total{chain_key=\"2\"} 1";
        assert!(metrics.encode().contains(exhausted));

        // Re-discovered (e.g. by the startup rescan): dropped again with no estimate, preflight
        // or broadcast, and not double-counted.
        mock_state(&rpc, false, true);
        assert_eq!(reconcile().await, DeliveryResultKind::Terminal);
        assert!(rpc.read_q().is_empty());
        assert!(metrics.encode().contains(exhausted));

        // Pending (queued/deferred) execution of the same message is not subject to the budget.
        for _ in 0..3 {
            mock_state(&rpc, true, false);
            mock_retry_receipt(&rpc, vec![], true);
            assert_eq!(
                reconcile().await,
                DeliveryResultKind::AwaitingExecution { retry_after: None }
            );
            assert!(rpc.read_q().is_empty());
        }
    }

    #[tokio::test]
    async fn failed_destination_retry_waits_for_its_backoff() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_mocked_client(rpc.clone());
        let (route, job) = execution_job_fixture();
        let locks = crate::broadcast::BroadcastLocks::new();
        let outcomes = OutcomeStore::new(8);
        let retries = FailedRetries::in_memory(2);
        let metrics = NoopMetrics::new();
        let reconcile = || {
            reconcile_execution(
                &provider,
                Address::repeat_byte(4),
                &locks,
                &route,
                job.message_id,
                &outcomes,
                &retries,
                metrics.as_ref(),
            )
        };
        let before = now_unix().unwrap();
        mock_state(&rpc, false, true);
        mock_retry_receipt(&rpc, vec![destination_failed_log(&route, &job)], true);
        let DeliveryResultKind::AwaitingExecution {
            retry_after: Some(next),
        } = reconcile().await
        else {
            panic!("a failed retry must schedule the next attempt");
        };
        // One attempt spent: the default schedule waits 2 × 60 s before the next.
        assert!((before + 120..=now_unix().unwrap() + 120).contains(&next));
        assert!(rpc.read_q().is_empty());

        // Redispatched early (e.g. a restart probe): only the state read, no estimate or send.
        mock_state(&rpc, false, true);
        assert_eq!(
            reconcile().await,
            DeliveryResultKind::AwaitingExecution {
                retry_after: Some(next)
            }
        );
        assert!(rpc.read_q().is_empty());
    }

    #[tokio::test]
    async fn initial_destination_failed_schedules_the_first_retry() {
        for max_attempts in [5, 0] {
            let rpc = Asserter::new();
            let provider = ProviderBuilder::new()
                .disable_recommended_fillers()
                .connect_mocked_client(rpc.clone());
            let (mut route, mut job) = execution_job_fixture();
            route.failed_retry.max_attempts = max_attempts;
            job.reconcile_only = false;
            rpc.push_success(&Bytes::from(true.abi_encode()));
            mock_execution_receipt(&rpc, vec![destination_failed_log(&route, &job)], true);
            let outcomes = Arc::new(OutcomeStore::new(8));
            let retries = FailedRetries::in_memory(2);
            let before = now_unix().unwrap();
            let result = handle_job(
                &route,
                &DeliveryConfig {
                    simulate_before_send: false,
                    ..Default::default()
                },
                &provider,
                Address::repeat_byte(4),
                &crate::broadcast::BroadcastLocks::new(),
                &job,
                MessageFunding::unknown(),
                NoopMetrics::new().as_ref(),
                None,
                &outcomes,
                &retries,
            )
            .await
            .unwrap();
            if max_attempts == 0 {
                assert_eq!(result, DeliveryResultKind::Terminal);
                continue;
            }
            let DeliveryResultKind::AwaitingExecution {
                retry_after: Some(next),
            } = result
            else {
                panic!("first DestinationFailed must schedule retryFailedMessage: {result:?}");
            };
            assert!((before + 60..=now_unix().unwrap() + 60).contains(&next));
            assert_eq!(
                retries.get(job.message_id).await.unwrap().unwrap().attempts,
                0
            );
        }
    }

    #[tokio::test]
    async fn zero_failed_retry_budget_never_broadcasts() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_mocked_client(rpc.clone());
        let (mut route, job) = execution_job_fixture();
        route.failed_retry.max_attempts = 0;
        let outcomes = OutcomeStore::new(8);
        mock_state(&rpc, false, true);
        assert_eq!(
            reconcile_execution(
                &provider,
                Address::repeat_byte(4),
                &crate::broadcast::BroadcastLocks::new(),
                &route,
                job.message_id,
                &outcomes,
                &FailedRetries::in_memory(2),
                NoopMetrics::new().as_ref(),
            )
            .await,
            DeliveryResultKind::Terminal
        );
        assert!(rpc.read_q().is_empty());
        assert!(outcomes
            .get(&job.message_id)
            .unwrap()
            .reason
            .unwrap()
            .contains("gave up after 0 retryFailedMessage attempts"));
    }

    #[tokio::test]
    async fn retry_pending_can_become_failed_then_execute() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_mocked_client(rpc.clone());
        let (route, job) = execution_job_fixture();
        let outcomes = Arc::new(OutcomeStore::new(8));
        let locks = crate::broadcast::BroadcastLocks::new();
        let retries = FailedRetries::in_memory(2);
        let before = now_unix().unwrap();
        mock_state(&rpc, true, false);
        mock_retry_receipt(
            &rpc,
            vec![inbox_event_log(
                route.inbox_address,
                IInbox::DestinationFailed {
                    messageId: job.message_id,
                    emitterAddress: job.emitter,
                    destination: Address::repeat_byte(5),
                    dispatcher: Address::repeat_byte(6),
                    relayer: Address::repeat_byte(4),
                    messagePayload: Bytes::new(),
                }
                .encode_log_data(),
            )],
            true,
        );
        assert!(matches!(
            handle_job(
                &route,
                &DeliveryConfig::default(),
                &provider,
                Address::repeat_byte(4),
                &locks,
                &job,
                MessageFunding::unknown(),
                NoopMetrics::new().as_ref(),
                None,
                &outcomes,
                &retries,
            )
            .await
            .unwrap(),
            DeliveryResultKind::AwaitingExecution {
                retry_after: Some(next)
            } if (before + 60..=now_unix().unwrap() + 60).contains(&next)
        ));
        // The pending retry does not count against the failed-destination budget.
        assert_eq!(
            retries.get(job.message_id).await.unwrap().unwrap().attempts,
            0
        );
        assert_eq!(
            outcomes.get(&job.message_id).unwrap().kind,
            OutcomeKind::DestinationFailed
        );
        // Redispatched once the backoff has elapsed (a fresh ledger stands in for the wait).
        mock_state(&rpc, false, true);
        mock_retry_receipt(
            &rpc,
            vec![inbox_event_log(
                route.inbox_address,
                IInbox::MessageExecuted {
                    messageId: job.message_id,
                    emitterAddress: job.emitter,
                    destination: Address::repeat_byte(5),
                    dispatcher: Address::repeat_byte(6),
                    relayer: Address::repeat_byte(4),
                    messagePayload: Bytes::new(),
                }
                .encode_log_data(),
            )],
            true,
        );
        assert_eq!(
            handle_job(
                &route,
                &DeliveryConfig::default(),
                &provider,
                Address::repeat_byte(4),
                &locks,
                &job,
                MessageFunding::unknown(),
                NoopMetrics::new().as_ref(),
                None,
                &outcomes,
                &FailedRetries::in_memory(2),
            )
            .await
            .unwrap(),
            DeliveryResultKind::Delivered
        );
        assert!(rpc.read_q().is_empty());
    }

    #[tokio::test]
    async fn reconciliation_distinguishes_unaccepted_from_unavailable_and_honors_deferral() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_mocked_client(rpc.clone());
        let (route, job) = execution_job_fixture();
        let outcomes = OutcomeStore::new(8);
        let locks = crate::broadcast::BroadcastLocks::new();
        mock_state(&rpc, false, false);
        assert_eq!(
            reconcile_execution(
                &provider,
                Address::repeat_byte(4),
                &locks,
                &route,
                job.message_id,
                &outcomes,
                &FailedRetries::in_memory(2),
                NoopMetrics::new().as_ref(),
            )
            .await,
            DeliveryResultKind::AwaitingVotes
        );
        rpc.push_failure_msg("gateway unavailable");
        assert_eq!(
            reconcile_execution(
                &provider,
                Address::repeat_byte(4),
                &locks,
                &route,
                job.message_id,
                &outcomes,
                &FailedRetries::in_memory(2),
                NoopMetrics::new().as_ref(),
            )
            .await,
            DeliveryResultKind::Retryable
        );
        mock_state(&rpc, true, false);
        let deferred = IInbox::RetryDeferred {
            messageId: job.message_id,
            retryAfter: 1_900_000_000,
        }
        .abi_encode();
        rpc.push_failure_msg(cc_style(&deferred));
        assert_eq!(
            reconcile_execution(
                &provider,
                Address::repeat_byte(4),
                &locks,
                &route,
                job.message_id,
                &outcomes,
                &FailedRetries::in_memory(2),
                NoopMetrics::new().as_ref(),
            )
            .await,
            DeliveryResultKind::AwaitingExecution {
                retry_after: Some(1_900_000_000)
            }
        );
        mock_state(&rpc, false, true);
        mock_retry_receipt(&rpc, vec![], false);
        rpc.push_failure_msg(cc_style(&deferred));
        assert_eq!(
            reconcile_execution(
                &provider,
                Address::repeat_byte(4),
                &locks,
                &route,
                job.message_id,
                &outcomes,
                &FailedRetries::in_memory(2),
                NoopMetrics::new().as_ref(),
            )
            .await,
            DeliveryResultKind::AwaitingExecution {
                retry_after: Some(1_900_000_000)
            }
        );
        assert!(outcomes.get(&job.message_id).is_none());
        assert!(rpc.read_q().is_empty());
    }

    #[tokio::test]
    async fn execution_confirmations_preserve_work_through_reorg() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_mocked_client(rpc.clone());
        let (mut route, job) = execution_job_fixture();
        route.block_confirmation_depth = 12;
        let locks = crate::broadcast::BroadcastLocks::new();
        let outcomes = OutcomeStore::new(8);
        rpc.push_success(&Bytes::from(U256::from(100).abi_encode()));
        rpc.push_success(&"0x69"); // head 105: execution has only five blocks of depth
        assert_eq!(
            reconcile_execution(
                &provider,
                Address::repeat_byte(4),
                &locks,
                &route,
                job.message_id,
                &outcomes,
                &FailedRetries::in_memory(2),
                NoopMetrics::new().as_ref(),
            )
            .await,
            DeliveryResultKind::AwaitingExecution { retry_after: None }
        );
        assert!(outcomes.get(&job.message_id).is_none());
        assert!(
            rpc.read_q().is_empty(),
            "unconfirmed execution must not be rebroadcast"
        );
        // The destination reorg removes the execution; the durable publication returns to voting.
        mock_state(&rpc, false, false);
        assert_eq!(
            reconcile_execution(
                &provider,
                Address::repeat_byte(4),
                &locks,
                &route,
                job.message_id,
                &outcomes,
                &FailedRetries::in_memory(2),
                NoopMetrics::new().as_ref(),
            )
            .await,
            DeliveryResultKind::AwaitingVotes
        );
        // A reorg between latest-state and head reads must not combine unrelated evidence.
        rpc.push_success(&Bytes::from(U256::from(200).abi_encode()));
        rpc.push_success(&"0xd4");
        rpc.push_success(&Bytes::from(U256::ZERO.abi_encode()));
        assert_eq!(
            reconcile_execution(
                &provider,
                Address::repeat_byte(4),
                &locks,
                &route,
                job.message_id,
                &outcomes,
                &FailedRetries::in_memory(2),
                NoopMetrics::new().as_ref(),
            )
            .await,
            DeliveryResultKind::AwaitingExecution { retry_after: None }
        );
        assert!(outcomes.get(&job.message_id).is_none());
        rpc.push_success(&Bytes::from(U256::from(200).abi_encode()));
        rpc.push_success(&"0xd4"); // head 212: replacement execution reaches the configured depth
        rpc.push_success(&Bytes::from(U256::from(200).abi_encode()));
        assert_eq!(
            reconcile_execution(
                &provider,
                Address::repeat_byte(4),
                &locks,
                &route,
                job.message_id,
                &outcomes,
                &FailedRetries::in_memory(2),
                NoopMetrics::new().as_ref(),
            )
            .await,
            DeliveryResultKind::Delivered
        );
        assert!(rpc.read_q().is_empty());
    }

    #[tokio::test]
    async fn initial_and_retry_execution_receipts_wait_for_confirmations() {
        for retry in [false, true] {
            let rpc = Asserter::new();
            let provider = ProviderBuilder::new()
                .disable_recommended_fillers()
                .connect_mocked_client(rpc.clone());
            let (mut route, mut job) = execution_job_fixture();
            route.block_confirmation_depth = 2;
            job.reconcile_only = retry;
            let log = inbox_event_log(
                route.inbox_address,
                IInbox::MessageExecuted {
                    messageId: job.message_id,
                    emitterAddress: job.emitter,
                    destination: Address::repeat_byte(5),
                    dispatcher: Address::repeat_byte(6),
                    relayer: Address::repeat_byte(4),
                    messagePayload: job.payload.clone().into(),
                }
                .encode_log_data(),
            );
            if retry {
                mock_state(&rpc, true, false);
                mock_retry_receipt(&rpc, vec![log], true);
            } else {
                rpc.push_success(&Bytes::from(true.abi_encode()));
                mock_execution_receipt(&rpc, vec![log], true);
            }
            let outcomes = Arc::new(OutcomeStore::new(8));
            assert_eq!(
                handle_job(
                    &route,
                    &DeliveryConfig {
                        simulate_before_send: false,
                        ..Default::default()
                    },
                    &provider,
                    Address::repeat_byte(4),
                    &crate::broadcast::BroadcastLocks::new(),
                    &job,
                    MessageFunding::unknown(),
                    NoopMetrics::new().as_ref(),
                    None,
                    &outcomes,
                    &FailedRetries::in_memory(2),
                )
                .await
                .unwrap(),
                DeliveryResultKind::AwaitingExecution { retry_after: None }
            );
            assert_eq!(
                outcomes.get(&job.message_id).unwrap().kind,
                OutcomeKind::Pending
            );
            assert!(rpc.read_q().is_empty());
        }
    }

    #[tokio::test]
    async fn accepted_retry_gas_cap_and_preflight_never_broadcast_known_failure() {
        for pending in [true, false] {
            let rpc = Asserter::new();
            let provider = ProviderBuilder::new()
                .disable_recommended_fillers()
                .connect_mocked_client(rpc.clone());
            let (mut route, job) = execution_job_fixture();
            route.max_gas_limit = 100_000;
            let locks = crate::broadcast::BroadcastLocks::new();
            let outcomes = OutcomeStore::new(8);
            mock_state(&rpc, pending, !pending);
            rpc.push_success(&"0x186a1"); // one gas above the configured cap
            assert_eq!(
                reconcile_execution(
                    &provider,
                    Address::repeat_byte(4),
                    &locks,
                    &route,
                    job.message_id,
                    &outcomes,
                    &FailedRetries::in_memory(2),
                    NoopMetrics::new().as_ref(),
                )
                .await,
                DeliveryResultKind::AwaitingExecution { retry_after: None }
            );
            assert!(rpc.read_q().is_empty());
            mock_state(&rpc, pending, !pending);
            rpc.push_success(&"0x186a0");
            rpc.push_failure_msg("execution reverted: InsufficientGasForDestination()");
            assert_eq!(
                reconcile_execution(
                    &provider,
                    Address::repeat_byte(4),
                    &locks,
                    &route,
                    job.message_id,
                    &outcomes,
                    &FailedRetries::in_memory(2),
                    NoopMetrics::new().as_ref(),
                )
                .await,
                DeliveryResultKind::AwaitingExecution { retry_after: None }
            );
            assert!(outcomes.get(&job.message_id).is_none());
            assert!(rpc.read_q().is_empty());
        }
    }

    #[tokio::test]
    async fn execution_worker_cancels_while_rpc_is_blackholed() {
        for wait_for_timeout in [false, true] {
            use tokio::io::AsyncReadExt;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (mut route, job) = execution_job_fixture();
            route.destination_rpc_url = format!("http://{}", listener.local_addr().unwrap());
            let (request_tx, request_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0; 1024];
                assert!(stream.read(&mut buf).await.unwrap() > 0);
                let _ = request_tx.send(());
                std::future::pending::<()>().await;
            });
            let (job_tx, job_rx) = mpsc::channel(1);
            job_tx.send(job).await.unwrap();
            let (result_tx, mut result_rx) = mpsc::channel(1);
            let cancel = CancellationToken::new();
            let worker = tokio::spawn(run(
                route,
                DeliveryConfig::default(),
                "unused".into(),
                job_rx,
                result_tx,
                NoopMetrics::new(),
                crate::health::Health::new(crate::health::PROGRESS_DEADLINE),
                crate::broadcast::BroadcastLocks::new(),
                Arc::new(OutcomeStore::new(8)),
                None,
                cancel.clone(),
            ));
            tokio::time::timeout(Duration::from_secs(5), request_rx)
                .await
                .unwrap()
                .unwrap();
            if wait_for_timeout {
                tokio::time::pause();
                tokio::time::advance(FUNDED_GAS_READ_TIMEOUT + Duration::from_secs(1)).await;
                let result = tokio::time::timeout(Duration::from_secs(1), result_rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(result.outcome, DeliveryResultKind::Retryable);
                tokio::time::resume();
            }
            cancel.cancel();
            tokio::time::timeout(Duration::from_secs(1), worker)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            server.abort();
        }
    }

    fn delivery_fixture() -> (ChainRoute, DeliveryJob) {
        let route = ChainRoute {
            chain_key: 2,
            creditcoin_chain_id: 42,
            destination_rpc_url: "http://unused.invalid".into(),
            inbox_address: Address::repeat_byte(0x11),
            signer_key: None,
            outbox_address: None,
            relayer_contract_address: None,
            block_confirmation_depth: 0,
            start_block: None,
            attestor_set: crate::config::AttestorSet::Static(vec![Address::repeat_byte(0x22)]),
            threshold_override: None,
            ack: None,
            claim: None,
            max_native_coin_value_wei: U256::ZERO,
            max_gas_limit: 5_000_000,
            auto_request_top_up: false,
            failed_retry: Default::default(),
        };
        let job = DeliveryJob {
            chain_key: route.chain_key,
            message_id: B256::repeat_byte(1),
            emitter: Address::repeat_byte(2),
            outbox: Address::repeat_byte(3),
            sequence: 1,
            payload: envelope(0, 100_000),
            votes_calldata: vec![],
            signer_count: 1,
            indexed_at: Instant::now(),
            reconcile_only: false,
        };
        (route, job)
    }

    /// Exercise the worker's simulate, funded estimate, send and mined-replay paths. A pause is
    /// reversible even though every one of those RPC responses is a deterministic EVM revert.
    #[tokio::test]
    async fn paused_inbox_is_retryable_at_every_delivery_stage() {
        for stage in ["simulate", "estimate", "send", "mined"] {
            let rpc = Asserter::new();
            let (route, job) = delivery_fixture();
            let config = DeliveryConfig {
                simulate_before_send: stage == "simulate",
                max_retries: 0,
                ..Default::default()
            };
            let funding = if stage == "estimate" {
                MessageFunding {
                    gas: Some(200_000),
                    ..MessageFunding::unknown()
                }
            } else {
                MessageFunding::unknown()
            };
            if stage == "send" || stage == "mined" {
                rpc.push_success(&Bytes::from(true.abi_encode())); // preflight before sending
            }
            if stage == "mined" {
                let hash = B256::repeat_byte(0x44);
                rpc.push_success(&hash);
                rpc.push_success(&serde_json::json!({
                    "status": "0x0", "cumulativeGasUsed": "0x1",
                    "logsBloom": format!("0x{}", "00".repeat(256)), "logs": [],
                    "transactionHash": hash, "transactionIndex": "0x0",
                    "blockHash": B256::repeat_byte(0x55), "blockNumber": "0x1",
                    "gasUsed": "0x1", "effectiveGasPrice": "0x1",
                    "from": Address::repeat_byte(4), "to": route.inbox_address, "type": "0x2",
                }));
            }
            rpc.push_failure_msg("execution reverted: EnforcedPause()");
            let provider = ProviderBuilder::new()
                .disable_recommended_fillers()
                .connect_mocked_client(rpc.clone());
            let outcomes = Arc::new(OutcomeStore::new(8));
            let result = handle_job(
                &route,
                &config,
                &provider,
                Address::repeat_byte(4),
                &crate::broadcast::BroadcastLocks::new(),
                &job,
                funding,
                NoopMetrics::new().as_ref(),
                None,
                &outcomes,
                &FailedRetries::in_memory(2),
            )
            .await
            .unwrap();
            assert_eq!(result, DeliveryResultKind::Retryable, "{stage}");
            assert!(
                outcomes.get(&job.message_id).is_none(),
                "{stage} recorded a final outcome"
            );
            assert!(
                rpc.read_q().is_empty(),
                "{stage} did not exercise the intended RPC path"
            );
        }
    }

    #[tokio::test]
    async fn validator_false_never_broadcasts_and_true_later_recovers() {
        for mode in ["simulate", "funded preflight", "unfunded preflight"] {
            let rpc = Asserter::new();
            let provider = ProviderBuilder::new()
                .disable_recommended_fillers()
                .connect_mocked_client(rpc.clone());
            let (route, job) = delivery_fixture();
            let funding = if mode == "funded preflight" {
                MessageFunding {
                    gas: Some(100_000),
                    ..MessageFunding::unknown()
                }
            } else {
                MessageFunding::unknown()
            };
            let config = DeliveryConfig {
                simulate_before_send: mode == "simulate",
                ..Default::default()
            };
            let locks = crate::broadcast::BroadcastLocks::new();
            let outcomes = Arc::new(OutcomeStore::new(8));
            if funding.gas.is_some() {
                rpc.push_success(&"0x186a0");
            }
            rpc.push_success(&Bytes::from(false.abi_encode()));
            assert_eq!(
                handle_job(
                    &route,
                    &config,
                    &provider,
                    Address::repeat_byte(4),
                    &locks,
                    &job,
                    funding,
                    NoopMetrics::new().as_ref(),
                    None,
                    &outcomes,
                    &FailedRetries::in_memory(2),
                )
                .await
                .unwrap(),
                DeliveryResultKind::Retryable,
                "{mode}"
            );
            assert!(outcomes.get(&job.message_id).is_none());
            assert!(rpc.read_q().is_empty(), "{mode}");
            if config.simulate_before_send {
                rpc.push_success(&Bytes::from(true.abi_encode()));
            }
            if funding.gas.is_some() {
                rpc.push_success(&"0x186a0");
            }
            rpc.push_success(&Bytes::from(true.abi_encode()));
            mock_execution_receipt(
                &rpc,
                vec![inbox_event_log(
                    route.inbox_address,
                    IInbox::MessageExecuted {
                        messageId: job.message_id,
                        emitterAddress: job.emitter,
                        destination: Address::repeat_byte(5),
                        dispatcher: Address::repeat_byte(6),
                        relayer: Address::repeat_byte(4),
                        messagePayload: job.payload.clone().into(),
                    }
                    .encode_log_data(),
                )],
                true,
            );
            assert_eq!(
                handle_job(
                    &route,
                    &config,
                    &provider,
                    Address::repeat_byte(4),
                    &locks,
                    &job,
                    funding,
                    NoopMetrics::new().as_ref(),
                    None,
                    &outcomes,
                    &FailedRetries::in_memory(2),
                )
                .await
                .unwrap(),
                DeliveryResultKind::Delivered,
                "{mode}"
            );
            assert!(rpc.read_q().is_empty());
        }
    }

    #[tokio::test]
    async fn repeated_gas_cap_failures_do_not_broadcast_and_recover_after_state_changes() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Mutex;

        let (mut route, job) = delivery_fixture();
        route.max_gas_limit = 100_000;
        let signer = Address::repeat_byte(4);
        let recovered = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let hash = B256::repeat_byte(0x44);
        let event = IInbox::MessageExecuted {
            messageId: job.message_id,
            emitterAddress: job.emitter,
            destination: Address::repeat_byte(5),
            dispatcher: Address::repeat_byte(6),
            relayer: signer,
            messagePayload: job.payload.clone().into(),
        };
        let log = Log {
            inner: alloy::primitives::Log {
                address: route.inbox_address,
                data: event.encode_log_data(),
            },
            ..Default::default()
        };
        let receipt = serde_json::json!({
            "status": "0x1", "cumulativeGasUsed": "0x1",
            "logsBloom": format!("0x{}", "00".repeat(256)), "logs": [log],
            "transactionHash": hash, "transactionIndex": "0x0",
            "blockHash": B256::repeat_byte(0x55), "blockNumber": "0x1",
            "gasUsed": "0x1", "effectiveGasPrice": "0x1",
            "from": signer, "to": route.inbox_address, "type": "0x2",
        });
        let app = axum::Router::new().route("/", axum::routing::post({
            let recovered = recovered.clone();
            let requests = requests.clone();
            move |axum::Json(request): axum::Json<serde_json::Value>| {
                let recovered = recovered.clone();
                let requests = requests.clone();
                let receipt = receipt.clone();
                async move {
                    requests.lock().unwrap().push(request.clone());
                    let mut response = serde_json::json!({"jsonrpc": "2.0", "id": request["id"]});
                    if request["method"] == "eth_call" && !recovered.load(Ordering::SeqCst) {
                        response["error"] = serde_json::json!({
                            "code": 3, "message": "execution reverted: InsufficientGasForDestination()"
                        });
                    } else {
                        response["result"] = match request["method"].as_str().unwrap() {
                            "eth_estimateGas" => serde_json::json!("0x186a0"),
                            "eth_call" => serde_json::json!(Bytes::from(true.abi_encode())),
                            "eth_sendTransaction" => serde_json::json!(hash),
                            "eth_getTransactionReceipt" => receipt,
                            method => panic!("unexpected RPC method {method}"),
                        };
                    }
                    axum::Json(response)
                }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect(&url)
            .await
            .unwrap();
        let outcomes = Arc::new(OutcomeStore::new(8));
        let config = DeliveryConfig {
            simulate_before_send: false,
            max_retries: 1,
            ..Default::default()
        };
        for attempt in 0..4 {
            if attempt == 3 {
                recovered.store(true, Ordering::SeqCst);
            }
            let result = handle_job(
                &route,
                &config,
                &provider,
                signer,
                &crate::broadcast::BroadcastLocks::new(),
                &job,
                MessageFunding {
                    gas: Some(100_000),
                    ..MessageFunding::unknown()
                },
                NoopMetrics::new().as_ref(),
                None,
                &outcomes,
                &FailedRetries::in_memory(2),
            )
            .await
            .unwrap();
            let requests = requests.lock().unwrap();
            let sends = requests
                .iter()
                .filter(|r| r["method"] == "eth_sendTransaction")
                .count();
            if attempt < 3 {
                assert_eq!(result, DeliveryResultKind::Retryable);
                assert_eq!(sends, 0, "a known gas-cap failure was broadcast");
                assert!(outcomes.get(&job.message_id).is_none());
            } else {
                assert_eq!(result, DeliveryResultKind::Delivered);
                assert_eq!(sends, 1);
            }
            for call in requests.iter().filter(|r| r["method"] == "eth_call") {
                assert_eq!(call["params"][0]["gas"], "0x186a0");
                assert_eq!(call["params"][0]["from"], serde_json::json!(signer));
            }
        }
        server.abort();
    }

    #[tokio::test]
    async fn locally_verified_publication_limits_remain_terminal_without_sending() {
        let (route, mut job) = delivery_fixture();
        for payload in [envelope(1, 100_000), envelope(0, route.max_gas_limit + 1)] {
            job.payload = payload;
            let rpc = Asserter::new();
            let provider = ProviderBuilder::new().connect_mocked_client(rpc);
            let outcomes = Arc::new(OutcomeStore::new(8));
            assert_eq!(
                handle_job(
                    &route,
                    &DeliveryConfig::default(),
                    &provider,
                    Address::repeat_byte(4),
                    &crate::broadcast::BroadcastLocks::new(),
                    &job,
                    MessageFunding::unknown(),
                    NoopMetrics::new().as_ref(),
                    None,
                    &outcomes,
                    &FailedRetries::in_memory(2),
                )
                .await
                .unwrap(),
                DeliveryResultKind::Terminal,
            );
            assert_eq!(
                outcomes.get(&job.message_id).unwrap().kind,
                OutcomeKind::Undeliverable
            );
        }
    }

    #[test]
    fn state_dependent_and_unknown_reverts_keep_work() {
        let (route, job) = delivery_fixture();
        let metrics = NoopMetrics::new();
        let outcomes = OutcomeStore::new(8);
        for error in [
            structured_revert(
                "execution reverted: InvalidAttestor",
                &[0x12, 0x34, 0x56, 0x78],
            ),
            structured_revert("execution reverted: ThresholdNotMet", &[]),
            structured_revert(
                "execution reverted",
                &IInbox::InvalidMessageDispatcher {
                    dispatcher: Address::ZERO,
                }
                .abi_encode(),
            ),
            structured_revert(
                "execution reverted",
                &IInbox::ValidationFailedWithNativeValue {
                    messageId: job.message_id,
                    value: U256::from(1),
                }
                .abi_encode(),
            ),
        ] {
            let class = classify_delivery_revert(&error).unwrap();
            assert!(matches!(
                settle_pre_send_revert(
                    &route,
                    &job,
                    metrics.as_ref(),
                    &outcomes,
                    "simulate",
                    class,
                    &error,
                ),
                Stage::Done(DeliveryResultKind::Retryable)
            ));
            assert_eq!(
                retry_delivery_revert(
                    &route,
                    job.message_id,
                    metrics.as_ref(),
                    Some(class),
                    "send or mined",
                ),
                DeliveryResultKind::Retryable
            );
        }
        assert_eq!(
            retry_delivery_revert(
                &route,
                job.message_id,
                metrics.as_ref(),
                None,
                "replay unavailable",
            ),
            DeliveryResultKind::Retryable
        );
        assert!(outcomes.get(&job.message_id).is_none());

        let error = structured_revert(
            "execution reverted",
            &IInbox::MessageIdMismatch {
                messageId: job.message_id,
            }
            .abi_encode(),
        );
        let class = classify_delivery_revert(&error).unwrap();
        // Inbox bubbles dispatcher/validator errors, so even this selector cannot prove a bad
        // publication independently of the mutable contracts that emitted it.
        assert_eq!(class, DeliveryRevert::Other);
        assert!(matches!(
            settle_pre_send_revert(
                &route,
                &job,
                metrics.as_ref(),
                &outcomes,
                "simulate",
                class,
                &error,
            ),
            Stage::Done(DeliveryResultKind::Retryable)
        ));
        assert!(outcomes.get(&job.message_id).is_none());
    }

    /// Matches the grace period `run` actually computes: see the comment above its `error_grace_period` binding.
    const ERROR_GRACE_PERIOD: Duration =
        Duration::from_secs(DELIVERY_RETRY_MAX.as_secs() + PRUNE_TICK_INTERVAL.as_secs());

    fn envelope(native_value: u64, gas_limit: u64) -> Vec<u8> {
        (
            Address::repeat_byte(0x11),
            U256::from(native_value),
            U256::from(gas_limit),
            Bytes::from(vec![0xde, 0xad]),
        )
            .abi_encode_params()
    }

    /// A four-field envelope `abi.encode(destination, nativeCoinValue, gasLimit, payloadData)` yields
    /// its second word; anything else (legacy raw payloads, truncated bytes) yields zero so the
    /// delivery goes out with `msg.value == 0`, which is what every pre-envelope Inbox expects.
    #[test]
    fn envelope_native_value_reads_the_second_word_or_zero() {
        let envelope = envelope(1_500, 300_000);
        assert_eq!(envelope_native_value(&envelope), U256::from(1_500u64));

        let zero_value = self::envelope(0, 300_000);
        assert_eq!(envelope_native_value(&zero_value), U256::ZERO);

        assert_eq!(envelope_native_value(b"not an envelope"), U256::ZERO);
        assert_eq!(envelope_native_value(&[]), U256::ZERO);
        // Cut inside the head (only two of the four words present): the decoder cannot locate the
        // dynamic tail, so this is not an envelope. Trimming tail *padding* is tolerated by the
        // decoder and still yields the value, which is fine because the head words are intact.
        assert_eq!(envelope_native_value(&envelope[..64]), U256::ZERO);
    }

    /// The third word is the attested destination gasLimit; a non-envelope has none (so the cap
    /// cannot refuse legacy payloads by mistake).
    #[test]
    fn envelope_terms_read_gas_limit_or_nothing() {
        let terms = envelope_terms(&envelope(7, 4_999_999));
        assert_eq!(terms.native_value, U256::from(7u64));
        assert_eq!(terms.gas_limit, Some(U256::from(4_999_999u64)));
        assert_eq!(envelope_terms(b"raw").gas_limit, None);
        assert_eq!(envelope_terms(&[]), EnvelopeTerms::default());
    }

    /// The route-level cap replaces the old hard-coded constant; its default is still zero, so a
    /// route that never set it fronts nothing (the constant is now the whole default policy).
    #[test]
    fn native_value_cap_defaults_to_zero() {
        assert_eq!(crate::config::DEFAULT_MAX_NATIVE_COIN_VALUE_WEI, U256::ZERO);
        // What handle_job compares: an envelope with any value is over a zero cap; a zero-value
        // envelope and a non-envelope are not.
        let cap = crate::config::DEFAULT_MAX_NATIVE_COIN_VALUE_WEI;
        assert!(envelope_native_value(&envelope(1, 100_000)) > cap);
        assert!(envelope_native_value(&envelope(0, 100_000)) <= cap);
        assert!(envelope_native_value(b"raw") <= cap);
    }

    /// The gas cap refuses exactly what exceeds it, and nothing the router itself would accept
    /// below it. Compared as U256 so a 2^64+ attested gasLimit cannot wrap into an acceptable value.
    #[test]
    fn gas_limit_cap_refuses_only_oversized_envelopes() {
        let cap = crate::config::DEFAULT_MAX_GAS_LIMIT;
        let over = |payload: &[u8]| {
            envelope_terms(payload)
                .gas_limit
                .is_some_and(|g| g > U256::from(cap))
        };
        assert!(!over(&envelope(0, cap)));
        assert!(!over(&envelope(0, cap - 1)));
        assert!(over(&envelope(0, cap + 1)));
        assert!(!over(b"legacy payload"));
        // A gasLimit word above u64: still refused, never silently truncated.
        let huge = (
            Address::repeat_byte(0x11),
            U256::ZERO,
            U256::from(u64::MAX) + U256::from(1u64),
            Bytes::from(vec![0xde]),
        )
            .abi_encode_params();
        assert!(over(&huge));
    }

    fn inbox_log(inbox: Address, topics: Vec<B256>) -> Log {
        Log {
            inner: alloy::primitives::Log {
                address: inbox,
                data: LogData::new_unchecked(topics, Bytes::new()),
            },
            ..Default::default()
        }
    }

    /// Build a log from an actual ABI-encoded event (topics AND data), for shapes like
    /// `DestinationFailed`/`MessageExecuted` that carry non-indexed fields — unlike `inbox_log`'s
    /// topics-only fixtures, which only work for fully-indexed events.
    fn inbox_event_log(inbox: Address, data: LogData) -> Log {
        Log {
            inner: alloy::primitives::Log {
                address: inbox,
                data,
            },
            ..Default::default()
        }
    }

    fn addr_topic(a: Address) -> B256 {
        B256::left_padding_from(a.as_slice())
    }

    /// Receipt fixtures for the successful-tx shapes the Inbox can produce: `Delivered`,
    /// `Pending` (either of the #54-split `MessageQueued`/`MessageDeferred` topics), and
    /// `DestinationFailed`. asc-contracts #54's `DestinationFailed` arrives *with*
    /// `MessageReceived`, so it must win over the plain success arm, and — unlike the retired
    /// 3-indexed-arg `MessageExecutionFailed` — `dispatcher` is a non-indexed field this must
    /// decode from the log body, not pull from a fixed topic index (topics[2] is `destination`
    /// now, a different field entirely).
    #[test]
    fn success_receipt_logs_classify_delivered_pending_and_destination_failed() {
        let inbox = Address::repeat_byte(0xaa);
        let other = Address::repeat_byte(0xbb);
        let dispatcher = Address::repeat_byte(0xdd);
        let relayer = Address::repeat_byte(0xee);
        let id = B256::repeat_byte(0x01);

        let received = inbox_log(
            inbox,
            vec![
                IInbox::MessageReceived::SIGNATURE_HASH,
                id,
                addr_topic(other),
                addr_topic(relayer),
            ],
        );
        let failed = inbox_event_log(
            inbox,
            IInbox::DestinationFailed {
                messageId: id,
                emitterAddress: other,
                destination: other,
                dispatcher,
                relayer,
                messagePayload: Bytes::new(),
            }
            .encode_log_data(),
        );
        let queued = inbox_log(
            inbox,
            vec![
                IInbox::MessageQueued::SIGNATURE_HASH,
                id,
                addr_topic(dispatcher),
                addr_topic(relayer),
            ],
        );
        let deferred = inbox_log(
            inbox,
            vec![
                IInbox::MessageDeferred::SIGNATURE_HASH,
                id,
                addr_topic(dispatcher),
                addr_topic(relayer),
            ],
        );
        // The same topic0 from a different contract (a dApp re-emitting) must not count.
        let foreign_failed = inbox_event_log(
            other,
            IInbox::DestinationFailed {
                messageId: id,
                emitterAddress: other,
                destination: other,
                dispatcher,
                relayer,
                messagePayload: Bytes::new(),
            }
            .encode_log_data(),
        );

        assert_eq!(
            classify_success_logs(inbox, id, [&received]),
            ReceiptClass::Unknown
        );
        assert_eq!(
            classify_success_logs(inbox, id, [&failed, &received]),
            ReceiptClass::DestinationFailed { dispatcher }
        );
        // Order-independent.
        assert_eq!(
            classify_success_logs(inbox, id, [&received, &failed]),
            ReceiptClass::DestinationFailed { dispatcher }
        );
        assert_eq!(
            classify_success_logs(inbox, id, [&queued]),
            ReceiptClass::Pending
        );
        assert_eq!(
            classify_success_logs(inbox, id, [&deferred]),
            ReceiptClass::Pending
        );
        assert_eq!(
            classify_success_logs(inbox, id, [&foreign_failed, &received]),
            ReceiptClass::Unknown
        );
        assert_eq!(
            classify_success_logs(inbox, id, std::iter::empty()),
            ReceiptClass::Unknown
        );
    }

    #[test]
    fn success_receipt_requires_execution_for_the_exact_message() {
        let inbox = Address::repeat_byte(1);
        let id = B256::repeat_byte(2);
        let executed = inbox_event_log(
            inbox,
            IInbox::MessageExecuted {
                messageId: id,
                emitterAddress: Address::repeat_byte(3),
                destination: Address::repeat_byte(4),
                dispatcher: Address::repeat_byte(5),
                relayer: Address::repeat_byte(6),
                messagePayload: Bytes::new(),
            }
            .encode_log_data(),
        );
        assert_eq!(
            classify_success_logs(inbox, id, [&executed]),
            ReceiptClass::Delivered
        );
        assert_eq!(
            classify_success_logs(inbox, B256::repeat_byte(9), [&executed]),
            ReceiptClass::Unknown
        );
        let validation_failed = inbox_log(
            inbox,
            vec![
                alloy::primitives::keccak256("ValidationFailed(bytes32)"),
                id,
            ],
        );
        assert_eq!(
            classify_success_logs(inbox, id, [&validation_failed]),
            ReceiptClass::Unknown
        );
    }

    /// The topic0 values the classifier keys on are the compiled contract's (pinned by the
    /// abi_surface gate); this pins the Rust side so a mirror edit cannot move them unnoticed.
    #[test]
    fn destination_failed_topic0_is_the_54_signature() {
        assert_eq!(
            IInbox::DestinationFailed::SIGNATURE,
            "DestinationFailed(bytes32,address,address,address,address,bytes)"
        );
        assert_ne!(
            IInbox::DestinationFailed::SIGNATURE_HASH,
            IInbox::MessageReceived::SIGNATURE_HASH
        );
    }

    fn cc_style(data: &[u8]) -> String {
        format!(
            "server returned an error response: error code -32603: VM Exception while processing \
             transaction: revert, data: \"0x{}\"",
            alloy::hex::encode(data)
        )
    }

    /// Each #36 revert is recognised from raw selector data (Creditcoin-style node), from a decoded
    /// name (name-decoding node), and is kept apart from the generic revert and transport arms.
    #[test]
    fn delivery_reverts_classify_by_selector_and_by_name() {
        let id = B256::repeat_byte(0x02);
        let vf = IInbox::ValidationFailedWithNativeValue {
            messageId: id,
            value: U256::from(5u64),
        }
        .abi_encode();
        assert_eq!(
            classify_revert_str(&cc_style(&vf), None),
            Some(DeliveryRevert::ValidationFailedWithNativeValue)
        );
        assert_eq!(
            classify_revert_str("reverted: ValidationFailedWithNativeValue", None),
            Some(DeliveryRevert::ValidationFailedWithNativeValue)
        );

        let imd = IInbox::InvalidMessageDispatcher {
            dispatcher: Address::repeat_byte(0xdd),
        }
        .abi_encode();
        assert_eq!(
            classify_revert_str(&cc_style(&imd), None),
            Some(DeliveryRevert::InvalidMessageDispatcher)
        );

        let igd = IMessageDispatcher::InsufficientGasForDestination {}.abi_encode();
        assert_eq!(
            classify_revert_str(&cc_style(&igd), None),
            Some(DeliveryRevert::InsufficientGasForDestination)
        );
        // Structured revert data takes precedence over (an absent) string field.
        assert_eq!(
            classify_revert_str(
                "execution reverted",
                Some(IMessageDispatcher::InsufficientGasForDestination::SELECTOR)
            ),
            Some(DeliveryRevert::InsufficientGasForDestination)
        );

        let dup = IInbox::MessageAlreadyValidated { messageId: id }.abi_encode();
        assert_eq!(
            classify_revert_str(&cc_style(&dup), None),
            Some(DeliveryRevert::Duplicate)
        );
        assert_eq!(
            classify_revert_str("execution reverted: Already validated", None),
            Some(DeliveryRevert::Duplicate)
        );

        assert_eq!(
            classify_revert_str("execution reverted: VotesBelowThreshold", None),
            Some(DeliveryRevert::Other)
        );
        // Unknown selector, no phrasing: still a revert (data present), so Other — not a retry.
        assert_eq!(
            classify_revert_str(&cc_style(&[0x12, 0x34, 0x56, 0x78]), None),
            Some(DeliveryRevert::Other)
        );
        assert_eq!(classify_revert_str("connection refused", None), None);
        assert_eq!(
            classify_revert_str("error code -32000: insufficient funds for gas", None),
            None
        );
    }

    /// Build the error alloy hands back for a geth-style JSON-RPC revert: the selector lives only
    /// in the structured `data` field of the error payload.
    fn structured_revert(message: &str, data: &[u8]) -> alloy::contract::Error {
        // Deserialized rather than named: `ErrorPayload` lives in alloy-json-rpc, which the
        // umbrella crate only re-exports behind a feature this workspace does not enable.
        let payload = serde_json::from_value(serde_json::json!({
            "code": 3,
            "message": message,
            "data": format!("0x{}", alloy::hex::encode(data)),
        }))
        .unwrap();
        alloy::contract::Error::TransportError(alloy::transports::RpcError::ErrorResp(payload))
    }

    /// The mined-revert replay (and every send-time revert) must classify from the structured
    /// revert data, not only from the stringified error — geth-style nodes carry the selector in
    /// the JSON-RPC `data` field. A funded delivery pins gas and skips the estimate, so this
    /// replay is the only place it can learn `InsufficientGasForDestination` and bump gas.
    #[test]
    fn structured_revert_data_classifies_without_string_dialects() {
        let igd = IMessageDispatcher::InsufficientGasForDestination {}.abi_encode();
        let err = structured_revert("execution reverted", &igd);
        assert!(
            err.as_revert_data().is_some(),
            "fixture must carry structured revert data: {err}"
        );
        assert_eq!(
            classify_delivery_revert(&err),
            Some(DeliveryRevert::InsufficientGasForDestination)
        );

        let vf = IInbox::ValidationFailedWithNativeValue {
            messageId: B256::repeat_byte(0x04),
            value: U256::from(1u64),
        }
        .abi_encode();
        assert_eq!(
            classify_delivery_revert(&structured_revert("execution reverted", &vf)),
            Some(DeliveryRevert::ValidationFailedWithNativeValue)
        );
        let imd = IInbox::InvalidMessageDispatcher {
            dispatcher: Address::repeat_byte(0xdd),
        }
        .abi_encode();
        assert_eq!(
            classify_delivery_revert(&structured_revert("execution reverted", &imd)),
            Some(DeliveryRevert::InvalidMessageDispatcher)
        );
        // Structured RetryDeferred decodes retryAfter the same way.
        let deferred = IInbox::RetryDeferred {
            messageId: B256::repeat_byte(0x05),
            retryAfter: 1_800_000_777,
        }
        .abi_encode();
        assert_eq!(
            decode_retry_deferred(&structured_revert("execution reverted", &deferred)),
            Some(1_800_000_777)
        );
    }

    /// Every stage that ends in a terminal revert maps the classification to the same label: the
    /// #36 hard failures get their own series whether they surfaced at simulate, send, or in the
    /// mined-revert replay; an unrecognized revert shape gets its own `Unclassified` series
    /// (distinct from the generic `Reverted`, which still covers `InsufficientGasForDestination`
    /// and non-revert failures).
    #[test]
    fn revert_status_gives_36_errors_their_own_labels_at_every_stage() {
        assert_eq!(
            revert_status(Some(DeliveryRevert::ValidationFailedWithNativeValue)),
            DeliveryStatus::ValidationFailedWithNativeValue
        );
        assert_eq!(
            revert_status(Some(DeliveryRevert::InvalidMessageDispatcher)),
            DeliveryStatus::InvalidDispatcher
        );
        assert_eq!(
            revert_status(Some(DeliveryRevert::Duplicate)),
            DeliveryStatus::AlreadyValidated
        );
        assert_eq!(
            revert_status(Some(DeliveryRevert::InsufficientGasForDestination)),
            DeliveryStatus::Reverted
        );
        assert_eq!(
            revert_status(Some(DeliveryRevert::Other)),
            DeliveryStatus::Unclassified
        );
        assert_eq!(revert_status(None), DeliveryStatus::Reverted);
    }

    /// The top-up signal is idempotent on success but NOT on failure: a send that never completed
    /// must be retryable on the next under-funded refusal (bounded), and an in-flight one must not
    /// be doubled.
    #[test]
    fn top_up_ledger_retries_failed_sends_but_not_settled_or_in_flight_ones() {
        let id = B256::repeat_byte(0x06);
        let other = B256::repeat_byte(0x07);
        let mut ledger = TopUpLedger::default();

        // First request goes out; a second while in flight does not.
        assert_eq!(ledger.begin(id), Ok(1));
        assert_eq!(ledger.begin(id), Err("a request is already in flight"));
        // Independent messages do not interfere.
        assert_eq!(ledger.begin(other), Ok(1));

        // A failed send frees the slot for a retry, counting attempts.
        ledger.fail(id);
        assert_eq!(ledger.begin(id), Ok(2));
        ledger.fail(id);
        assert_eq!(ledger.begin(id), Ok(3));
        ledger.fail(id);
        // Budget spent: bounded, never a hot loop.
        assert_eq!(MAX_TOP_UP_ATTEMPTS, 3);
        assert_eq!(ledger.begin(id), Err("attempts exhausted"));

        // A landed (or deterministically rejected) request settles the message for good…
        ledger.settle(other);
        assert_eq!(ledger.begin(other), Err("already requested"));
        // …and a late failure report cannot un-settle it.
        ledger.fail(other);
        assert_eq!(ledger.begin(other), Err("already requested"));

        // A failure reported for an id the ledger never saw is recorded, not panicked on.
        let stray = B256::repeat_byte(0x08);
        ledger.fail(stray);
        assert_eq!(ledger.begin(stray), Ok(2));
    }

    /// `retryAfter` comes out of the RetryDeferred revert payload; a different error, a truncated
    /// payload, or no payload yields nothing (→ fixed backoff).
    #[test]
    fn retry_deferred_decodes_retry_after_from_revert_data() {
        let id = B256::repeat_byte(0x03);
        let deferred = IInbox::RetryDeferred {
            messageId: id,
            retryAfter: 1_800_000_123,
        }
        .abi_encode();
        assert_eq!(
            decode_retry_deferred_str(&cc_style(&deferred)),
            Some(1_800_000_123)
        );
        // Unknown hint: the contract encodes 0 — decodes as Some(0), which the scheduler treats
        // as "no hint".
        let unknown = IInbox::RetryDeferred {
            messageId: id,
            retryAfter: 0,
        }
        .abi_encode();
        assert_eq!(decode_retry_deferred_str(&cc_style(&unknown)), Some(0));
        // Wrong error, truncated payload, no payload.
        let other = IInbox::MessageAlreadyValidated { messageId: id }.abi_encode();
        assert_eq!(decode_retry_deferred_str(&cc_style(&other)), None);
        assert_eq!(
            decode_retry_deferred_str(&cc_style(&deferred[..deferred.len() - 8])),
            None
        );
        assert_eq!(decode_retry_deferred_str("connection refused"), None);
    }

    /// A usable hint replaces the fixed delay (plus margin); 0, past, missing-clock and absent
    /// hints fall back to the fixed schedule; a far-future hint is capped.
    #[test]
    fn pending_retry_delay_honours_retry_after_within_bounds() {
        let now = 1_800_000_000u64;
        assert_eq!(
            pending_retry_delay(0, None, Some(now)),
            PENDING_RETRY_DELAYS[0]
        );
        assert_eq!(
            pending_retry_delay(1, None, Some(now)),
            PENDING_RETRY_DELAYS[1]
        );
        assert_eq!(
            pending_retry_delay(2, None, Some(now)),
            PENDING_RETRY_DELAYS[2]
        );
        // Past the table: sticks to the last delay rather than panicking.
        assert_eq!(
            pending_retry_delay(9, None, Some(now)),
            PENDING_RETRY_DELAYS[2]
        );

        assert_eq!(
            pending_retry_delay(0, Some(now + 90), Some(now)),
            Duration::from_secs(90) + RETRY_DEFERRED_MARGIN
        );
        // 0 = "no schedule exposed"; a past timestamp = the window already opened.
        assert_eq!(
            pending_retry_delay(1, Some(0), Some(now)),
            PENDING_RETRY_DELAYS[1]
        );
        assert_eq!(
            pending_retry_delay(1, Some(now - 1), Some(now)),
            PENDING_RETRY_DELAYS[1]
        );
        assert_eq!(
            pending_retry_delay(1, Some(now), Some(now)),
            PENDING_RETRY_DELAYS[1]
        );
        // No local clock: cannot compute a wait, so the fixed schedule.
        assert_eq!(
            pending_retry_delay(0, Some(now + 90), None),
            PENDING_RETRY_DELAYS[0]
        );
        // Bogus far-future hint is capped.
        assert_eq!(
            pending_retry_delay(0, Some(now + 30 * 24 * 3600), Some(now)),
            MAX_RETRY_DEFERRED_WAIT
        );
    }

    /// +25% per attempt from the pinned gas (or the attested gasLimit when unpinned), clamped to the
    /// route cap, and `None` once the cap is reached so the loop terminates.
    #[test]
    fn gas_bump_is_25_percent_capped_at_the_route_limit() {
        assert_eq!(
            bumped_gas_limit(Some(1_000_000), None, 5_000_000),
            Some(1_250_000)
        );
        assert_eq!(
            bumped_gas_limit(Some(4_500_000), None, 5_000_000),
            Some(5_000_000)
        );
        assert_eq!(bumped_gas_limit(Some(5_000_000), None, 5_000_000), None);
        assert_eq!(bumped_gas_limit(Some(6_000_000), None, 5_000_000), None);
        // Nothing pinned: start from the attested gasLimit.
        assert_eq!(
            bumped_gas_limit(None, Some(400_000), 5_000_000),
            Some(500_000)
        );
        // Neither: nothing to bump from.
        assert_eq!(bumped_gas_limit(None, None, 5_000_000), None);
        // Always makes progress even for tiny values.
        assert_eq!(bumped_gas_limit(Some(1), None, 10), Some(2));
        // Chain of bumps from a funded 1M under the default cap terminates.
        let mut g = Some(1_000_000);
        let mut steps = 0;
        while let Some(next) = bumped_gas_limit(g, None, crate::config::DEFAULT_MAX_GAS_LIMIT) {
            assert!(next > g.unwrap());
            g = Some(next);
            steps += 1;
            assert!(steps < 20, "bump chain must converge on the cap");
        }
        assert_eq!(g, Some(crate::config::DEFAULT_MAX_GAS_LIMIT));
    }

    // -------------------------------------------------------------------------------------
    // Top-up foreclosure. An under-funded delivery is retried on the assumption that a
    // `topUpGasLimit` may still raise the funded gas. Both conditions below make that a hard
    // revert in `RelayerContract._checkTopUp`, so retrying past them is unbounded waste — this is
    // what let one usc-devnet message accumulate 469 attempts over 2.5 days.
    // -------------------------------------------------------------------------------------

    const T0: u64 = 1_787_610_830; // the deadline of the message that motivated this

    fn funding(deadline: Option<u64>, relay_settled: bool) -> MessageFunding {
        MessageFunding {
            gas: Some(100_000),
            delivery_deadline: deadline,
            relay_settled,
        }
    }

    #[test]
    fn a_settled_relay_forecloses_top_up_without_consulting_the_clock() {
        // Clock-free on purpose: `RelayAlreadySettled` does not depend on time, and passing `None`
        // proves the check does not silently rely on a clock being available.
        assert!(funding(Some(T0), true).top_up_foreclosed(None).is_some());
        assert!(funding(None, true).top_up_foreclosed(None).is_some());
    }

    #[test]
    fn a_deadline_past_the_grace_window_forecloses_top_up() {
        let grace = TOP_UP_DEADLINE_GRACE.as_secs();
        assert!(funding(Some(T0), false)
            .top_up_foreclosed(Some(T0 + grace + 1))
            .is_some());
    }

    #[test]
    fn a_deadline_inside_the_grace_window_still_allows_top_up() {
        // The contract compares against the *source chain's* clock, not ours, so a deadline that
        // has only just passed by our reckoning must not strand a still-rescuable message.
        let grace = TOP_UP_DEADLINE_GRACE.as_secs();
        assert!(funding(Some(T0), false)
            .top_up_foreclosed(Some(T0))
            .is_none());
        assert!(funding(Some(T0), false)
            .top_up_foreclosed(Some(T0 + grace))
            .is_none());
    }

    #[test]
    fn a_healthy_message_is_never_foreclosed() {
        assert!(funding(Some(T0), false)
            .top_up_foreclosed(Some(T0 - 3600))
            .is_none());
    }

    /// An unreadable ledger must behave exactly as it did before this tracking existed: retry.
    /// Terminating a delivery on the strength of a failed read would turn a transient source-RPC
    /// outage into permanent non-delivery, which is the failure class C1r exists to prevent.
    #[test]
    fn an_unknown_ledger_never_forecloses() {
        let u = MessageFunding::unknown();
        assert!(u.top_up_foreclosed(Some(T0 + 10_000_000)).is_none());
        assert!(u.top_up_foreclosed(None).is_none());
        assert!(u.gas.is_none(), "unknown funding must not pin a gas limit");
    }

    #[test]
    fn a_missing_local_clock_does_not_foreclose_on_the_deadline_alone() {
        assert!(funding(Some(T0), false).top_up_foreclosed(None).is_none());
    }

    #[test]
    fn duplicate_delivery_matches_all_dialects() {
        // The deployed SimpleInbox string revert.
        assert!(revert_duplicate_delivery(
            &"execution reverted: Already validated"
        ));
        // Decoded custom-error name (future inbox versions).
        assert!(revert_duplicate_delivery(
            &"reverted: MessageAlreadyValidated"
        ));
        // Raw selector data (Creditcoin-style node).
        let sel = alloy::hex::encode(IInbox::MessageAlreadyValidated::SELECTOR);
        assert!(revert_duplicate_delivery(&format!(
            "VM Exception while processing transaction: revert, data: \"0x{sel}\""
        )));
        // The receiver-side guard, decoded name (what a name-decoding node prints).
        assert!(revert_duplicate_delivery(
            &"reverted: MessageAlreadyProcessed"
        ));
        // The receiver-side guard as raw selector data — the usc-devnet 2026-09-01 case verbatim,
        // which the Inbox-only matching classified as a terminal revert.
        // Pin the selector to the on-chain artifact value so a mirror edit that changes the
        // signature (and thus silently stops matching real reverts) fails here, not on devnet.
        assert_eq!(
            IMessageReceiver::MessageAlreadyProcessed::SELECTOR,
            [0x73, 0x0a, 0xc1, 0xe2],
        );
        let sel = alloy::hex::encode(IMessageReceiver::MessageAlreadyProcessed::SELECTOR);
        assert!(revert_duplicate_delivery(&format!(
            "server returned an error response: error code 3: execution reverted, data: \"0x{sel}635ab2e71674df43451fb64cb3b06745c8ff56561727aaf688181774f5fb04c6\""
        )));
        // A transport failure is not a duplicate.
        assert!(!revert_duplicate_delivery(&"connection refused"));
        // An unrelated revert is not a duplicate either.
        assert!(!revert_duplicate_delivery(
            &"execution reverted: VotesBelowThreshold"
        ));
    }

    /// No job has run yet this worker's lifetime (registration-time silence) — the ticker must
    /// heartbeat so an idle-from-the-start route is never mistaken for wedged.
    #[test]
    fn idle_ticker_heartbeats_before_any_job_has_run() {
        assert!(idle_ticker_should_heartbeat(
            None,
            None,
            HEALTH_TICK,
            ERROR_GRACE_PERIOD
        ));
    }

    /// A job just succeeded (no error outstanding): the per-job heartbeat call already reported
    /// progress for this period, so the ticker must stand down rather than double-report.
    #[test]
    fn idle_ticker_stands_down_right_after_a_successful_job() {
        assert!(!idle_ticker_should_heartbeat(
            Some(Duration::from_secs(1)),
            None,
            HEALTH_TICK,
            ERROR_GRACE_PERIOD
        ));
    }

    /// Once a full tick interval has passed with no further job activity and no outstanding error,
    /// the route is genuinely idle again and the ticker resumes heartbeating on its own.
    #[test]
    fn idle_ticker_resumes_once_a_full_interval_has_passed_since_a_successful_job() {
        assert!(idle_ticker_should_heartbeat(
            Some(HEALTH_TICK),
            None,
            HEALTH_TICK,
            ERROR_GRACE_PERIOD
        ));
        assert!(idle_ticker_should_heartbeat(
            Some(HEALTH_TICK + Duration::from_secs(1)),
            None,
            HEALTH_TICK,
            ERROR_GRACE_PERIOD
        ));
    }

    /// A job just failed: the per-job `health.error` call already reported the accurate signal, so
    /// the ticker must stand down rather than paper over the failure with an unconditional
    /// heartbeat.
    #[test]
    fn idle_ticker_stands_down_right_after_a_failed_job() {
        assert!(!idle_ticker_should_heartbeat(
            Some(Duration::from_secs(1)),
            Some(Duration::from_secs(1)),
            HEALTH_TICK,
            ERROR_GRACE_PERIOD
        ));
    }

    /// The core regression this gate exists to prevent: the pool's own delivery backoff
    /// (`DELIVERY_RETRY_MAX`) can space retries up to five minutes apart, far slower than the 15s
    /// `HEALTH_TICK`. The ticker must keep standing down for the whole error-grace period no matter
    /// how long a single gap between job activity runs, so a still-retrying route can never have its
    /// run of failures papered over by this timer.
    #[test]
    fn idle_ticker_stands_down_through_a_full_retry_backoff_window() {
        assert!(!idle_ticker_should_heartbeat(
            Some(HEALTH_TICK),
            Some(HEALTH_TICK),
            HEALTH_TICK,
            ERROR_GRACE_PERIOD
        ));
        assert!(!idle_ticker_should_heartbeat(
            Some(ERROR_GRACE_PERIOD - Duration::from_secs(1)),
            Some(ERROR_GRACE_PERIOD - Duration::from_secs(1)),
            HEALTH_TICK,
            ERROR_GRACE_PERIOD
        ));
    }

    /// The exact scenario Bugbot flagged: a retry becoming *eligible* at `DELIVERY_RETRY_MAX` isn't
    /// the same as it being *dispatched* then — `collect_ready_deliveries` only runs on the pool's
    /// own `PRUNE_TICK_INTERVAL`, so an eligible retry can still be sitting queued, undispatched, at
    /// that instant. The ticker must not resume in that window: doing so would refresh `last_ok`
    /// while a retryable message is still waiting to go out, papering over an active failure loop.
    #[test]
    fn idle_ticker_does_not_resume_merely_because_the_backoff_cap_has_elapsed() {
        assert!(!idle_ticker_should_heartbeat(
            Some(DELIVERY_RETRY_MAX),
            Some(DELIVERY_RETRY_MAX),
            HEALTH_TICK,
            ERROR_GRACE_PERIOD
        ));
        assert!(!idle_ticker_should_heartbeat(
            Some(DELIVERY_RETRY_MAX + PRUNE_TICK_INTERVAL - Duration::from_secs(1)),
            Some(DELIVERY_RETRY_MAX + PRUNE_TICK_INTERVAL - Duration::from_secs(1)),
            HEALTH_TICK,
            ERROR_GRACE_PERIOD
        ));
    }

    /// Once the error-grace period has fully elapsed with no further failure — the backlog cleared,
    /// or the failing message was evicted from the pool and nothing remains to retry — the ticker
    /// resumes on its own rather than leaving the route wedged in `degraded`, or worse `stale`, over
    /// a failure with nothing left behind it.
    #[test]
    fn idle_ticker_resumes_once_the_error_grace_period_has_fully_elapsed() {
        assert!(idle_ticker_should_heartbeat(
            Some(ERROR_GRACE_PERIOD),
            Some(ERROR_GRACE_PERIOD),
            HEALTH_TICK,
            ERROR_GRACE_PERIOD
        ));
        assert!(idle_ticker_should_heartbeat(
            Some(Duration::from_secs(3600)),
            Some(Duration::from_secs(3600)),
            HEALTH_TICK,
            ERROR_GRACE_PERIOD
        ));
    }
}
