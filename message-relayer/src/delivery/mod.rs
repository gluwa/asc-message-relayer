//! Per-route delivery worker.
//!
//! Consumes [`DeliveryJob`]s from the vote pool and submits `Inbox.deliverMessage(...)` on the
//! destination chain. Implements the PoC §7 + §9 behaviour:
//!
//!  1. Refuse what can never be delivered: an envelope whose `nativeCoinValue` exceeds the route's
//!     `max_native_coin_value_wei`, or whose attested `gasLimit` exceeds `max_gas_limit`
//!     (asc-contracts #36 — the router only rejects `gasLimit == 0`, so an oversized one would be
//!     retried forever). Both are terminal with their own metric label.
//!  2. (Optional) `eth_call` simulate to catch `validateVotes` reverts before paying gas.
//!     Simulation distinguishes reverts (terminal / already-validated) from transport failures
//!     (returned to the pool's bounded retry) — a mere RPC blip must not drop a message.
//!  3. Send the transaction, watching for receipt (bounded by [`RECEIPT_TIMEOUT`] so a stuck
//!     underpriced tx cannot wedge the route's serial worker).
//!  4. Classify the outcome from the receipt logs. `MessagePending` and (#36)
//!     `MessageExecutionFailed` are **events on a successful tx**: the former means the dispatcher
//!     deferred/queued the message (retryable via `retryPendingMessage`), the latter that the
//!     destination call failed and the message is consumed for good (no retry; delivery still
//!     counts and is still paid). A mined-but-reverted tx is replayed to learn why: an
//!     `InsufficientGasForDestination` revert is retried with 25% more gas up to `max_gas_limit`.
//!  5. On `MessagePending`, schedule bounded `retryPendingMessage` attempts (permissionless),
//!     honouring a `RetryDeferred(retryAfter)` hint over the fixed backoff.
//!  6. On RPC-level failure, retry up to `delivery.max_retries` with backoff.
//!
//! The worker processes one job at a time per route — serial nonce management is the simplest
//! approach for PoC scope and matches PoC §7.2 ("optional multiple wallets for throughput, out
//! of PoC scope"). Each route runs in its own [`tokio::spawn`] so a slow destination chain
//! does not block the others.

use std::collections::HashSet;
use std::sync::Arc;
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
use crate::prom::{DeliveryStatus, Metrics};
use crate::revert::{is_revert, revert_data, revert_selector};

pub mod encode;

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

/// Bounded, permissionless `retryPendingMessage` schedule after a delivery lands in the
/// `MessagePending` state (dispatcher deferred/queued the message). Backoff gives the destination
/// time to recover (e.g. a rate-limit window); anyone else may also retry, so this is best-effort.
/// When the previous attempt reverted `RetryDeferred(retryAfter)` with a usable timestamp, that
/// timestamp (plus [`RETRY_DEFERRED_MARGIN`]) replaces the fixed delay — see
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

/// Longest the pending-retry task will honour a `retryAfter` hint for. A dispatcher hint is
/// advisory and unauthenticated by us; a bogus far-future value must not park a detached task for
/// days. Past this the attempt falls back to the fixed schedule (and, most likely, defers again
/// and exhausts its bounded budget — the message stays retryable on-chain by anyone).
const MAX_RETRY_DEFERRED_WAIT: Duration = Duration::from_secs(6 * 3600);

/// Job dispatched by the pool when a `messageHash` clears the threshold.
#[derive(Clone, Debug)]
pub struct DeliveryJob {
    pub chain_key: u64,
    pub message_id: B256,
    pub emitter: Address,
    /// Source Outbox the message was scanned from; second `deliverMessage` argument (#45).
    pub outbox: Address,
    pub message_hash: B256,
    pub payload: Vec<u8>,
    pub votes_calldata: Vec<u8>,
    pub signer_count: usize,
    pub indexed_at: Instant,
}

#[derive(Clone, Debug)]
pub struct DeliveryResult {
    pub chain_key: u64,
    pub message_hash: B256,
    pub outcome: DeliveryResultKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryResultKind {
    Delivered,
    Terminal,
    Retryable,
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
    cancel: CancellationToken,
) -> Result<()> {
    let chain_key = route.chain_key;
    let health_key = format!("delivery:{chain_key}");

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
    // until restart. Every send from this signer — this worker's, the detached
    // `spawn_pending_retry` tasks holding provider clones, and the set-update submitter, which
    // shares `route.signer_key` — serializes through `broadcast_locks` instead of through a
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
    // Beating on this interval means "the select loop is still turning", which is the property we
    // actually want to assert; per-job progress is reported separately below.
    let mut liveness = tokio::time::interval(HEALTH_TICK);
    liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!(chain_key, "🛑 delivery worker exiting on cancel");
                return Ok(());
            }
            _ = liveness.tick() => {
                health.heartbeat(&health_key);
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
                let funding = match (&source_provider, route.relayer_contract_address) {
                    (Some(p), Some(relayer_contract)) => {
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
                };
                let outcome = match handle_job(
                    &route,
                    &delivery_config,
                    &provider,
                    signer_address,
                    &broadcast_locks,
                    &job,
                    funding,
                    metrics.as_ref(),
                    top_up.as_mut(),
                ).await {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        error!(chain_key, message_id = %job.message_id, %err, "❌ delivery job failed");
                        DeliveryResultKind::Retryable
                    }
                };
                // Job finished (delivered, terminal, or retryable) — real forward progress.
                health.heartbeat(&health_key);
                if result_tx
                    .send(DeliveryResult {
                        chain_key: job.chain_key,
                        message_hash: job.message_hash,
                        outcome,
                    })
                    .await
                    .is_err()
                {
                    warn!(chain_key, "delivery result channel closed; worker exiting");
                    return Ok(());
                }
            }
        }
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

/// Sends `RelayerContract(Lite).requestTopUp(messageId, additionalGasNeeded)` on Creditcoin when a
/// delivery is refused for being under-funded, at most once per message for the life of the
/// process (`requested`). Signed by the route's ack (else claim) key — the same key that already
/// talks to the RelayerContract for `claimDelivery` — and serialized through the shared
/// [`crate::broadcast::BroadcastLocks`] so it cannot race the ack worker for that key's nonce.
///
/// The call is a pure on-chain signal (`TopUpRequested` event; no state change) for the payer /
/// quoter to act on with `topUpGasLimit`. It is permissionless, so whether to send it at all is
/// relayer policy: `ChainRoute::auto_request_top_up`, default off.
struct TopUpRequester {
    provider: DynProvider,
    relayer_contract: Address,
    signer_address: Address,
    broadcast_locks: Arc<crate::broadcast::BroadcastLocks>,
    /// Message ids already requested. Restarts forget this, so a message still under-funded
    /// across a restart is requested again — one duplicate event, harmless.
    requested: HashSet<B256>,
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
            requested: HashSet::new(),
        })
    }

    /// Request a top-up of `additional_gas` for `message_id`, unless already requested. Detached:
    /// the send + receipt wait must not sit in the serial delivery worker's critical path (it is
    /// a side signal, not part of delivering anything). The idempotency mark is taken *before*
    /// spawning so a second refusal of the same message while the first request is still in
    /// flight does not double-send.
    fn request(&mut self, chain_key: u64, message_id: B256, additional_gas: u64) {
        if !self.requested.insert(message_id) {
            debug!(chain_key, %message_id, "requestTopUp already sent for this message; not repeating");
            return;
        }
        let locks = self.broadcast_locks.clone();
        let provider = self.provider.clone();
        let relayer_contract = self.relayer_contract;
        let signer_address = self.signer_address;
        tokio::spawn(async move {
            let ledger = IRelayerContract::new(relayer_contract, &provider);
            let call = ledger.requestTopUp(message_id, U256::from(additional_gas));
            let sent = match locks
                .broadcast(signer_address, SEND_TIMEOUT, call.send())
                .await
            {
                Ok(res) => res,
                Err(stalled) => {
                    warn!(chain_key, %message_id, %stalled, "requestTopUp send did not complete");
                    return;
                }
            };
            match sent {
                Ok(builder) => {
                    match tokio::time::timeout(
                        RECEIPT_TIMEOUT,
                        crate::receipt::await_receipt(&builder),
                    )
                    .await
                    {
                        Ok(Ok(receipt)) if receipt.status() => {
                            info!(chain_key, %message_id, additional_gas, tx = %receipt.transaction_hash,
                                "🪙 requestTopUp emitted (TopUpRequested) — awaiting the payer's topUpGasLimit");
                        }
                        Ok(Ok(receipt)) => {
                            warn!(chain_key, %message_id, tx = %receipt.transaction_hash,
                                "requestTopUp tx mined but reverted");
                        }
                        Ok(Err(err)) => {
                            warn!(chain_key, %message_id, %err, "requestTopUp receipt failed");
                        }
                        Err(_) => {
                            warn!(chain_key, %message_id, "requestTopUp receipt timed out");
                        }
                    }
                }
                // A revert here (UnknownOperation / RelayAlreadySettled / DeliveryDeadlineReached)
                // means a top-up could not help anyway; the delivery path reaches the same
                // conclusion through `top_up_foreclosed` on its next pass. Not retried.
                Err(err) => {
                    warn!(chain_key, %message_id, %err, "requestTopUp rejected; not retrying");
                }
            }
        });
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
    /// #36: votes failed validation while native value was attached. Terminal for these votes.
    ValidationFailedWithNativeValue,
    /// #36: the Inbox's dispatcher has no code (value attached). Terminal until reconfigured.
    InvalidMessageDispatcher,
    /// #36: the destination call failed with too little gas to prove the attested `gasLimit` was
    /// forwarded. Retryable with a higher tx gas limit.
    InsufficientGasForDestination,
    /// Any other deterministic revert: retrying would revert identically.
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
/// `MessageExecutionFailed` (#36) is emitted *together with* `MessageDelivered`, so the plain
/// success arm is only reached when neither of the two qualifying events is present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiptClass {
    /// `MessageDelivered` alone: destination executed.
    Delivered,
    /// `MessageExecutionFailed` + `MessageDelivered`: consumed, destination call failed, no retry.
    DestinationFailed { dispatcher: Address },
    /// `MessagePending`: dispatcher deferred/queued; `retryPendingMessage` applies.
    Pending,
}

fn classify_success_logs<'a>(
    inbox: Address,
    logs: impl IntoIterator<Item = &'a Log>,
) -> ReceiptClass {
    let mut pending = false;
    for log in logs {
        if log.address() != inbox {
            continue;
        }
        match log.topics().first() {
            Some(t) if *t == IInbox::MessageExecutionFailed::SIGNATURE_HASH => {
                // topics[2] is the indexed `dispatcher` (left-padded address).
                let dispatcher = log
                    .topics()
                    .get(2)
                    .map(|t| Address::from_slice(&t[12..]))
                    .unwrap_or_default();
                return ReceiptClass::DestinationFailed { dispatcher };
            }
            Some(t) if *t == IInbox::MessagePending::SIGNATURE_HASH => pending = true,
            _ => {}
        }
    }
    if pending {
        ReceiptClass::Pending
    } else {
        ReceiptClass::Delivered
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
fn pending_retry_delay(attempt: usize, retry_after: Option<u64>, now: Option<u64>) -> Duration {
    let fixed = PENDING_RETRY_DELAYS[attempt.min(PENDING_RETRY_DELAYS.len() - 1)];
    match (retry_after, now) {
        (Some(ts), Some(now)) if ts > now => {
            (Duration::from_secs(ts - now) + RETRY_DEFERRED_MARGIN).min(MAX_RETRY_DEFERRED_WAIT)
        }
        _ => fixed,
    }
}

/// `Some(retryAfter)` when `err` is a `RetryDeferred(messageId, retryAfter)` revert from
/// `retryPendingMessage`. Structured revert data first, then the `data: "0x…"` field of the error
/// string (Creditcoin-style nodes).
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

/// Log + count a deterministic revert seen before the send (simulate / estimate) and decide the
/// job's fate. `InsufficientGasForDestination` is not terminal — the send loop bumps gas — so it
/// proceeds; everything else that reverts is settled here.
fn settle_pre_send_revert(
    route: &ChainRoute,
    job: &DeliveryJob,
    metrics: &dyn crate::prom::MetricsTrait,
    stage: &str,
    revert: DeliveryRevert,
    err: &alloy::contract::Error,
) -> Stage {
    let chain_key = route.chain_key;
    let message_id = job.message_id;
    match revert {
        DeliveryRevert::Duplicate => {
            debug!(chain_key, %message_id, "{stage} detected already-validated; idempotent success");
            metrics.inc_deliver_tx(chain_key, DeliveryStatus::AlreadyValidated);
            Stage::Done(DeliveryResultKind::Delivered)
        }
        DeliveryRevert::ValidationFailedWithNativeValue => {
            metrics.inc_deliver_tx(chain_key, DeliveryStatus::ValidationFailedWithNativeValue);
            error!(chain_key, %message_id, %err,
                "❌ {stage}(deliverMessage) reverted ValidationFailedWithNativeValue — the votes fail \
                 validation and native value was attached; terminal for this vote bundle");
            Stage::Done(DeliveryResultKind::Terminal)
        }
        DeliveryRevert::InvalidMessageDispatcher => {
            metrics.inc_deliver_tx(chain_key, DeliveryStatus::InvalidDispatcher);
            error!(chain_key, %message_id, inbox = %route.inbox_address, %err,
                "❌ {stage}(deliverMessage) reverted InvalidMessageDispatcher — the Inbox's dispatcher \
                 has no code; terminal until the Inbox is reconfigured");
            Stage::Done(DeliveryResultKind::Terminal)
        }
        DeliveryRevert::InsufficientGasForDestination => {
            warn!(chain_key, %message_id, %err,
                "{stage}(deliverMessage) reverted InsufficientGasForDestination; proceeding to send \
                 with a higher gas limit");
            Stage::Proceed
        }
        DeliveryRevert::Other => {
            metrics.inc_deliver_tx(chain_key, DeliveryStatus::Reverted);
            warn!(chain_key, %message_id, %err, "{stage}(deliverMessage) reverted; treating as terminal");
            Stage::Done(DeliveryResultKind::Terminal)
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
) -> Result<DeliveryResultKind> {
    let inbox = IInbox::new(route.inbox_address, provider);

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
            return Ok(DeliveryResultKind::Terminal);
        }
    }

    if delivery_config.simulate_before_send {
        // Validity check only — do NOT pin `.gas()` here. The simulate exists to catch
        // `validateVotes` logic reverts; constraining it to the funded gas would conflate an
        // under-funded message (out-of-gas) with a genuine revert and add head-vs-mined-block
        // boundary nondeterminism. Gas is pinned on the real send below.
        if let Err(err) = inbox
            .deliverMessage(
                job.message_id,
                job.outbox,
                job.emitter,
                Bytes::from(job.payload.clone()),
                Bytes::from(job.votes_calldata.clone()),
            )
            .value(native_value)
            .call()
            .await
        {
            // If the inbox already accepted this message we treat it as success (idempotent —
            // PoC §6.5). Any other *revert* is deterministic, so we don't burn gas. A transport
            // failure (RPC blip, timeout) is neither — the pool retries it with backoff; treating
            // it as terminal would silently drop a deliverable message.
            match classify_delivery_revert(&err) {
                Some(revert) => {
                    if let Stage::Done(kind) =
                        settle_pre_send_revert(route, job, metrics, "simulate", revert, &err)
                    {
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
            // `simulate_before_send` is off, this is where a deterministic revert first surfaces,
            // and blanket-retrying a permanent revert would loop forever. Only genuine transport
            // errors are retryable (we must not send unverified: an under-funded message would
            // OOG and be dropped as terminal — the exact failure this guard exists to prevent).
            Ok(Err(err)) => match classify_delivery_revert(&err) {
                Some(revert) => {
                    if let Stage::Done(kind) =
                        settle_pre_send_revert(route, job, metrics, "estimate", revert, &err)
                    {
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
                Bytes::from(job.payload.clone()),
                Bytes::from(job.votes_calldata.clone()),
            )
            .value(native_value);
        if let Some(gas) = gas_limit {
            tx = tx.gas(gas);
        }
        // `send()` is several RPC round trips (gas, fee, nonce, `eth_sendRawTransaction`) and alloy's
        // HTTP transport sets no timeout, so on a black-holed endpoint this await never returns and
        // parks the route — the same hazard FUNDED_GAS_READ_TIMEOUT and RECEIPT_TIMEOUT guard.
        //
        // Serialized on the signer so the chain-read nonce this send is about to fetch already
        // reflects every earlier broadcast from the same key — including the detached
        // `retryPendingMessage` tasks and the set-update submitter. The guard covers only the
        // broadcast; the receipt is awaited below, outside it, or a single confirmation would block
        // every other sender on the key. Either stall is retryable and consumes no nonce.
        let pending = match broadcast_locks
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
                            // execute: the Inbox emits `MessagePending` (deferred/queued — stored
                            // for `retryPendingMessage`) or, since #36, `MessageExecutionFailed`
                            // alongside `MessageDelivered` (destination call failed, message
                            // consumed). Both are detected from the receipt logs, not a revert.
                            break match classify_success_logs(
                                route.inbox_address,
                                receipt.inner.logs(),
                            ) {
                                ReceiptClass::Delivered => SendOutcome::Succeeded,
                                ReceiptClass::Pending => SendOutcome::Pending,
                                ReceiptClass::DestinationFailed { dispatcher } => {
                                    SendOutcome::DestinationFailed { dispatcher }
                                }
                            };
                        }
                        // Mined but reverted. Replay the exact call at that block to learn why: an
                        // `InsufficientGasForDestination` is ours to fix by resending with more gas;
                        // a duplicate means another relayer's tx landed in the same block (success);
                        // anything else is a deterministic revert and terminal.
                        let reason = replay_revert_reason(
                            &inbox,
                            job,
                            native_value,
                            gas_limit,
                            receipt.block_number,
                        )
                        .await;
                        let class = reason.as_deref().and_then(|r| classify_revert_str(r, None));
                        let reason = reason.unwrap_or_else(|| "tx mined but reverted".into());
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
                                        break SendOutcome::Reverted(format!(
                                            "InsufficientGasForDestination at the route's \
                                             max_gas_limit ({}): {reason}",
                                            route.max_gas_limit
                                        ));
                                    }
                                }
                            }
                            _ => break SendOutcome::Reverted(reason),
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
                            break SendOutcome::Reverted(format!(
                                "InsufficientGasForDestination at the route's max_gas_limit ({}): {err}",
                                route.max_gas_limit
                            ));
                        }
                    }
                }
                // Deterministic contract revert at send / gas-estimation time — retrying would
                // revert identically, so don't burn the retry budget on it.
                Some(revert) => break SendOutcome::Reverted(revert_summary(revert, &err)),
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
        SendOutcome::Succeeded => {
            metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::Succeeded);
            metrics.observe_time_to_deliver(started.elapsed());
            info!(
                chain_key = route.chain_key,
                message_id = %job.message_id,
                signer_count = job.signer_count,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "✅ message delivered"
            );
            Ok(DeliveryResultKind::Delivered)
        }
        SendOutcome::DestinationFailed { dispatcher } => {
            // Delivered and consumed (processedAt set) — the relayer is paid on claim — but the
            // destination call failed for good. Nothing to retry: `retryPendingMessage` reverts
            // `MessageNotPending`. Surfaced distinctly so a misbehaving destination dApp shows up
            // as its own series instead of inflating `Succeeded`.
            metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::DestinationFailed);
            metrics.observe_time_to_deliver(started.elapsed());
            warn!(
                chain_key = route.chain_key,
                message_id = %job.message_id,
                %dispatcher,
                signer_count = job.signer_count,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "⚠️ message delivered but the destination call FAILED (MessageExecutionFailed) — \
                 consumed on-chain, no retry possible; delivery still counts for the fee claim"
            );
            Ok(DeliveryResultKind::Delivered)
        }
        SendOutcome::AlreadyValidated => {
            metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::AlreadyValidated);
            info!(
                chain_key = route.chain_key,
                message_id = %job.message_id,
                "↩️ another relayer already delivered — idempotent success"
            );
            Ok(DeliveryResultKind::Delivered)
        }
        SendOutcome::Pending => {
            metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::Pending);
            warn!(
                chain_key = route.chain_key,
                message_id = %job.message_id,
                "⚠️ votes validated but the dispatcher deferred/queued the message — left pending; \
                 scheduling bounded retryPendingMessage attempts"
            );
            // The votes are consumed on-chain (`validatedMessages[messageId] = true`), so from the
            // pool's perspective delivery is complete — a re-dispatch would revert as a duplicate.
            // The remaining `retryPendingMessage` work is permissionless best-effort.
            spawn_pending_retry(
                (*provider).clone(),
                signer_address,
                broadcast_locks.clone(),
                *inbox.address(),
                job.message_id,
                route.chain_key,
            );
            Ok(DeliveryResultKind::Delivered)
        }
        SendOutcome::Reverted(reason) => {
            metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::Reverted);
            error!(
                chain_key = route.chain_key,
                message_id = %job.message_id,
                %reason,
                "❌ delivery reverted; no further retries"
            );
            Ok(DeliveryResultKind::Terminal)
        }
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

/// Human-readable reason for a terminal send-time revert, naming the #36 errors that would
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
/// same `msg.value` and gas, to recover the revert reason the receipt does not carry. Best-effort
/// and bounded: `None` when the replay succeeds (state moved on) or cannot be made in time — the
/// caller then falls back to a generic terminal revert, which is what it did before this existed.
async fn replay_revert_reason<P: Provider>(
    inbox: &IInbox::IInboxInstance<P>,
    job: &DeliveryJob,
    native_value: U256,
    gas_limit: Option<u64>,
    block_number: Option<u64>,
) -> Option<String> {
    let mut call = inbox
        .deliverMessage(
            job.message_id,
            job.outbox,
            job.emitter,
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
        Ok(Err(err)) => Some(err.to_string()),
        Ok(Ok(_)) => None,
        Err(_elapsed) => None,
    }
}

#[derive(Debug)]
enum SendOutcome {
    Succeeded,
    AlreadyValidated,
    /// Tx succeeded but the receipt carries `MessagePending` — the dispatcher deferred/queued the
    /// message and it is stored for `retryPendingMessage`.
    Pending,
    /// Tx succeeded and the receipt carries `MessageExecutionFailed` (#36): the destination call
    /// failed, the message is consumed, no retry is possible.
    DestinationFailed {
        dispatcher: Address,
    },
    /// Deterministic revert (mined-and-reverted, or revert at send/estimation time).
    Reverted(String),
    /// Transient infrastructure failure — returned to the pool's bounded retry.
    Failed(String),
}

/// Bounded, detached best-effort `retryPendingMessage` attempts. Detached because it must not
/// block the route's serial delivery worker; bounded ([`PENDING_RETRY_DELAYS`]) because the call
/// is permissionless — anyone (including a future relayer restart) can retry a message that is
/// still pending, so giving up here strands nothing. A `RetryDeferred(retryAfter)` revert (#36)
/// moves the next attempt to `retryAfter` instead of the fixed backoff (still counted against the
/// same bounded budget).
fn spawn_pending_retry<P: Provider + 'static>(
    provider: P,
    signer_address: Address,
    broadcast_locks: Arc<crate::broadcast::BroadcastLocks>,
    inbox_address: Address,
    message_id: B256,
    chain_key: u64,
) {
    tokio::spawn(async move {
        let inbox = IInbox::new(inbox_address, &provider);
        // `retryAfter` from the previous attempt's `RetryDeferred`, if any.
        let mut retry_after: Option<u64> = None;
        for attempt in 0..PENDING_RETRY_DELAYS.len() {
            let delay = pending_retry_delay(attempt, retry_after, now_unix());
            if let Some(ts) = retry_after {
                info!(chain_key, %message_id, attempt, retry_after = ts, delay_secs = delay.as_secs(),
                    "⏳ retryPendingMessage deferred by the dispatcher; waiting for retryAfter");
            }
            retry_after = None;
            tokio::time::sleep(delay).await;
            // Someone (a dApp user, another relayer) may have completed the retry meanwhile.
            match inbox.isPending(message_id).call().await {
                Ok(ret) if !ret => {
                    info!(chain_key, %message_id, "♻️ pending message already resolved");
                    return;
                }
                Ok(_) => {}
                Err(err) => {
                    warn!(chain_key, %message_id, %err, "isPending check failed; attempting retry anyway");
                }
            }
            // Serialized and bounded like the delivery send: this task runs detached but signs with
            // the same key as the worker that spawned it, so an unserialized broadcast here would
            // race the worker for the same chain-read nonce.
            let sent = match broadcast_locks
                .broadcast(
                    signer_address,
                    SEND_TIMEOUT,
                    inbox.retryPendingMessage(message_id).send(),
                )
                .await
            {
                Ok(res) => res,
                Err(stalled) => {
                    warn!(chain_key, %message_id, attempt, %stalled, "retryPendingMessage send did not complete");
                    continue;
                }
            };
            match sent {
                Ok(builder) => {
                    match tokio::time::timeout(
                        RECEIPT_TIMEOUT,
                        crate::receipt::await_receipt(&builder),
                    )
                    .await
                    {
                        Ok(Ok(receipt)) if receipt.status() => {
                            // Executed — or (#36) consumed as a destination failure: either way
                            // the message is no longer pending.
                            match classify_success_logs(inbox_address, receipt.inner.logs()) {
                                ReceiptClass::DestinationFailed { dispatcher } => {
                                    warn!(chain_key, %message_id, %dispatcher,
                                        "♻️ retryPendingMessage consumed the message but the destination call FAILED (MessageExecutionFailed)");
                                }
                                _ => {
                                    info!(chain_key, %message_id, "♻️ retryPendingMessage succeeded")
                                }
                            }
                            return;
                        }
                        Ok(Ok(_)) => {
                            warn!(chain_key, %message_id, attempt, "retryPendingMessage tx reverted");
                        }
                        Ok(Err(err)) => {
                            warn!(chain_key, %message_id, attempt, %err, "retryPendingMessage receipt failed");
                        }
                        Err(_) => {
                            warn!(chain_key, %message_id, attempt, "retryPendingMessage receipt timed out");
                        }
                    }
                }
                Err(err) => {
                    // The node's gas estimation reverted before anything was broadcast. A
                    // `RetryDeferred` carries the dispatcher's next-available hint: honour it.
                    match decode_retry_deferred(&err) {
                        Some(ts) => {
                            retry_after = Some(ts);
                            debug!(chain_key, %message_id, attempt, retry_after = ts, %err,
                                "retryPendingMessage reverted RetryDeferred");
                        }
                        None => {
                            warn!(chain_key, %message_id, attempt, %err, "retryPendingMessage send failed");
                        }
                    }
                }
            }
        }
        warn!(
            chain_key,
            %message_id,
            "retryPendingMessage attempts exhausted; message stays retryable on-chain \
             (permissionless retryPendingMessage)"
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::LogData;

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

    fn addr_topic(a: Address) -> B256 {
        B256::left_padding_from(a.as_slice())
    }

    /// Receipt fixtures for the three successful-tx shapes the Inbox can produce. #36's
    /// `MessageExecutionFailed` arrives *with* `MessageDelivered`, so it must win over the plain
    /// success arm, and it must carry the dispatcher out of topics[2].
    #[test]
    fn success_receipt_logs_classify_delivered_pending_and_destination_failed() {
        let inbox = Address::repeat_byte(0xaa);
        let other = Address::repeat_byte(0xbb);
        let dispatcher = Address::repeat_byte(0xdd);
        let relayer = Address::repeat_byte(0xee);
        let id = B256::repeat_byte(0x01);

        let delivered = inbox_log(
            inbox,
            vec![
                IInbox::MessageDelivered::SIGNATURE_HASH,
                id,
                addr_topic(other),
                addr_topic(relayer),
            ],
        );
        let failed = inbox_log(
            inbox,
            vec![
                IInbox::MessageExecutionFailed::SIGNATURE_HASH,
                id,
                addr_topic(dispatcher),
                addr_topic(relayer),
            ],
        );
        let pending = inbox_log(
            inbox,
            vec![
                IInbox::MessagePending::SIGNATURE_HASH,
                id,
                addr_topic(dispatcher),
                addr_topic(relayer),
            ],
        );
        // The same topic0 from a different contract (a dApp re-emitting) must not count.
        let foreign_failed = inbox_log(
            other,
            vec![
                IInbox::MessageExecutionFailed::SIGNATURE_HASH,
                id,
                addr_topic(dispatcher),
                addr_topic(relayer),
            ],
        );

        assert_eq!(
            classify_success_logs(inbox, [&delivered]),
            ReceiptClass::Delivered
        );
        assert_eq!(
            classify_success_logs(inbox, [&failed, &delivered]),
            ReceiptClass::DestinationFailed { dispatcher }
        );
        // Order-independent.
        assert_eq!(
            classify_success_logs(inbox, [&delivered, &failed]),
            ReceiptClass::DestinationFailed { dispatcher }
        );
        assert_eq!(
            classify_success_logs(inbox, [&pending]),
            ReceiptClass::Pending
        );
        assert_eq!(
            classify_success_logs(inbox, [&foreign_failed, &delivered]),
            ReceiptClass::Delivered
        );
        assert_eq!(
            classify_success_logs(inbox, std::iter::empty()),
            ReceiptClass::Delivered
        );
    }

    /// The topic0 values the classifier keys on are the compiled contract's (pinned by the
    /// abi_surface gate); this pins the Rust side so a mirror edit cannot move them unnoticed.
    #[test]
    fn message_execution_failed_topic0_is_the_36_signature() {
        assert_eq!(
            IInbox::MessageExecutionFailed::SIGNATURE,
            "MessageExecutionFailed(bytes32,address,address)"
        );
        assert_ne!(
            IInbox::MessageExecutionFailed::SIGNATURE_HASH,
            IInbox::MessageDelivered::SIGNATURE_HASH
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
}
