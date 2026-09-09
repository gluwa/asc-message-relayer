//! Claim submitter — the "relayer on both sides" (client chain → Creditcoin direction).
//!
//! The reverse of the vote path: a user acts on the **client** chain (e.g. locks tokens on the
//! bridge), and the resulting state change is carried to **Creditcoin** by proof, not by attestor
//! votes — the client chain's content is attested wholesale, so a native USC proof of the tx is
//! all the Creditcoin-side contract needs. For each route that opts in (`route.claim = Some(..)`),
//! this worker:
//!
//!  1. Watches the client chain for the configured intent event (currently the bridge's
//!     `Locked(address indexed ccRecipient, uint256 amount, uint256 nonce)`) on the configured
//!     source contract.
//!  2. For each emitting transaction, fetches a native USC proof from the proof-gen API
//!     (`GET {proof_gen_url}/api/v1/proof-by-tx/{chain_key}/{tx_hash}`).
//!  3. Submits the proof to the Creditcoin-side target (currently `CcBridge.claim(..)`), which
//!     verifies it against the block-prover precompile, decodes the `Locked` logs itself, and
//!     releases funds to the recipients proven in those logs.
//!
//! The submission is **permissionless and unredirectable** — the target contract pays only the
//! recipients encoded in the *proven* logs, never the caller — so this worker needs gas on
//! Creditcoin but no authority, and racing a user's manual claim is harmless (`AlreadyClaimed`
//! dedup on-chain).
//!
//! The target call is deliberately isolated: swapping `CcBridge.claim` for the generic
//! `IUSCBridgeInbound.bridgeFromIntent(chainKey, blockHeight, inclusionProof, continuityProof)`
//! when it deploys is an ABI + config change confined to this module (same proof arguments).
//!
//! Submission is keyed (and deduped) by client-chain **transaction hash**: one tx may contain
//! several `Locked` logs and the target processes all of them in a single call.

use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::network::EthereumWallet;
use alloy::primitives::{keccak256, Address, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::{SolError, SolEvent, SolValue};
use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::checkpoint::CheckpointStore;
use crate::config::{ChainRoute, ClaimConfig};
use crate::pending::{BoundedSeen, PendingTxs};
use crate::proofgen::{ProofFetch, ProofGenClient};

/// Poll cadence for the client-chain intent watcher and the pending-proof retry queue.
pub const CLAIM_POLL_INTERVAL_SECS: u64 = 6;

/// Maximum `encodedTransaction` size accepted on-chain by the claim target. Mirrors
/// `MAX_ENCODED_TRANSACTION_BYTES` in `CcBridge.sol`; keep the two in sync.
pub const MAX_ENCODED_TRANSACTION_BYTES: usize = 500_000;

/// Hard cap on the unclaimed-tx queue (see the equivalent in the ack submitter).
const MAX_PENDING_CLAIMS: usize = 10_000;
/// Hard cap on the recently-finished dedup set.
const MAX_DONE_TRACKED: usize = 10_000;
/// Most pending txs attempted per tick.
const MAX_CLAIMS_PER_TICK: usize = 256;
/// Maximum concurrent proof-fetch + submit attempts within a tick.
const MAX_CLAIM_CONCURRENCY: usize = 8;
/// Maximum block span per `eth_getLogs` scan (public RPCs cap the queryable range).
const MAX_BLOCKS_PER_SCAN: u64 = 2_000;
/// Upper bound on waiting for the claim receipt so one stuck tx cannot wedge the pipeline.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(120);
/// Upper bound on a single `claim` broadcast (gas/fee/nonce reads plus `eth_sendRawTransaction`).
/// Alloy's HTTP transport sets no timeout, so a black-holed Creditcoin RPC would otherwise park the
/// attempt, the tick's whole batch, and the worker's cancel branch. Also bounds how long one attempt
/// can hold the signer's broadcast slot. See `crate::ack::SEND_TIMEOUT`.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// Retry cadence while the proof block is not attested yet (`BlockNotReady`). This is the normal
/// early state — client-chain finality plus attestation takes minutes on real chains.
const NOT_READY_RETRY: Duration = Duration::from_secs(15);
/// Give up on a tx whose proof never becomes ready.
const MAX_CLAIM_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// Give up loudly after this many transient submit failures (unfunded signer, dead RPC).
const MAX_CLAIM_TRANSIENT_ATTEMPTS: u32 = 20;

sol! {
    /// The client-chain intent event this submitter watches. For the bridge PoC that is the
    /// destination bridge's `Locked` event; the signature must match `AnvilBridge.sol` exactly
    /// or discovery silently matches nothing.
    #[sol(rpc)]
    contract ISourceBridge {
        event Locked(address indexed ccRecipient, uint256 amount, uint256 nonce);
    }

    /// The Creditcoin-side proof consumer (currently `CcBridge`). Proof argument structs are
    /// declared locally (identical ABI layout to the shared `write_ability::abi` ones — sol!
    /// generates distinct Rust types per macro invocation, hence the `From` conversions below).
    #[sol(rpc)]
    contract IClaimTarget {
        function claim(
            uint64 height,
            bytes calldata encodedTransaction,
            MerkleProof calldata merkleProof,
            ContinuityProof calldata continuityProof
        ) external;

        /// Replay-protection mapping: `keccak256(abi.encode(ccRecipient, amount, nonce))` → bool.
        /// Read by the pre-check so already-claimed locks never cost a proof fetch.
        function claimed(bytes32 key) external view returns (bool);

        error AlreadyClaimed();
        error ProofVerificationFailed();
        error NoLockedLogs();
        error WrongEmitter(address emitter);
        error MalformedLockedLog();
        error UnsupportedTxType(uint8 txType);
        error EncodedTransactionTooLarge(uint256 size, uint256 maxSize);
    }

    struct MerkleProofEntry {
        bytes32 hash;
        bool isLeft;
    }

    struct MerkleProof {
        bytes32 root;
        MerkleProofEntry[] siblings;
    }

    struct ContinuityProof {
        bytes32 lowerEndpointDigest;
        bytes32[] roots;
    }
}

impl From<crate::abi::MerkleProof> for MerkleProof {
    fn from(m: crate::abi::MerkleProof) -> Self {
        Self {
            root: m.root,
            siblings: m
                .siblings
                .into_iter()
                .map(|s| MerkleProofEntry {
                    hash: s.hash,
                    isLeft: s.isLeft,
                })
                .collect(),
        }
    }
}

impl From<crate::abi::ContinuityProof> for ContinuityProof {
    fn from(c: crate::abi::ContinuityProof) -> Self {
        Self {
            lowerEndpointDigest: c.lowerEndpointDigest,
            roots: c.roots,
        }
    }
}

/// The claim target's replay key for one `Locked` event:
/// `keccak256(abi.encode(ccRecipient, amount, nonce))` — must match `CcBridge.claim` exactly.
fn claim_key(
    recipient: Address,
    amount: alloy::primitives::U256,
    nonce: alloy::primitives::U256,
) -> B256 {
    keccak256((recipient, amount, nonce).abi_encode())
}

/// Spawn the claim submitter for one route. Returns immediately when the route has no `claim`
/// config; otherwise loops until `cancel` fires. `scan_lookback_blocks` rewinds the persisted
/// cursor on startup so claims in flight when the process died are re-discovered.
pub async fn run(
    route: ChainRoute,
    creditcoin_eth_rpc_url: String,
    checkpoint: Option<Arc<CheckpointStore>>,
    scan_lookback_blocks: u64,
    health: Arc<crate::health::Health>,
    broadcast_locks: Arc<crate::broadcast::BroadcastLocks>,
    cancel: CancellationToken,
) -> Result<()> {
    let chain_key = route.chain_key;
    let checkpoint_key = format!("claim:{chain_key}");
    let health_key = checkpoint_key.clone();
    let Some(claim) = route.claim.clone() else {
        debug!(chain_key, "claim disabled for route; submitter not started");
        return Ok(());
    };

    // Register with the health watchdog BEFORE any fallible or blocking setup — see the identical
    // comment in `crate::ack::run` for why (`Health::status` cannot see a component that never
    // registered, and every connect plus the first-boot `get_block_number` below is an unbounded
    // RPC await). Must stay *after* the `route.claim` guard above.
    health.heartbeat(&health_key);

    // Read-only provider on the client chain (where the intent events are emitted).
    let client_provider = ProviderBuilder::new()
        .connect(&route.destination_rpc_url)
        .await
        .with_context(|| {
            format!(
                "chain_key {chain_key}: claim submitter failed to connect to client-chain RPC at {}",
                route.destination_rpc_url
            )
        })?;

    // Wallet-bearing provider on Creditcoin, where the claim is submitted. Permissionless: the
    // signer needs gas only — payouts go to the recipients proven in the Locked logs.
    let signer: PrivateKeySigner = claim
        .signer_key
        .trim()
        .parse()
        .with_context(|| format!("chain_key {chain_key}: invalid claim.signer_key"))?;
    let submitter_address = signer.address();
    // Chain-read nonces, with the submit loop's `MAX_CLAIM_CONCURRENCY` fan-out serialized on the
    // submitter address through `broadcast_locks` rather than through a per-provider local counter —
    // so a failed broadcast leaves no nonce gap, and routes sharing this Creditcoin key coordinate
    // too. See `crate::ack::run` and `crate::broadcast`.
    let cc_provider = crate::broadcast::chain_nonce_builder()
        .wallet(EthereumWallet::from(signer))
        .connect(&creditcoin_eth_rpc_url)
        .await
        .with_context(|| {
            format!(
                "chain_key {chain_key}: claim submitter failed to connect to Creditcoin EVM RPC \
                 at {creditcoin_eth_rpc_url}"
            )
        })?;

    let client = ProofGenClient::new(&claim.proof_gen_url)?;

    info!(
        chain_key,
        source_bridge = %claim.source_bridge_address,
        target = %claim.target_address,
        submitter = %submitter_address,
        proof_gen_url = %claim.proof_gen_url,
        "🎫 claim submitter online"
    );

    // Resume from the persisted cursor, rewound by the lookback (pending queue is memory-only;
    // re-processing is cheap — already-claimed locks are skipped by the claimed() pre-check).
    let mut last_seen = match checkpoint.as_ref().and_then(|c| c.get(&checkpoint_key)) {
        Some(block) => {
            let resume = block.saturating_sub(scan_lookback_blocks);
            info!(
                chain_key,
                checkpoint = block,
                resume_from = resume + 1,
                "↩️ resuming claim scan from checkpoint (rewound by lookback)"
            );
            resume
        }
        None => {
            if let Some(start) = claim.start_block {
                info!(
                    chain_key,
                    start_block = start,
                    "⏮️ no claim checkpoint; starting initial scan from configured block"
                );
                start.saturating_sub(1)
            } else {
                client_provider.get_block_number().await.with_context(|| {
                    format!("chain_key {chain_key}: claim submitter failed to read chain head")
                })?
            }
        }
    };

    let mut pending = PendingTxs::new(MAX_PENDING_CLAIMS);
    let mut done = BoundedSeen::new(MAX_DONE_TRACKED);

    let mut tick = tokio::time::interval(Duration::from_secs(crate::config::poll_secs_override(
        "RELAYER_CLAIM_POLL_SECS",
        CLAIM_POLL_INTERVAL_SECS,
    )));
    let mut pacer = crate::pacing::RateLimitPacer::default();
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!(chain_key, "🛑 claim submitter exiting on cancel");
                return Ok(());
            }
            _ = tick.tick() => {
                // Rate-limit pacing: while a deferral window is active, skip the tick entirely —
                // no sleeping inside the select arm (see `crate::pacing`).
                if let Some(remaining) = pacer.deferring() {
                    tracing::debug!(chain_key, remaining_ms = remaining.as_millis() as u64,
                        "⏸️ pacing claim discovery — skipping tick");
                    continue;
                }
                let mut rate_limited = false;
                match discover_locks(
                    chain_key,
                    claim.source_bridge_address,
                    claim.confirmation_depth,
                    &client_provider,
                    &mut last_seen,
                    &mut pending,
                    &done,
                ).await {
                    Ok(()) => {
                        // Successful client-chain scan = loop progress (C2r).
                        health.heartbeat(&health_key);
                        if let Some(cp) = &checkpoint {
                            // Never persist the cursor past a still-pending lock: a restart then
                            // rescans from before the oldest unfinished tx and re-discovers it —
                            // regardless of how long it was pending (proof-gen outage, backoff).
                            // The in-memory cursor keeps advancing; re-discovery is idempotent via
                            // the `claimed()` pre-check.
                            let persist = pending
                                .oldest_pending_block()
                                .map_or(last_seen, |b| last_seen.min(b.saturating_sub(1)));
                            if let Err(err) = cp.set(&checkpoint_key, persist) {
                                warn!(chain_key, %err, "failed to persist claim checkpoint");
                            }
                        }
                    }
                    Err(err) => {
                        rate_limited = crate::pacing::error_looks_rate_limited(&format!("{err:#}"));
                        warn!(chain_key, %err, "claim discovery iteration failed; will retry");
                    }
                }

                process_pending(
                    chain_key,
                    &claim,
                    &client,
                    &cc_provider,
                    submitter_address,
                    &broadcast_locks,
                    &mut pending,
                    &mut done,
                ).await;

                // Rate-limit pacing: a shared, RPS-capped endpoint rejects reads whenever the
                // co-tenant attestor fleet bursts; retrying at base cadence keeps paying into the
                // limit that is rejecting us. A rate-limited failure arms a deferral window
                // (checked at tick start); clean iterations decay the level and are never slowed.
                pacer.after(rate_limited);
                if rate_limited {
                    if let Some(window) = pacer.deferring() {
                        warn!(chain_key, defer_ms = window.as_millis() as u64,
                            "🧯 provider is rate limiting — deferring claim discovery");
                    }
                }
            }
        }
    }
}

/// Poll the client chain for new `Locked` events on the source bridge and enqueue their tx hashes
/// (with the per-lock replay keys as metadata for the `claimed()` pre-check).
///
/// Scans only up to `tip - confirmation_depth`: proof-gen additionally gates on attestation, but
/// lagging discovery avoids enqueueing locks that a client-chain reorg could still drop.
async fn discover_locks<P: Provider>(
    chain_key: u64,
    source_bridge: Address,
    confirmation_depth: u64,
    provider: &P,
    last_seen: &mut u64,
    pending: &mut PendingTxs,
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
        .address(source_bridge)
        .event_signature(ISourceBridge::Locked::SIGNATURE_HASH)
        .from_block(from_block)
        .to_block(to_block);

    let logs = provider
        .get_logs(&filter)
        .await
        .with_context(|| format!("eth_getLogs Locked from {from_block} to {to_block} failed"))?;

    for log in logs {
        let Some(tx_hash) = log.transaction_hash else {
            warn!(chain_key, "Locked log without transaction_hash; skipping");
            continue;
        };
        let key = match ISourceBridge::Locked::decode_log(&log.inner) {
            Ok(decoded) => claim_key(
                decoded.data.ccRecipient,
                decoded.data.amount,
                decoded.data.nonce,
            ),
            Err(err) => {
                warn!(chain_key, %tx_hash, %err, "could not decode Locked log; skipping");
                continue;
            }
        };
        if done.contains(&tx_hash) {
            continue;
        }
        if pending.contains(&tx_hash) {
            pending.note_meta(&tx_hash, key);
            continue;
        }
        // Discovery block anchors the checkpoint holdback below; `from_block` is a safe
        // (conservative) stand-in on the rare RPC that omits log block numbers.
        let block = log.block_number.unwrap_or(from_block);
        if let Some(evicted) = pending.insert(tx_hash, Instant::now(), block, vec![key]) {
            warn!(
                chain_key,
                %evicted,
                "claim pending queue at capacity; giving up on oldest unclaimed lock"
            );
        }
        debug!(chain_key, %tx_hash, claim_key = %key, "🔒 observed Locked; queued for claim");
    }

    *last_seen = to_block;
    Ok(())
}

/// Try to fetch a proof and submit a claim for every pending client-chain tx that is due.
#[allow(clippy::too_many_arguments)]
async fn process_pending<P: Provider>(
    chain_key: u64,
    claim: &ClaimConfig,
    client: &ProofGenClient,
    cc_provider: &P,
    submitter_address: alloy::primitives::Address,
    broadcast_locks: &Arc<crate::broadcast::BroadcastLocks>,
    pending: &mut PendingTxs,
    done: &mut BoundedSeen,
) {
    let now = Instant::now();
    let batch = pending.ready(MAX_CLAIMS_PER_TICK, now);
    if batch.is_empty() {
        return;
    }

    let results: Vec<(B256, Result<ClaimOutcome>)> = futures::stream::iter(batch)
        .map(|(tx_hash, keys)| async move {
            let outcome = claim_tx(
                chain_key,
                claim,
                &keys,
                client,
                cc_provider,
                submitter_address,
                broadcast_locks,
                tx_hash,
            )
            .await;
            (tx_hash, outcome)
        })
        .buffer_unordered(MAX_CLAIM_CONCURRENCY)
        .collect()
        .await;

    let now = Instant::now();
    for (tx_hash, outcome) in results {
        match outcome {
            Ok(ClaimOutcome::Claimed) => {
                info!(chain_key, %tx_hash, "💰 lock claimed on Creditcoin");
                pending.remove(&tx_hash);
                done.insert(tx_hash);
            }
            Ok(ClaimOutcome::Terminal(reason)) => {
                info!(chain_key, %tx_hash, %reason, "claim skipped (terminal); will not retry");
                pending.remove(&tx_hash);
                done.insert(tx_hash);
            }
            Ok(ClaimOutcome::NotReady) => {
                if pending.age(&tx_hash, now) > Some(MAX_CLAIM_AGE) {
                    warn!(
                        chain_key,
                        %tx_hash,
                        "proof never became ready within {MAX_CLAIM_AGE:?}; giving up on this claim"
                    );
                    pending.remove(&tx_hash);
                    done.insert(tx_hash);
                } else {
                    debug!(chain_key, %tx_hash, "proof not ready yet; deferred");
                    pending.defer(&tx_hash, now + NOT_READY_RETRY);
                }
            }
            Err(err) => {
                let attempts = pending.record_transient_failure(&tx_hash, now);
                // Do NOT drop after a fixed budget (C1r/C2): the old give-up permanently abandoned
                // the claim once its discovery cursor had advanced past it, so a multi-hour proof-gen
                // / Creditcoin-RPC outage silently lost every claim discovered before it, even across
                // restarts. Keep retrying at the capped backoff instead — re-submission is idempotent
                // on-chain (the `claimed()` pre-check), the queue stays memory-bounded by its cap, and
                // (unlike acks) a dropped claim is user-recoverable but should not require it.
                if attempts >= MAX_CLAIM_TRANSIENT_ATTEMPTS {
                    warn!(
                        chain_key,
                        %tx_hash,
                        attempts,
                        %err,
                        "claim still failing after {MAX_CLAIM_TRANSIENT_ATTEMPTS}+ transient attempts; \
                         continuing to retry at capped backoff (check the claim signer balance, \
                         proof-gen, and the Creditcoin RPC). The lock also stays claimable on-chain."
                    );
                } else {
                    warn!(
                        chain_key,
                        %tx_hash,
                        attempts,
                        %err,
                        "claim attempt failed transiently; will retry with backoff"
                    );
                }
            }
        }
    }
}

enum ClaimOutcome {
    /// Proof verified and the target released the funds.
    Claimed,
    /// The proof block is not yet attested (`BlockNotReady`); retry later.
    NotReady,
    /// A permanent condition (already claimed, wrong emitter, proof rejected, …).
    Terminal(String),
}

/// Fetch the native proof for `tx_hash` and submit it to the Creditcoin claim target.
///
/// Before any proof is fetched, the per-lock replay keys are checked against the target's
/// `claimed()` mapping: when every lock in the tx is already claimed (user claimed manually, or
/// another relayer won the race), the tx is terminal without costing a proof-gen round-trip.
#[allow(clippy::too_many_arguments)]
async fn claim_tx<P: Provider>(
    chain_key: u64,
    claim: &ClaimConfig,
    keys: &[B256],
    client: &ProofGenClient,
    cc_provider: &P,
    submitter_address: alloy::primitives::Address,
    broadcast_locks: &Arc<crate::broadcast::BroadcastLocks>,
    tx_hash: B256,
) -> Result<ClaimOutcome> {
    // Fail open: if the view calls error we fall through to the proof path — the target enforces
    // the same rule on-chain, this is purely a cost-saving shortcut.
    if !keys.is_empty() {
        match any_unclaimed(cc_provider, claim.target_address, keys).await {
            Ok(false) => {
                return Ok(ClaimOutcome::Terminal(
                    "every lock in this tx is already claimed".into(),
                ));
            }
            Ok(true) => {}
            Err(err) => {
                warn!(chain_key, %tx_hash, %err, "claimed() pre-check failed; proceeding with proof");
            }
        }
    }

    let proof = match client.proof_by_tx(chain_key, tx_hash).await? {
        ProofFetch::Ready(p) => p,
        ProofFetch::NotReady(_) => return Ok(ClaimOutcome::NotReady),
    };

    let encoded_tx = proof.encoded_transaction()?;
    if encoded_tx.len() > MAX_ENCODED_TRANSACTION_BYTES {
        return Ok(ClaimOutcome::Terminal(format!(
            "encodedTransaction {} bytes exceeds on-chain max {} bytes",
            encoded_tx.len(),
            MAX_ENCODED_TRANSACTION_BYTES
        )));
    }

    let (merkle_proof, continuity_proof) = proof.to_proofs()?;
    let height = proof.header_number;

    let target = IClaimTarget::new(claim.target_address, cc_provider);
    // Serialized on the submitter address (broadcast only — the receipt is awaited below, outside the
    // guard) so this tick's concurrent sends cannot read the same chain nonce. A stall consumes no
    // nonce and is retried; re-submission is idempotent (the target rejects an already-claimed key).
    let pending_tx = match broadcast_locks
        .broadcast(
            submitter_address,
            SEND_TIMEOUT,
            target
                .claim(
                    height,
                    encoded_tx,
                    merkle_proof.into(),
                    continuity_proof.into(),
                )
                .send(),
        )
        .await
    {
        Ok(res) => res,
        Err(stalled) => return Err(anyhow!("claim {stalled}")),
    };

    match pending_tx {
        // `crate::receipt::await_receipt` instead of `builder.get_receipt()`: the latter runs on
        // alloy's block-decoding heartbeat, which wedges against Frontier's mixHash-less blocks
        // (see the `receipt` module docs).
        Ok(builder) => {
            match tokio::time::timeout(RECEIPT_TIMEOUT, crate::receipt::await_receipt(&builder))
                .await
            {
                Err(_elapsed) => Err(anyhow!(
                    "no receipt within {RECEIPT_TIMEOUT:?} (claim tx possibly stuck)"
                )),
                Ok(receipt_result) => match receipt_result {
                    Ok(receipt) if receipt.status() => {
                        let gas_used = u128::from(receipt.gas_used);
                        let effective_gas_price = receipt.effective_gas_price;
                        let gas_cost_wei = gas_used.saturating_mul(effective_gas_price);
                        info!(
                            chain_key,
                            %tx_hash,
                            claim_tx_hash = %receipt.transaction_hash,
                            gas_used = %gas_used,
                            effective_gas_price_wei = %effective_gas_price,
                            gas_cost_wei = %gas_cost_wei,
                            "claim confirmed",
                        );
                        Ok(ClaimOutcome::Claimed)
                    }
                    Ok(_) => Ok(ClaimOutcome::Terminal("tx mined but reverted".into())),
                    Err(err) => Err(anyhow!("receipt fetch failed: {err}")),
                },
            }
        }
        Err(err) if is_terminal_revert(&err) => Ok(ClaimOutcome::Terminal(describe_revert(&err))),
        Err(err) => Err(anyhow!("claim send failed: {err}")),
    }
}

/// Whether any of `keys` is still unclaimed on the target.
async fn any_unclaimed<P: Provider>(provider: &P, target: Address, keys: &[B256]) -> Result<bool> {
    let target = IClaimTarget::new(target, provider);
    for key in keys {
        if !target
            .claimed(*key)
            .call()
            .await
            .context("IClaimTarget.claimed call failed")?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Decode a known claim-path revert selector into its error name, for actionable Terminal logs.
fn claim_revert_name(sel: [u8; 4]) -> Option<&'static str> {
    use IClaimTarget as T;
    Some(match sel {
        s if s == T::AlreadyClaimed::SELECTOR => "AlreadyClaimed",
        s if s == T::ProofVerificationFailed::SELECTOR => "ProofVerificationFailed",
        s if s == T::NoLockedLogs::SELECTOR => "NoLockedLogs",
        s if s == T::WrongEmitter::SELECTOR => "WrongEmitter",
        s if s == T::MalformedLockedLog::SELECTOR => "MalformedLockedLog",
        s if s == T::UnsupportedTxType::SELECTOR => "UnsupportedTxType",
        s if s == T::EncodedTransactionTooLarge::SELECTOR => "EncodedTransactionTooLarge",
        _ => return None,
    })
}

/// Classify a submit error as a permanent on-chain revert (vs. a transient RPC failure). A revert
/// at send / gas-estimation time is deterministic for this tx, so it must be terminal.
fn is_terminal_revert(err: &impl std::fmt::Display) -> bool {
    let s = err.to_string();
    if crate::revert::is_revert(&s) {
        return true;
    }
    // Decoded error-name fallback (nodes that surface the custom-error name without standard
    // revert phrasing).
    s.contains("AlreadyClaimed")
        || s.contains("ProofVerificationFailed")
        || s.contains("NoLockedLogs")
        || s.contains("WrongEmitter")
}

/// Prefix a terminal revert with the decoded error name when the selector is recognized.
fn describe_revert(err: &impl std::fmt::Display) -> String {
    let s = err.to_string();
    match crate::revert::revert_selector(&s).and_then(claim_revert_name) {
        Some(name) => format!("{name}: {s}"),
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, U256};

    #[test]
    fn claim_key_matches_solidity_abi_encode() {
        // Golden vector: cast keccak $(cast abi-encode 'f(address,uint256,uint256)'
        //   0x440F33CEa415A19610F51b21d85bdE365D96c453 1000000000000000000 7)
        let key = claim_key(
            address!("440F33CEa415A19610F51b21d85bdE365D96c453"),
            U256::from(1_000_000_000_000_000_000u128),
            U256::from(7u64),
        );
        assert_eq!(
            key,
            "0x1cb29e72f8e38b44bb2278df0d901a3c5afcad2ef836c9a458cad46d9e1c0c34"
                .parse::<B256>()
                .unwrap()
        );
    }

    #[test]
    fn claim_selectors_pin_to_on_wire_values() {
        // Computed with `cast sig` against CcBridge.sol's error declarations.
        assert_eq!(
            IClaimTarget::AlreadyClaimed::SELECTOR,
            [0x64, 0x6c, 0xf5, 0x58]
        );
        assert_eq!(
            IClaimTarget::WrongEmitter::SELECTOR,
            [0x6b, 0xc6, 0x49, 0x80]
        );
        assert_eq!(
            IClaimTarget::NoLockedLogs::SELECTOR,
            [0x1e, 0xf5, 0xfe, 0xac]
        );
        assert_eq!(
            IClaimTarget::ProofVerificationFailed::SELECTOR,
            [0xd6, 0x11, 0xc3, 0x18]
        );
        assert_eq!(
            IClaimTarget::MalformedLockedLog::SELECTOR,
            [0x9a, 0x13, 0x0c, 0x63]
        );
        assert_eq!(
            IClaimTarget::UnsupportedTxType::SELECTOR,
            [0xfe, 0x38, 0x64, 0x9a]
        );
    }

    #[test]
    fn terminal_revert_classification() {
        // Raw-selector node dialect (Creditcoin EVM RPC).
        assert!(is_terminal_revert(
            &"claim send failed: server returned an error response: error code -32603: VM \
              Exception while processing transaction: revert, data: \"0x646cf558\""
        ));
        let described = describe_revert(
            &"VM Exception while processing transaction: revert, data: \"0x646cf558\"",
        );
        assert!(described.starts_with("AlreadyClaimed: "));
        // Decoded-name dialect.
        assert!(is_terminal_revert(&"execution reverted: AlreadyClaimed"));
        // Transient infra failures stay retryable.
        assert!(!is_terminal_revert(
            &"error sending request: connection refused"
        ));
        assert!(!is_terminal_revert(
            &"error code -32000: insufficient funds for gas"
        ));
    }

    #[test]
    fn locked_event_signature_matches_bridge() {
        // keccak256("Locked(address,uint256,uint256)") — drift here means discovery silently
        // matches nothing on the deployed bridge.
        assert_eq!(
            ISourceBridge::Locked::SIGNATURE_HASH,
            keccak256(b"Locked(address,uint256,uint256)")
        );
    }
}
