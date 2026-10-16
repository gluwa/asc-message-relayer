//! Source message discovery across every historically authorized Outbox.
//!
//! Default changes, removal and Discovery replacement do not reset the scan. Each candidate
//! emitter is checked against governance's Discovery at the finalized source block, matching
//! the attestor's block-end authorization semantics. Historical RPC failures stop progress.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::primitives::{Address, B256};
use alloy::providers::Provider;
use alloy::rpc::types::{BlockNumberOrTag, Filter, Log};
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

mod authority;
pub mod factory;
pub mod finality;

use crate::abi::IOutbox;
use crate::checkpoint::CheckpointStore;
use crate::config::ChainRoute;
use crate::prom::Metrics;
use finality::{pick_to_block, read_finalized_head, FinalityPolicy, FinalityTracker};
use write_ability::protocol::chain_key_to_bytes32;

pub use factory::{DiscoveryResolver, OutboxResolver, ResolvedOutbox};
/// Settlement's legacy resolver refresh cadence. Source discovery does not poll a default.
pub const DEFAULT_RESOLVE_POLL_INTERVAL_SECS: u64 = 60;
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 6;
const MAX_BLOCKS_PER_SCAN: u64 = 2_000;
/// Bound individual network calls, never draining a bounded channel under backpressure.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// A finalized message that the relayer has discovered on the Creditcoin Outbox. The vote pool
/// keys on `message_id` (also the digest attestors sign directly since asc-contracts #54); the
/// rest of the fields are needed to recompute the calldata for `Inbox.deliverMessage`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct IndexedMessage {
    pub chain_key: u64,
    pub message_id: B256,
    pub emitter: Address,
    /// The Outbox the event was scanned from: bound into `messageId` and the second
    /// `deliverMessage` argument (asc-contracts #45).
    pub outbox: Address,
    /// Per-emitter Outbox sequence `messageId` was derived from (asc-contracts #54) — the fourth
    /// `deliverMessage` argument.
    pub sequence: u64,
    pub destination_chain_key: B256,
    pub creditcoin_chain_id: u64,
    pub payload: Vec<u8>,
    /// Transaction + block of the `MessagePublished` emission. Carried so the pool can build a
    /// [`ReobservationRequest`](write_ability::envelope::ReobservationRequest) pointing attestors at
    /// the exact event when a message stalls below quorum.
    pub tx_hash: B256,
    pub block_height: u64,
}

/// Immutable route domain plus the optional, explicit operator trust override.
#[derive(Debug, Clone, Copy)]
struct SourceRoute {
    chain_key: u64,
    destination_chain_key: B256,
    creditcoin_chain_id: u64,
    outbox_override: Option<Address>,
}

/// One cursor covers every Outbox for a route. A pinned override gets a distinct key so enabling,
/// changing or disabling it cannot turn a partial address scan into an all-Outbox checkpoint.
fn checkpoint_key(chain_key: u64, outbox_override: Option<Address>) -> String {
    match outbox_override {
        Some(address) => format!("outbox-pinned:{chain_key}:{address}"),
        None => format!("outboxes:{chain_key}"),
    }
}

fn resume_cursor(
    checkpoint: Option<u64>,
    durable_work: bool,
    start_block: Option<u64>,
    lookback: u64,
) -> u64 {
    checkpoint.filter(|_| durable_work).map_or_else(
        || start_block.unwrap_or(1).saturating_sub(1),
        |block| block.saturating_sub(lookback),
    )
}

/// Watch finalized publication history without depending on today's default or active set.
/// Legacy single-Outbox checkpoints are intentionally not reused: they did not cover this scope.
#[allow(clippy::too_many_arguments)]
pub async fn watch_outbox(
    route: ChainRoute,
    creditcoin_eth_rpc_url: String,
    indexed_tx: mpsc::Sender<IndexedMessage>,
    metrics: Metrics,
    checkpoint: Option<Arc<CheckpointStore>>,
    scan_lookback_blocks: u64,
    health: Arc<crate::health::Health>,
    work: Option<Arc<crate::work::WorkStore>>,
    cancel: CancellationToken,
) -> Result<()> {
    let chain_key = route.chain_key;
    anyhow::ensure!(
        checkpoint.is_some() == work.is_some(),
        "source checkpoint and unfinished-work persistence must be enabled together"
    );
    if route.outbox_address.is_none() {
        authority::registry_chain_key(chain_key)?;
    }
    if let Some(address) = route.outbox_address {
        anyhow::ensure!(
            !address.is_zero(),
            "outbox_address override must not be zero"
        );
        warn!(chain_key, %address, "source scan pinned by outbox_address; bypassing historical Discovery authorization");
    }
    let key = checkpoint_key(chain_key, route.outbox_address);
    let health_key = format!("outbox:{chain_key}");
    health.heartbeat(&health_key);
    let mut source_rpc = crate::rpc::Reconnecting::new(
        format!("outbox:{chain_key} source"),
        creditcoin_eth_rpc_url.clone(),
    );
    let provider = source_rpc
        .connect()
        .await
        .with_context(|| format!("chain_key {chain_key}: failed to connect to source RPC"))?
        .clone();
    let creditcoin_chain_id = tokio::time::timeout(RPC_TIMEOUT, provider.get_chain_id())
        .await
        .context("source chain ID lookup timed out")??;
    let source = SourceRoute {
        chain_key,
        destination_chain_key: chain_key_to_bytes32(chain_key),
        creditcoin_chain_id,
        outbox_override: route.outbox_address,
    };
    let persisted = checkpoint.as_ref().and_then(|c| c.get(&key));
    let durable_work = checkpoint
        .as_ref()
        .is_some_and(|c| c.has_durable_work(&key));
    if let Some(work) = &work {
        work.prepare_route(chain_key, durable_work).await?;
    }
    let mut last_seen = resume_cursor(
        persisted,
        durable_work,
        route.start_block,
        scan_lookback_blocks,
    );
    if persisted.is_none() || !durable_work {
        info!(chain_key, from_block = last_seen + 1, "starting all-Outbox history scan; single-address checkpoints cannot establish coverage");
    }
    let policy = FinalityPolicy::Finalized;
    let mut finality = FinalityTracker::new(Instant::now());
    let mut tick = tokio::time::interval(Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            _ = tick.tick() => {
                let scan = match source_rpc.connect().await {
                    Ok(provider) => poll_once(&source, &policy, &mut finality, provider,
                        &mut last_seen, &indexed_tx, metrics.as_ref(), work.as_deref(), &cancel, &|| health.heartbeat(&health_key)).await,
                    Err(err) => Err(err),
                };
                match scan {
                    Ok(()) => {
                        source_rpc.note_ok();
                        health.heartbeat(&health_key);
                        if let Some(cp) = &checkpoint {
                            // Every message in the successful prefix was persisted before it
                            // reached the channel. No periodically sampled holdback is needed.
                            let saved = if work.is_some() {
                                cp.set_journaled(&key, last_seen, None)
                            } else {
                                cp.set(&key, last_seen)
                            };
                            if let Err(err) = saved {
                                metrics.inc_checkpoint_write_failure(chain_key);
                                warn!(chain_key, %err, "failed to persist source checkpoint");
                            }
                        }
                    }
                    Err(err) => {
                        health.error(&health_key);
                        source_rpc.note_err();
                        warn!(chain_key, %err, "source poll failed; cursor retained for retry");
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn poll_once<P: Provider>(
    source: &SourceRoute,
    policy: &FinalityPolicy,
    finality: &mut FinalityTracker,
    provider: &P,
    last_seen: &mut u64,
    indexed_tx: &mpsc::Sender<IndexedMessage>,
    metrics: &dyn crate::prom::MetricsTrait,
    work: Option<&crate::work::WorkStore>,
    cancel: &CancellationToken,
    progress: &(dyn Fn() + Sync),
) -> Result<()> {
    let (finalized, tip) = match policy {
        FinalityPolicy::Finalized => (Some(read_finalized_head(provider).await?), 0),
        FinalityPolicy::Depth(_) => (
            None,
            tokio::time::timeout(RPC_TIMEOUT, provider.get_block_number())
                .await
                .context("source tip lookup timed out")??,
        ),
    };
    let was_stalled = finality.is_stalled();
    let confirmed = pick_to_block(finalized, tip, policy, finality, Instant::now())?;
    if finality.is_stalled() && !was_stalled {
        warn!(
            chain_key = source.chain_key,
            confirmed, "source finality stalled; waiting for a finalized advance"
        );
    }
    if confirmed <= *last_seen {
        return Ok(());
    }
    let from_block = *last_seen + 1;
    let mut to_block = confirmed.min(last_seen.saturating_add(MAX_BLOCKS_PER_SCAN));
    let logs = loop {
        match fetch_message_logs(
            provider,
            from_block,
            to_block,
            source.outbox_override,
            progress,
        )
        .await
        {
            Ok(logs) => break logs,
            Err(err) if err.is::<LogRangeTooLarge>() => {
                to_block = from_block + (to_block - from_block) / 2;
            }
            Err(err) => return Err(err),
        }
    };
    // Cache only in this bounded range, never across source blocks or registry replacement.
    let mut discoveries = HashMap::new();
    let mut memberships = HashMap::new();
    for log in logs {
        // Dense valid ranges can take many bounded RPC calls. Keep liveness tied to active
        // scanning rather than forcing a restart that endlessly replays the same prefix.
        progress();
        let block_height = log
            .block_number
            .context("MessagePublished has no block number")?;
        anyhow::ensure!(
            !log.removed && (from_block..=to_block).contains(&block_height),
            "MessagePublished is removed or outside the requested range"
        );
        let outbox = log.address();
        if let Some(pinned) = source.outbox_override {
            anyhow::ensure!(
                outbox == pinned,
                "provider returned a log outside the pinned Outbox"
            );
        } else {
            let discovery = match discoveries.get(&block_height) {
                Some(discovery) => *discovery,
                None => {
                    let discovery =
                        authority::discovery_at(provider, source.chain_key, block_height).await?;
                    discoveries.insert(block_height, discovery);
                    discovery
                }
            };
            let Some(discovery) = discovery else { continue };
            let authorized = match memberships.get(&(block_height, outbox)) {
                Some(authorized) => *authorized,
                None => {
                    let authorized = authority::authorized_at(
                        provider,
                        source.chain_key,
                        discovery,
                        outbox,
                        block_height,
                    )
                    .await?;
                    memberships.insert((block_height, outbox), authorized);
                    authorized
                }
            };
            if !authorized {
                continue;
            }
        }
        let decoded = IOutbox::MessagePublished::decode_log_validate(&log.inner)
            .with_context(|| format!("invalid MessagePublished from authorized Outbox {outbox} at block {block_height}"))?;
        let tx_hash = log
            .transaction_hash
            .context("authorized MessagePublished has no transaction hash")?;
        let indexed = IndexedMessage {
            chain_key: source.chain_key,
            message_id: decoded.data.messageId,
            emitter: Address::from_slice(&decoded.data.emitterAddress.as_slice()[..20]),
            outbox,
            sequence: decoded.data.sequence,
            destination_chain_key: source.destination_chain_key,
            creditcoin_chain_id: source.creditcoin_chain_id,
            payload: decoded.data.payload.to_vec(),
            tx_hash,
            block_height,
        };
        debug!(chain_key = source.chain_key, %outbox, message_id = %indexed.message_id, block_height, "indexed authorized source message");
        // Preserve unfinished work before sending it or advancing the source scan. Any write
        // failure returns with the original cursor, so the complete range remains replayable.
        if let Some(work) = work {
            work.record(indexed.clone()).await?;
        }
        metrics.inc_messages_indexed(source.chain_key);
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            sent = indexed_tx.send(indexed) => {
                if sent.is_err() {
                    if cancel.is_cancelled() { return Ok(()); }
                    anyhow::bail!("vote pool channel closed");
                }
            }
        }
    }
    *last_seen = to_block;
    Ok(())
}

#[derive(Debug)]
struct LogRangeTooLarge;
impl std::fmt::Display for LogRangeTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("source log range exceeds provider result limit")
    }
}
impl std::error::Error for LogRangeTooLarge {}

/// Shrink multi-block result-limit failures; for one dense block, authenticate candidate logs
/// from its receipts so unauthorized event spam cannot permanently block discovery.
async fn fetch_message_logs<P: Provider>(
    provider: &P,
    from: u64,
    to: u64,
    pinned: Option<Address>,
    progress: &(dyn Fn() + Sync),
) -> Result<Vec<Log>> {
    let mut filter = Filter::new()
        .event_signature(IOutbox::MessagePublished::SIGNATURE_HASH)
        .from_block(from)
        .to_block(to);
    if let Some(address) = pinned {
        filter = filter.address(address);
    }
    match tokio::time::timeout(RPC_TIMEOUT, provider.get_logs(&filter))
        .await
        .context("source log query timed out")?
    {
        Ok(logs) => Ok(logs),
        Err(err) if log_limit_error(&err.to_string()) && from < to => Err(LogRangeTooLarge.into()),
        Err(err) if log_limit_error(&err.to_string()) => {
            message_logs_from_receipts(provider, from, pinned, progress).await
        }
        Err(err) => Err(err).context("source log query failed"),
    }
}

fn log_limit_error(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("query returned more than")
        || message.contains("too many results")
        || message.contains("too many logs")
        || message.contains("log response size exceeded")
}

async fn message_logs_from_receipts<P: Provider>(
    provider: &P,
    number: u64,
    pinned: Option<Address>,
    progress: &(dyn Fn() + Sync),
) -> Result<Vec<Log>> {
    let block = tokio::time::timeout(
        RPC_TIMEOUT,
        provider.get_block_by_number(BlockNumberOrTag::Number(number)),
    )
    .await
    .context("receipt fallback block lookup timed out")??
    .context("receipt fallback block missing")?;
    anyhow::ensure!(
        block.header.number == number,
        "receipt fallback returned wrong block"
    );
    let mut logs = Vec::new();
    for hash in block.transactions.hashes() {
        let receipt = tokio::time::timeout(RPC_TIMEOUT, provider.get_transaction_receipt(hash))
            .await
            .context("receipt fallback lookup timed out")??
            .context("receipt fallback transaction missing")?;
        anyhow::ensure!(
            receipt.transaction_hash == hash
                && receipt.block_number == Some(number)
                && receipt.block_hash == Some(block.header.hash),
            "receipt fallback returned inconsistent provenance"
        );
        progress();
        for log in receipt.inner.logs() {
            anyhow::ensure!(
                log.block_number == Some(number)
                    && log.block_hash == receipt.block_hash
                    && log.transaction_hash == Some(hash)
                    && !log.removed,
                "receipt fallback log has inconsistent provenance"
            );
            if log.topic0() == Some(&IOutbox::MessagePublished::SIGNATURE_HASH)
                && pinned.is_none_or(|address| log.address() == address)
            {
                logs.push(log.clone());
            }
        }
    }
    Ok(logs)
}

#[cfg(test)]
mod tests;
