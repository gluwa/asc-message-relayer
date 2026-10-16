//! Recover settlement routes from the Inbox's complete authorization history, including retired
//! Outboxes. A retry transaction contains only a message id, so its calldata and today's default
//! Outbox cannot identify where that message was published.

use std::collections::BTreeSet;
use std::path::PathBuf;

use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::{BlockId, BlockNumberOrTag, Filter};
use alloy::sol_types::{SolError, SolEvent, SolValue};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::abi::{IAcknowledgmentValidator, IInbox, IOutbox, OutboxMessage};

/// One bounded log range in each direction per tick. Backfill starts at the confirmed head and
/// works all the way to genesis; forward scanning keeps up with newly authorized Outboxes.
const HISTORY_SCAN_BLOCKS: u64 = 2_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct History {
    inbox: Address,
    source_chain_id: u64,
    /// Inclusive contiguous range already scanned. `None` means no historical coverage yet.
    scanned: Option<(u64, u64)>,
    outboxes: BTreeSet<Address>,
}

pub(super) struct RouteHistory {
    path: Option<PathBuf>,
    state: History,
}

impl RouteHistory {
    pub(super) fn load(
        path: Option<PathBuf>,
        inbox: Address,
        source_chain_id: u64,
    ) -> Result<Self> {
        let state = match path.as_ref().map(std::fs::read).transpose() {
            Ok(Some(bytes)) => {
                let state: History = serde_json::from_slice(&bytes)
                    .context("invalid settlement route history; refusing to skip history")?;
                if state.inbox != inbox || state.source_chain_id != source_chain_id {
                    bail!("settlement route history belongs to a different Inbox/source chain");
                }
                if state.scanned.is_some_and(|(from, to)| from > to) {
                    bail!("settlement route history has an invalid scanned range");
                }
                state
            }
            Ok(None) => History {
                inbox,
                source_chain_id,
                scanned: None,
                outboxes: BTreeSet::new(),
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => History {
                inbox,
                source_chain_id,
                scanned: None,
                outboxes: BTreeSet::new(),
            },
            Err(err) => return Err(err).context("reading settlement route history"),
        };
        Ok(Self { path, state })
    }

    pub(super) fn outboxes(&self) -> &BTreeSet<Address> {
        &self.state.outboxes
    }

    /// Seed current support as a fast path while full history catches up. These hints never
    /// advance historical coverage, and every message still has to match its committed Outbox.
    pub(super) async fn seed<P: Provider>(&mut self, provider: &P) -> Result<()> {
        let supported = IInbox::new(self.state.inbox, provider)
            .supportedOutboxes()
            .call()
            .await
            .context("reading current Inbox Outboxes")?;
        let mut next = self.state.clone();
        next.outboxes.extend(supported);
        self.commit(next).await
    }

    pub(super) async fn seed_validator<P: Provider>(
        &mut self,
        provider: &P,
        authority: Address,
    ) -> Result<()> {
        let outbox = IAcknowledgmentValidator::new(authority, provider)
            .outbox()
            .call()
            .await
            .context("reading configured validator's Outbox hint")?;
        if outbox != Address::ZERO {
            let mut next = self.state.clone();
            next.outboxes.insert(outbox);
            self.commit(next).await?;
        }
        Ok(())
    }

    pub(super) async fn refresh<P: Provider>(
        &mut self,
        provider: &P,
        confirmation_depth: u64,
    ) -> Result<()> {
        let confirmed = provider
            .get_block_number()
            .await?
            .saturating_sub(confirmation_depth);

        let mut next = self.state.clone();
        if let Some((low, high)) = next.scanned {
            // Forward progress first; old history must not prevent new deliveries settling.
            if high < confirmed {
                let to = confirmed.min(high.saturating_add(HISTORY_SCAN_BLOCKS));
                let (end, addresses) = scan(provider, next.inbox, high + 1, to).await?;
                next.outboxes.extend(addresses);
                next.scanned = Some((low, end));
                self.commit(next.clone()).await?;
            }
            if low > 0 {
                let from = low.saturating_sub(HISTORY_SCAN_BLOCKS);
                // Shrink from the low end when a provider caps log counts, so the returned
                // suffix stays contiguous with the already-scanned range.
                let (start, addresses) =
                    scan_backwards(provider, next.inbox, from, low - 1).await?;
                next.outboxes.extend(addresses);
                next.scanned = Some((start, next.scanned.expect("existing range").1));
                self.commit(next).await?;
            }
        } else {
            let from = confirmed.saturating_sub(HISTORY_SCAN_BLOCKS - 1);
            let (start, addresses) = scan_backwards(provider, next.inbox, from, confirmed).await?;
            next.outboxes.extend(addresses);
            next.scanned = Some((start, confirmed));
            self.commit(next).await?;
        }
        Ok(())
    }

    async fn commit(&mut self, next: History) -> Result<()> {
        if let Some(path) = self.path.clone() {
            let bytes = serde_json::to_vec(&next).context("encoding settlement route history")?;
            // Fsync is blocking work. Persist history and its range together before publishing
            // either in memory: a crash can cause a rescan, never a skipped authorization event.
            tokio::task::spawn_blocking(move || crate::checkpoint::write_atomic(&path, &bytes))
                .await
                .context("settlement route history persistence task failed")??;
        }
        self.state = next;
        Ok(())
    }
}

async fn read_range<P: Provider>(
    provider: &P,
    inbox: Address,
    from: u64,
    to: u64,
) -> Result<BTreeSet<Address>> {
    let result = provider
        .get_logs(
            &Filter::new()
                .address(inbox)
                .event_signature(IInbox::SupportedOutboxSet::SIGNATURE_HASH)
                .from_block(from)
                .to_block(to),
        )
        .await;
    let logs = match result {
        Ok(logs) => logs,
        Err(_) if from == to => {
            // A single block can itself exceed an RPC's log-count limit. Receipts are not
            // subject to eth_getLogs result caps; never skip that block to make progress.
            let block = provider
                .get_block_by_number(BlockNumberOrTag::Number(from))
                .await
                .context("support-history fallback block lookup")?
                .context("support-history fallback block unavailable")?;
            let expected: Vec<B256> = block.transactions.hashes().collect();
            if block.header.number != from
                || block.header.hash == B256::ZERO
                || expected.is_empty()
                || expected.iter().copied().collect::<BTreeSet<_>>().len() != expected.len()
            {
                bail!("support-history fallback block has invalid transaction coverage");
            }
            let receipts = provider
                .get_block_receipts(BlockId::number(from))
                .await
                .context("single-block support-history receipt fallback")?
                .context("support-history block receipts unavailable")?;
            if receipts.len() != expected.len() {
                bail!("support-history fallback receipts do not cover every block transaction");
            }
            let mut logs = Vec::new();
            let mut seen = BTreeSet::new();
            for receipt in receipts {
                let expected_hash = receipt
                    .transaction_index
                    .and_then(|index| usize::try_from(index).ok())
                    .and_then(|index| expected.get(index));
                if receipt.block_number != Some(from)
                    || receipt.block_hash != Some(block.header.hash)
                    || expected_hash != Some(&receipt.transaction_hash)
                    || !seen.insert(receipt.transaction_hash)
                {
                    bail!("support-history receipt is missing or mismatches block provenance");
                }
                for log in receipt.logs() {
                    if log.block_hash != receipt.block_hash
                        || log.block_number != receipt.block_number
                        || log.transaction_hash != Some(receipt.transaction_hash)
                        || log.transaction_index != receipt.transaction_index
                    {
                        bail!("support-history log does not belong to its receipt");
                    }
                    if log.address() == inbox
                        && log.topics().first() == Some(&IInbox::SupportedOutboxSet::SIGNATURE_HASH)
                    {
                        logs.push(log.clone());
                    }
                }
            }
            logs
        }
        Err(err) => return Err(err.into()),
    };
    let mut addresses = BTreeSet::new();
    for log in logs {
        if log.address() != inbox {
            bail!("support-history RPC returned a log from another Inbox");
        }
        if log.removed
            || log
                .block_number
                .is_none_or(|block| block < from || block > to)
            || log.block_hash.is_none()
            || log.transaction_hash.is_none()
            || log.transaction_index.is_none()
            || log.log_index.is_none()
        {
            bail!("support-history RPC returned a removed log or invalid provenance");
        }
        let event = IInbox::SupportedOutboxSet::decode_log(&log.inner)
            .context("decoding Inbox support history")?;
        // Both additions AND removals establish historical authorization. Never discard a
        // retired Outbox: its pending message may execute long after its removal.
        if event.outbox != Address::ZERO {
            addresses.insert(event.outbox);
        }
    }
    Ok(addresses)
}

async fn scan<P: Provider>(
    provider: &P,
    inbox: Address,
    from: u64,
    mut to: u64,
) -> Result<(u64, BTreeSet<Address>)> {
    loop {
        match read_range(provider, inbox, from, to).await {
            Ok(addresses) => return Ok((to, addresses)),
            Err(err) if from == to => return Err(err).context("scanning Inbox support history"),
            Err(_) => to = from + (to - from) / 2,
        }
    }
}

async fn scan_backwards<P: Provider>(
    provider: &P,
    inbox: Address,
    mut from: u64,
    to: u64,
) -> Result<(u64, BTreeSet<Address>)> {
    loop {
        match read_range(provider, inbox, from, to).await {
            Ok(addresses) => return Ok((from, addresses)),
            Err(err) if from == to => return Err(err).context("backfilling Inbox support history"),
            Err(_) => from += (to - from).div_ceil(2),
        }
    }
}

fn message_id(outbox: Address, message: &OutboxMessage, source_chain_id: u64) -> B256 {
    keccak256(
        (
            outbox,
            message.emitter,
            message.sequence,
            message.payloadHash,
            U256::from(source_chain_id),
        )
            .abi_encode_params(),
    )
}

/// Resolve actual publication records, then group unsettled acknowledgments by their current
/// source-side authority. An absent record (including an incomplete history scan) is retryable,
/// never evidence that an acknowledgment is unnecessary.
#[derive(Debug, Default)]
pub(super) struct Resolution {
    pub(super) authorities: BTreeSet<Address>,
    pub(super) failure: Option<anyhow::Error>,
}

pub(super) async fn validators<P: Provider>(
    provider: &P,
    source_chain_id: u64,
    destination_chain_key: u64,
    candidates: &BTreeSet<Address>,
    ids: &[B256],
) -> Resolution {
    let mut resolution = Resolution::default();
    if ids.is_empty() {
        resolution.failure = Some(anyhow::anyhow!(
            "cannot route settlement without message ids"
        ));
    }
    for id in ids {
        match validator_for(
            provider,
            source_chain_id,
            destination_chain_key,
            candidates,
            id,
        )
        .await
        {
            Ok(Some(authority)) => {
                resolution.authorities.insert(authority);
            }
            Ok(None) => {}
            Err(err) => {
                resolution.failure.get_or_insert(err);
            }
        }
    }
    resolution
}

async fn validator_for<P: Provider>(
    provider: &P,
    source_chain_id: u64,
    destination_chain_key: u64,
    candidates: &BTreeSet<Address>,
    id: &B256,
) -> Result<Option<Address>> {
    let mut failure = None;
    for address in candidates {
        let outbox = IOutbox::new(*address, provider);
        // Completion must survive a source reorg before the pending cursor is released.
        let message = match outbox
            .getMessage(*id)
            .block(BlockNumberOrTag::Finalized.into())
            .call()
            .await
        {
            Ok(message) => message,
            Err(err)
                if crate::revert::revert_selector(&err.to_string())
                    == Some(IOutbox::MessageNotFound::SELECTOR) =>
            {
                continue;
            }
            Err(err) => {
                failure = Some(err);
                continue;
            }
        };
        if message.emitter == Address::ZERO
            || message_id(*address, &message, source_chain_id) != *id
        {
            continue;
        }
        if message.canAck && !message.acknowledged {
            let authority = outbox
                .validator()
                .call()
                .await
                .context("reading Outbox validator")?;
            if authority == Address::ZERO {
                bail!("Outbox {address} has no acknowledgment validator");
            }
            let validator = IAcknowledgmentValidator::new(authority, provider);
            if validator
                .outbox()
                .call()
                .await
                .context("reading validator Outbox")?
                != *address
            {
                bail!("acknowledgment validator {authority} is not bound to Outbox {address}");
            }
            if validator
                .destinationChainKey()
                .call()
                .await
                .context("reading validator destination")?
                != destination_chain_key
            {
                bail!("acknowledgment validator {authority} is bound to another destination chain");
            }
            return Ok(Some(authority));
        }
        return Ok(None);
    }
    if let Some(err) = failure {
        return Err(err).with_context(|| format!("resolving original Outbox for {id}"));
    }
    bail!("original Outbox for {id} is not known yet; awaiting complete support history")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Bytes, U64};
    use alloy::providers::ProviderBuilder;
    use alloy::transports::mock::Asserter;

    async fn resolved<P: Provider>(
        provider: &P,
        source: u64,
        destination: u64,
        candidates: &BTreeSet<Address>,
        ids: &[B256],
    ) -> Result<BTreeSet<Address>> {
        let result = validators(provider, source, destination, candidates, ids).await;
        if let Some(err) = result.failure {
            return Err(err);
        }
        Ok(result.authorities)
    }

    const SOURCE: u64 = 42;
    const DESTINATION: u64 = 2;

    fn address(n: u8) -> Address {
        Address::repeat_byte(n)
    }

    fn record(can_ack: bool) -> OutboxMessage {
        OutboxMessage {
            emitter: address(7),
            sequence: 11,
            timestamp: 12,
            canAck: can_ack,
            acknowledged: false,
            payloadHash: keccak256(b"original publication"),
        }
    }

    fn push_record(rpc: &Asserter, message: &OutboxMessage) {
        rpc.push_success(&Bytes::from(message.abi_encode()));
    }

    fn push_authority(rpc: &Asserter, outbox: Address, validator: Address) {
        rpc.push_success(&Bytes::from(validator.abi_encode()));
        rpc.push_success(&Bytes::from(outbox.abi_encode()));
        rpc.push_success(&Bytes::from(DESTINATION.abi_encode()));
    }

    fn support(
        inbox: Address,
        outbox: Address,
        supported: bool,
        block: u64,
    ) -> alloy::rpc::types::Log {
        alloy::rpc::types::Log {
            inner: alloy::primitives::Log {
                address: inbox,
                data: IInbox::SupportedOutboxSet { outbox, supported }.encode_log_data(),
            },
            block_number: Some(block),
            block_hash: Some(B256::repeat_byte(2)),
            transaction_hash: Some(B256::repeat_byte(1)),
            transaction_index: Some(0),
            log_index: Some(0),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn retired_outbox_routes_retry_only_execution_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        let inbox = address(9);
        let old = address(1);
        let new = address(2);
        let rpc = Asserter::new();
        // The current list and discovery default contain only B. A's removal log still binds
        // it to this Inbox's history; no original deliverMessage calldata survives in a retry.
        rpc.push_success(&Bytes::from(vec![new].abi_encode()));
        rpc.push_success(&U64::from(5_000));
        rpc.push_success(&vec![
            support(inbox, old, false, 4_999),
            support(inbox, new, true, 5_000),
        ]);
        let provider = ProviderBuilder::new().connect_mocked_client(rpc.clone());
        let mut history = RouteHistory::load(Some(path.clone()), inbox, SOURCE).unwrap();
        history.seed(&provider).await.unwrap();
        history.refresh(&provider, 0).await.unwrap();
        drop(history);
        let history = RouteHistory::load(Some(path), inbox, SOURCE).unwrap();

        let message = record(true);
        let id = message_id(old, &message, SOURCE);
        let execution = IInbox::MessageExecuted {
            messageId: id,
            emitterAddress: message.emitter,
            destination: address(3),
            dispatcher: address(4),
            relayer: address(5),
            messagePayload: Bytes::new(),
        };
        let log = alloy::rpc::types::Log {
            inner: alloy::primitives::Log {
                address: inbox,
                data: execution.encode_log_data(),
            },
            ..Default::default()
        };
        let (_, discovered) = crate::ack::decode_delivery_log(&log).unwrap().unwrap();
        push_record(&rpc, &message);
        push_authority(&rpc, old, address(11));
        assert_eq!(
            resolved(
                &provider,
                SOURCE,
                DESTINATION,
                history.outboxes(),
                &[discovered]
            )
            .await
            .unwrap(),
            BTreeSet::from([address(11)]),
        );
        assert!(rpc.read_q().is_empty());
    }

    #[tokio::test]
    async fn one_destination_transaction_routes_to_each_original_validator() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(rpc.clone());
        let a = address(1);
        let b = address(2);
        let message = record(true);
        let ids = [
            message_id(a, &message, SOURCE),
            message_id(b, &message, SOURCE),
        ];
        push_record(&rpc, &message);
        push_authority(&rpc, a, address(11));
        rpc.push_failure_msg("execution reverted: 0x5d803cca");
        push_record(&rpc, &message);
        push_authority(&rpc, b, address(12));
        assert_eq!(
            resolved(
                &provider,
                SOURCE,
                DESTINATION,
                &BTreeSet::from([a, b]),
                &ids
            )
            .await
            .unwrap(),
            BTreeSet::from([address(11), address(12)]),
        );
        assert!(rpc.read_q().is_empty());
    }

    #[tokio::test]
    async fn only_a_verified_publication_can_suppress_acknowledgment() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(rpc.clone());
        let a = address(1);
        let b = address(2);
        let message = record(false);
        let id = message_id(a, &message, SOURCE);
        // B returning a non-acknowledgeable record does not make A's message settled.
        push_record(&rpc, &message);
        assert!(
            resolved(&provider, SOURCE, DESTINATION, &BTreeSet::from([b]), &[id])
                .await
                .is_err()
        );
        push_record(&rpc, &message);
        assert!(resolved(
            &provider,
            SOURCE + 1,
            DESTINATION,
            &BTreeSet::from([a]),
            &[id]
        )
        .await
        .is_err());
        push_record(&rpc, &message);
        assert!(
            resolved(&provider, SOURCE, DESTINATION, &BTreeSet::from([a]), &[id])
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn missing_records_and_rpc_failures_remain_retryable() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(rpc.clone());
        let a = address(1);
        let id = message_id(a, &record(true), SOURCE);
        for failure in ["execution reverted: 0x5d803cca", "temporary RPC outage"] {
            rpc.push_failure_msg(failure);
            assert!(
                resolved(&provider, SOURCE, DESTINATION, &BTreeSet::from([a]), &[id])
                    .await
                    .is_err()
            );
        }
        assert!(
            resolved(&provider, SOURCE, DESTINATION, &BTreeSet::new(), &[id])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn unresolved_message_does_not_hide_other_verified_routes() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(rpc.clone());
        let old = address(1);
        let live = address(2);
        let message = record(true);
        let missing = B256::repeat_byte(99);
        rpc.push_failure_msg("old Outbox is temporarily unavailable");
        rpc.push_failure_msg("execution reverted: 0x5d803cca");
        // An unrelated obsolete candidate must also not block the second, verified message.
        rpc.push_failure_msg("old Outbox is temporarily unavailable");
        push_record(&rpc, &message);
        push_authority(&rpc, live, address(12));
        let resolution = validators(
            &provider,
            SOURCE,
            DESTINATION,
            &BTreeSet::from([old, live]),
            &[missing, message_id(live, &message, SOURCE)],
        )
        .await;
        assert_eq!(resolution.authorities, BTreeSet::from([address(12)]));
        assert!(resolution.failure.is_some());
    }

    #[tokio::test]
    async fn malformed_history_provenance_never_advances_coverage() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(rpc.clone());
        let inbox = address(9);
        let good = support(inbox, address(1), true, 5);
        let mut malformed = vec![];
        let mut log = good.clone();
        log.removed = true;
        malformed.push(log);
        let mut log = good.clone();
        log.block_number = Some(6);
        malformed.push(log);
        let mut log = good.clone();
        log.transaction_hash = None;
        malformed.push(log);
        let mut log = good.clone();
        log.transaction_index = None;
        malformed.push(log);
        let mut log = good.clone();
        log.log_index = None;
        malformed.push(log);
        let mut log = good;
        log.block_hash = None;
        malformed.push(log);
        for log in malformed {
            rpc.push_success(&vec![log]);
            assert!(read_range(&provider, inbox, 5, 5).await.is_err());
        }
    }

    #[tokio::test]
    async fn rejects_a_validator_bound_to_another_outbox_or_destination() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(rpc.clone());
        let a = address(1);
        let message = record(true);
        let id = message_id(a, &message, SOURCE);
        push_record(&rpc, &message);
        rpc.push_success(&Bytes::from(address(11).abi_encode()));
        rpc.push_success(&Bytes::from(address(2).abi_encode()));
        assert!(
            resolved(&provider, SOURCE, DESTINATION, &BTreeSet::from([a]), &[id])
                .await
                .is_err()
        );
        push_record(&rpc, &message);
        push_authority(&rpc, a, address(11));
        assert!(resolved(
            &provider,
            SOURCE,
            DESTINATION + 1,
            &BTreeSet::from([a]),
            &[id]
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn history_shrinks_count_limited_ranges_without_skipping_blocks() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(rpc.clone());
        let inbox = address(9);
        rpc.push_failure_msg("too many logs");
        rpc.push_success(&vec![support(inbox, address(1), false, 7)]);
        let (low, outboxes) = scan_backwards(&provider, inbox, 1, 8).await.unwrap();
        assert_eq!(low, 5);
        assert!(outboxes.contains(&address(1)));
        rpc.push_failure_msg("range limit");
        rpc.push_success(&Vec::<alloy::rpc::types::Log>::new());
        assert_eq!(scan(&provider, inbox, 9, 16).await.unwrap().0, 12);
    }

    #[tokio::test]
    async fn a_single_dense_block_uses_receipts_instead_of_skipping_history() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(rpc.clone());
        let inbox = address(9);
        rpc.push_failure_msg("too many logs in one block");
        rpc.push_success(&history_block(1, vec![B256::repeat_byte(1)]));
        rpc.push_success(&serde_json::json!([{
            "transactionHash": B256::repeat_byte(1), "transactionIndex": "0x0",
            "blockHash": B256::repeat_byte(2), "blockNumber": "0x1",
            "gasUsed": "0x1", "effectiveGasPrice": "0x1", "cumulativeGasUsed": "0x1",
            "from": address(1), "to": inbox, "contractAddress": null, "status": "0x1",
            "type": "0x0", "logsBloom": alloy::primitives::Bloom::ZERO,
            "logs": [support(inbox, address(1), false, 1), support(address(8), address(2), true, 1)],
        }]));
        assert_eq!(
            read_range(&provider, inbox, 1, 1).await.unwrap(),
            BTreeSet::from([address(1)])
        );
    }

    fn history_block(number: u64, transactions: Vec<B256>) -> alloy::rpc::types::Block {
        let mut block: alloy::rpc::types::Block = Default::default();
        block.header.inner.number = number;
        block.header.hash = B256::repeat_byte(2);
        block.transactions = alloy::rpc::types::BlockTransactions::Hashes(transactions);
        block
    }

    #[tokio::test]
    async fn incomplete_receipt_fallback_never_advances_history() {
        let tx = B256::repeat_byte(1);
        let receipt = serde_json::json!({
            "transactionHash": tx, "transactionIndex": "0x0",
            "blockHash": B256::repeat_byte(2), "blockNumber": "0x0",
            "gasUsed": "0x1", "effectiveGasPrice": "0x1", "cumulativeGasUsed": "0x1",
            "from": address(1), "to": address(9), "contractAddress": null, "status": "0x1",
            "type": "0x0", "logsBloom": alloy::primitives::Bloom::ZERO,
            "logs": [support(address(9), address(1), false, 0)],
        });
        let mut wrong_block = receipt.clone();
        wrong_block["blockHash"] = serde_json::json!(B256::repeat_byte(99));
        let mut wrong_index = receipt.clone();
        wrong_index["transactionIndex"] = serde_json::json!("0x2");
        for receipts in [
            serde_json::json!([]),
            serde_json::json!([receipt.clone()]),
            serde_json::json!([receipt.clone(), receipt.clone()]),
            serde_json::json!([receipt.clone(), wrong_block]),
            serde_json::json!([receipt.clone(), wrong_index]),
        ] {
            let rpc = Asserter::new();
            let provider = ProviderBuilder::new().connect_mocked_client(rpc.clone());
            rpc.push_success(&U64::ZERO);
            rpc.push_failure_msg("too many logs");
            rpc.push_success(&history_block(0, vec![tx, B256::repeat_byte(3)]));
            rpc.push_success(&receipts);
            let mut history = RouteHistory::load(None, address(9), SOURCE).unwrap();
            assert!(history.refresh(&provider, 0).await.is_err());
            assert!(history.state.scanned.is_none());
            assert!(history.outboxes().is_empty());
        }
        let empty = serde_json::to_value(history_block(0, vec![])).unwrap();
        let mut missing = empty.clone();
        missing.as_object_mut().unwrap().remove("transactions");
        let mut malformed = empty.clone();
        malformed["transactions"] = serde_json::json!(["not-a-hash"]);
        let duplicate = serde_json::to_value(history_block(0, vec![tx, tx])).unwrap();
        for block in [empty, missing, malformed, duplicate] {
            let rpc = Asserter::new();
            let provider = ProviderBuilder::new().connect_mocked_client(rpc.clone());
            rpc.push_success(&U64::ZERO);
            rpc.push_failure_msg("too many logs");
            rpc.push_success(&block);
            let mut history = RouteHistory::load(None, address(9), SOURCE).unwrap();
            assert!(history.refresh(&provider, 0).await.is_err());
            assert!(history.state.scanned.is_none());
        }
    }

    #[tokio::test]
    async fn failed_history_reads_and_disk_writes_do_not_advance_coverage() {
        let rpc = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(rpc.clone());
        let mut history = RouteHistory::load(None, address(9), SOURCE).unwrap();
        rpc.push_success(&U64::ZERO);
        rpc.push_failure_msg("temporary getLogs outage");
        rpc.push_failure_msg("temporary receipt outage");
        assert!(history.refresh(&provider, 0).await.is_err());
        assert!(history.state.scanned.is_none());

        let dir = tempfile::tempdir().unwrap();
        let not_a_directory = dir.path().join("file");
        std::fs::write(&not_a_directory, b"file").unwrap();
        history.path = Some(not_a_directory.join("routes.json"));
        rpc.push_success(&U64::ZERO);
        rpc.push_success(&vec![support(address(9), address(1), true, 0)]);
        assert!(history.refresh(&provider, 0).await.is_err());
        assert!(history.state.scanned.is_none());
        assert!(history.outboxes().is_empty());
    }

    #[test]
    fn corrupt_or_mismatched_history_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        for text in ["", "not json"] {
            std::fs::write(&path, text).unwrap();
            assert!(RouteHistory::load(Some(path.clone()), address(9), SOURCE).is_err());
        }
        let state = History {
            inbox: address(9),
            source_chain_id: SOURCE,
            scanned: Some((0, 8)),
            outboxes: BTreeSet::new(),
        };
        std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(RouteHistory::load(Some(path.clone()), address(8), SOURCE).is_err());
        assert!(RouteHistory::load(Some(path), address(9), SOURCE + 1).is_err());
    }
}
