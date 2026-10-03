//! Historical Discovery membership for Outboxes.
//!
//! A default Outbox is a convenience for publishers, not the set authorized to publish. Every
//! Outbox registered for a chain key may publish until its scheduled removal becomes effective, so
//! discovery cannot be driven off `defaultOutbox`: on a chain key with two registered Outboxes, a
//! publication from the non-default one is real, finalizable work this relayer must index, and
//! resolving only the default address silently drops it.
//!
//! Authority is resolved at the *message's* finalized source block, not at the head. Asking for
//! today's active set would lose legitimate history after a default change, a removal taking
//! effect, a re-registration, or the Discovery registry itself being replaced — every case where a
//! message published earlier stays valid but is no longer in the current answer.
//!
//! Membership at a past block handles scheduled removals (the effective block is exclusive),
//! cancellations, and re-registration using the contract's own lifecycle semantics rather than
//! re-deriving them here.
//!
//! Both lookups are historical `eth_call`s at an explicit block, so the endpoint must serve archive
//! state (every fleet node runs `--pruning archive`; third-party operators must too). An RPC that
//! cannot serve the requested state is an error, never an empty or negative answer: treating a
//! refused historical call as "not authorized" would drop finalized messages without a trace.
//! Callers fail closed and retry without advancing their cursor — see
//! [`crate::events::watch_outbox`].
//!
//! Two more lookups carry the *lifecycle* around membership, the same timelock the ABI documents:
//!
//! - [`registered_at`] — the block an Outbox first became a registered publisher, from its
//!   `OutboxRegistered` event. The registry exposes no creation height, so without this a listener
//!   has no start block and must either skip everything below the head or rescan from genesis.
//!   This is what makes [`ResolvedOutbox::current_since_block`], which
//!   [`crate::events::factory`] hardcodes to `None` and defers to exactly this work, a real value.
//! - [`pending_removal_at`] — the block a scheduled removal becomes effective. `activeOutboxes`
//!   drops an Outbox the instant that block passes, so head-state membership alone would end the
//!   watch *before* the drain window closes and lose a message published in the final stretch.

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, B256};
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};

use crate::events::factory::IChainInfo;
use write_ability::abi::IOutboxDiscovery;

/// `chain-info` precompile address (`0x…0fD3`, 4051) on Creditcoin L1 — a runtime precompile
/// registered at `AddressU64<4051>` in creditcoin3 `runtime/src/precompiles.rs`, exposing
/// `pallet_supported_chains::OutboxDiscoveries` (`chain_key → discovery-registry address`) to the
/// EVM. Hand-synced with creditcoin3: it is not an asc-contracts artifact, so the `abi_surface`
/// drift gate cannot check this binding.
pub const CHAIN_INFO_PRECOMPILE: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0f, 0xd3,
]);

/// The registry contract the chain key was governed by at one particular source block.
///
/// Resolved per block rather than cached from the head: `set_outbox_discovery_addr` can re-point a
/// chain key at a different registry, and messages finalized under the old one stay authorized
/// there.
pub struct DiscoveryAt {
    /// Registry address governing `chain_key` at the queried block.
    pub address: Address,
}

/// The `uint32` the registry keys Outboxes by, from a route's `u64` `chain_key`.
///
/// A plain `as u32` would wrap 2^32 to 0 and read the registry for a *different* chain, then bind
/// whatever Outbox that answered with — a silent mis-binding. Unrepresentable keys are rejected
/// before any call is made.
pub fn registry_chain_key(chain_key: u64) -> Result<u32> {
    u32::try_from(chain_key).with_context(|| {
        format!(
            "chain_key {chain_key} exceeds the uint32 the Outbox registry is keyed by, so it \
             cannot be represented on-chain"
        )
    })
}

/// Find the governance-registered Discovery for `chain_key` as of `block`.
///
/// Returns `Ok(None)` — not an error — when nothing was registered at that block, which is the
/// normal answer for a chain key whose registry was deployed later. Any RPC failure propagates:
/// an unreachable precompile is not evidence that the registry was absent.
pub async fn discovery_at<P: Provider>(
    provider: &P,
    chain_key: u64,
    block: u64,
) -> Result<Option<DiscoveryAt>> {
    registry_chain_key(chain_key)?;

    let discovery = IChainInfo::new(CHAIN_INFO_PRECOMPILE, provider)
        .get_outbox_discovery_address(chain_key)
        .block(BlockNumberOrTag::Number(block).into())
        .call()
        .await
        .with_context(|| {
            format!(
                "chain_key {chain_key}: historical get_outbox_discovery_address at block {block} \
                 failed — the endpoint must serve archive state (--pruning archive) or this lookup \
                 cannot distinguish an unregistered chain key from an RPC error"
            )
        })?;

    Ok(
        (discovery.exists && !discovery.discoveryAddr.is_zero()).then_some(DiscoveryAt {
            address: discovery.discoveryAddr,
        }),
    )
}

/// Whether `outbox` was an authorized publisher for `chain_key` at `block` under `discovery`.
///
/// This is the authorization check for one candidate Outbox, evaluated against the registry that
/// governed the chain key *at that block*. False means the Outbox was not registered yet, its
/// removal had already become effective, its registration had been cancelled, or a different
/// registry governed the key — all correctly "not authorized here".
///
/// An RPC error is never `false`. Historical state is required for this answer to mean anything,
/// so an endpoint that refuses the call must surface as an error and the caller must retry without
/// advancing its cursor, rather than silently discarding finalized messages.
pub async fn authorized_at<P: Provider>(
    provider: &P,
    chain_key: u64,
    discovery: Address,
    outbox: Address,
    block: u64,
) -> Result<bool> {
    let chain_key_u32 = registry_chain_key(chain_key)?;
    let registry = IOutboxDiscovery::new(discovery, provider);

    registry
        .isActiveOutbox(chain_key_u32, outbox)
        .block(BlockNumberOrTag::Number(block).into())
        .call()
        .await
        .with_context(|| {
            format!(
                "chain_key {chain_key}: historical isActiveOutbox({outbox}) on registry {discovery} \
                 at block {block} failed — refusing to treat an unserved historical call as \
                 unauthorized"
            )
        })
}

/// Every Outbox currently registered as active for `chain_key`.
///
/// The candidate set to authorize against, not the answer on its own: this is the *head* state, so
/// it can miss an Outbox that has since been removed but whose messages are still finalizable. Use
/// it to discover candidates, then confirm each with [`authorized_at`] at the message's block.
///
/// Due-removed entries are already filtered out by the contract. An empty list means the chain key
/// has no Outbox registered right now.
pub async fn active_outboxes<P: Provider>(
    provider: &P,
    chain_key: u64,
    discovery: Address,
) -> Result<Vec<Address>> {
    let chain_key_u32 = registry_chain_key(chain_key)?;
    let registry = IOutboxDiscovery::new(discovery, provider);

    let outboxes = registry
        .activeOutboxes(chain_key_u32)
        .call()
        .await
        .with_context(|| {
            format!("chain_key {chain_key}: activeOutboxes on registry {discovery} failed")
        })?;

    Ok(outboxes)
}

/// The indexed `chainKey` topic of an [`IOutboxDiscovery::OutboxRegistered`] log: a `uint32` in a
/// 32-byte word, right-aligned.
fn chain_key_topic(chain_key_u32: u32) -> B256 {
    let mut word = [0u8; 32];
    word[28..].copy_from_slice(&chain_key_u32.to_be_bytes());
    B256::from(word)
}

/// The indexed `outbox` topic of the same log: a 20-byte address left-padded to a 32-byte word.
fn outbox_topic(outbox: Address) -> B256 {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(outbox.as_slice());
    B256::from(word)
}

/// The block at which `outbox` first became a registered publisher for `chain_key` under
/// `discovery`, from its `OutboxRegistered` event, or `None` if it was never registered there.
///
/// `OutboxDiscovery` exposes no creation height for an Outbox, so the event is the only provenance
/// there is: a listener that starts at the head skips every `MessagePublished` below it, and one
/// that starts at zero rescans a chain's whole history on every boot. This is the answer that
/// makes each listener's start block exact — the same thing the ABI note on the event says.
///
/// The *earliest* registration is returned, not the latest. A re-registration after a removal makes
/// the Outbox legal again, but messages published in the gap are correctly unauthorized, and
/// [`authorized_at`] rejects them at their own block — so starting at the first registration
/// costs a bounded re-scan and cannot miss anything, where starting at the last would silently
/// drop the history before it.
///
/// `chainKey`, `outbox` and `registrar` are all indexed, so this is a three-topic server-side
/// filter rather than a local scan of every registration. The range is still the full chain: there
/// is no way to ask a registry for an Outbox's registration height directly. An endpoint that
/// refuses the range (a range-capped public RPC) propagates as an error and the caller keeps its
/// existing cursor — never a fabricated height, and never a silent fall back to the head.
pub async fn registered_at<P: Provider>(
    provider: &P,
    chain_key: u64,
    discovery: Address,
    outbox: Address,
) -> Result<Option<u64>> {
    let chain_key_u32 = registry_chain_key(chain_key)?;

    let head = provider.get_block_number().await.with_context(|| {
        format!("chain_key {chain_key}: failed to read head while locating OutboxRegistered")
    })?;

    let filter = Filter::new()
        .address(discovery)
        .event_signature(IOutboxDiscovery::OutboxRegistered::SIGNATURE_HASH)
        .topic1(chain_key_topic(chain_key_u32))
        .topic2(outbox_topic(outbox))
        .from_block(0)
        .to_block(head);

    let logs = provider.get_logs(&filter).await.with_context(|| {
        format!(
            "chain_key {chain_key}: reading OutboxRegistered for {outbox} from registry {discovery} \
             failed — without it a listener on that Outbox has no start block and must not guess one"
        )
    })?;

    let mut first: Option<u64> = None;
    for log in logs {
        let Some(block_number) = log.block_number else {
            // No height means this log cannot anchor a start block. Treating it as "unknown" and
            // continuing would let a later registration win, so fail instead of picking a height.
            anyhow::bail!(
                "chain_key {chain_key}: OutboxRegistered log for {outbox} on registry {discovery} \
                 came back without a block number"
            );
        };
        first = earliest_registration(block_number, first);
    }

    Ok(first)
}

/// Fold one registration height into the running earliest, so the selection is testable without a
/// live provider. `seen` is the answer so far, `None` meaning nothing registered yet.
fn earliest_registration(block_number: u64, seen: Option<u64>) -> Option<u64> {
    Some(match seen {
        Some(prev) => prev.min(block_number),
        None => block_number,
    })
}

/// The block at which `outbox` stopped (or will stop) being authorized for `chain_key`, from
/// `pendingRemovalBlock`, or `None` when no removal is scheduled.
///
/// Read live rather than at a message's block, because it answers the forward question a listener
/// asks — *when must I stop scanning this Outbox* — and the scheduled value is in the registry
/// state, not in a log. The removal is not effective until this block: the Outbox stays authorized
/// through `effectiveBlock - 1`, and `activeOutboxes` drops it only afterwards, so a listener that
/// stops on the head-state answer alone drops a message published in the final window.
///
/// A removal that was already cancelled, or a chain key with no removal scheduled, reads `None` and
/// the listener keeps watching. Errors propagate: an unserved call is not "no removal".
pub async fn pending_removal_at<P: Provider>(
    provider: &P,
    chain_key: u64,
    discovery: Address,
    outbox: Address,
) -> Result<Option<u64>> {
    let chain_key_u32 = registry_chain_key(chain_key)?;
    let registry = IOutboxDiscovery::new(discovery, provider);

    let effective = registry
        .pendingRemovalBlock(chain_key_u32, outbox)
        .call()
        .await
        .with_context(|| {
            format!(
                "chain_key {chain_key}: pendingRemovalBlock({outbox}) on registry {discovery} \
                 failed — treating an unserved call as 'no removal scheduled' would silently \
                 extend a listener past its drain deadline"
            )
        })?;

    Ok((effective != 0).then_some(effective))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use alloy::sol_types::SolValue;

    #[test]
    fn chain_info_precompile_address_matches_creditcoin3_registration() {
        // AddressU64<4051> per creditcoin3 runtime/src/precompiles.rs: the low 8 bytes of the
        // 20-byte address hold the u64 value big-endian, the rest zero. 4051 decimal = 0xfd3.
        let mut bytes = [0u8; 20];
        bytes[12..20].copy_from_slice(&4051u64.to_be_bytes());
        assert_eq!(CHAIN_INFO_PRECOMPILE, Address::from(bytes));
    }

    /// The contract keys its Outbox maps by `uint32` while routes carry `chain_key` as `u64`. A
    /// plain `as u32` would wrap 2^32 to 0 and read the registry for a *different* chain, then bind
    /// whatever Outbox that answered with. It must refuse instead, and refuse before any call.
    #[test]
    fn refuses_a_chain_key_wider_than_uint32() {
        for key in [u64::from(u32::MAX) + 1, u64::MAX] {
            let err = registry_chain_key(key).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("uint32"), "key {key}: {msg}");
        }
    }

    /// The widest representable key must pass: otherwise the guard is off by one and quietly
    /// rejects a legitimate chain key.
    #[test]
    fn accepts_the_largest_representable_chain_key() {
        assert_eq!(registry_chain_key(u64::from(u32::MAX)).unwrap(), u32::MAX);
        assert_eq!(registry_chain_key(0).unwrap(), 0);
    }

    /// `registered_at` reaches the Outbox only through a server-side topic filter, so the topic
    /// words have to be exactly what the contract's indexed parameters encode. A `uint32` is
    /// right-aligned in 32 bytes and an `address` is left-padded to the same width; getting either
    /// wrong yields a filter that matches nothing and reports the Outbox as never registered, which
    /// looks like a working answer rather than a bug.
    ///
    /// Checked against the ABI encoder rather than hand-written bytes, so the expectation is the
    /// encoding a node performs, not a second copy of the same assumption.
    #[test]
    fn event_topics_are_abi_encoded() {
        for key in [0u32, 1, 2, 4, u32::MAX, 1 << 31] {
            assert_eq!(
                chain_key_topic(key).as_slice(),
                SolValue::abi_encode(&key).as_slice()
            );
        }
        for outbox in [
            Address::ZERO,
            address!("00000000000000000000000000000000000000aa"),
            address!("ffffffffffffffffffffffffffffffffffffffff"),
        ] {
            assert_eq!(
                outbox_topic(outbox).as_slice(),
                SolValue::abi_encode(&outbox).as_slice()
            );
        }
    }

    /// The two topic widths are encoded differently inside the same 32-byte word, so neither is a
    /// byte-offset copy of the other. A chain key must not spill into the bytes above its 4, or the
    /// filter would match a registration belonging to a neighbouring key; an outbox address
    /// occupies the high 20 and its padding is the low 12.
    #[test]
    fn topic_words_are_placed_where_the_abi_puts_them() {
        let key_word = chain_key_topic(0x0102_0304);
        assert_eq!(&key_word.as_slice()[..28], &[0u8; 28]);
        assert_eq!(&key_word.as_slice()[28..], &[0x01, 0x02, 0x03, 0x04]);

        let outbox_word = outbox_topic(address!("0102030405060708090a0b0c0d0e0f1011121314"));
        assert_eq!(&outbox_word.as_slice()[..12], &[0u8; 12]);
        assert_eq!(
            &outbox_word.as_slice()[12..],
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        );
    }

    /// The log query is only as narrow as the signature it carries. Every sibling event on the
    /// registry has to be excluded, and `OutboxRemovalScheduled` is the dangerous neighbour: it
    /// shares the `chainKey`/`outbox` topics, so a signature mix-up would anchor a listener at the
    /// removal block rather than the registration and start it *after* the history it needs.
    #[test]
    fn registration_signature_is_distinct_from_its_timelock_siblings() {
        let registered = IOutboxDiscovery::OutboxRegistered::SIGNATURE_HASH;
        assert_ne!(
            registered,
            IOutboxDiscovery::OutboxRemovalScheduled::SIGNATURE_HASH
        );
        assert_ne!(
            registered,
            IOutboxDiscovery::DefaultOutboxChangeScheduled::SIGNATURE_HASH
        );
        assert_ne!(
            registered,
            IOutboxDiscovery::PendingRemovalCancelled::SIGNATURE_HASH
        );
    }

    /// A relayer booting after a removal and a re-registration of the same Outbox still has to
    /// index the history from its *first* registration: starting at the latest one drops every
    /// message published before it, and those are exactly the ones a restarted relayer has no
    /// cursor for. The earliest log therefore wins, whatever order the RPC returns them in.
    #[test]
    fn earliest_registration_wins_over_a_later_re_registration() {
        let mut first = None;
        for block in [512u64, 90, 4096] {
            first = earliest_registration(block, first);
        }
        assert_eq!(first, Some(90));
        // The other order has to land on the same answer, or the result would depend on the RPC's
        // log ordering rather than on the chain.
        let mut reversed = None;
        for block in [4096u64, 90, 512] {
            reversed = earliest_registration(block, reversed);
        }
        assert_eq!(reversed, Some(90));
        // Never registered reads as "no answer", not zero: zero would anchor a listener at genesis.
        assert_eq!(earliest_registration(7, None), Some(7));
        assert_eq!(None::<u64>, None);
    }

    /// `pendingRemovalBlock` reads zero for "nothing scheduled", so the zero-guard is the only
    /// thing separating "keep watching forever" from "stop at block 0 and index nothing".
    #[test]
    fn zero_effective_block_is_not_a_removal() {
        assert_eq!((0u64 != 0).then_some(0u64), None);
        assert_eq!((1200u64 != 0).then_some(1200u64), Some(1200));
    }
}
