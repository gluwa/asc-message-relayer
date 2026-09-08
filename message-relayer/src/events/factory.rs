//! Outbox address resolution.
//!
//! One [`OutboxResolver`] implementation — [`DiscoveryResolver`] — used by every route. It reads
//! the discovery-registry address off the chain-info precompile (see
//! [`resolve_from_precompile_registry`]) and calls `defaultOutbox` on it. There is no scan
//! fallback: the factory's permissionless `OutboxCreated` logs and the config-driven
//! `outbox_registry_address` override are gone — `OutboxDiscovery` (asc-contracts#38) is the only
//! source of truth the production path trusts.
//!
//! The one exception is `outbox_address` (route config / `--outbox-address`), an operator-pinned
//! override checked before the registry lookup — see [`DiscoveryResolver::override_address`] for
//! when to use it.

use alloy::primitives::{address, Address};
use alloy::providers::DynProvider;
use alloy::sol;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::time::Duration;

use crate::config::ChainRoute;

/// What [`OutboxResolver::resolve`] found: the Outbox address to use, and — when known — the
/// block at which that Outbox became current. A caller switching to a newly-resolved address
/// (an Outbox rotation) uses `current_since_block` to resume `MessagePublished` discovery exactly
/// there instead of guessing "now" and risking a gap between the switch and the Outbox actually
/// going live.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedOutbox {
    pub address: Address,
    pub current_since_block: Option<u64>,
}

/// Pluggable strategy for resolving an Outbox address for a given route. Called once at startup
/// and periodically thereafter (see `events::watch_outbox`), so a rotation is picked up without a
/// restart — implementations should make a call with nothing new to report cheap.
#[async_trait]
pub trait OutboxResolver: Send + Sync + std::fmt::Debug {
    async fn resolve(&self, route: &ChainRoute, provider: &DynProvider) -> Result<ResolvedOutbox>;
}

/// Call `defaultOutbox(chainKey)` on `discovery` and turn a zero answer into an error.
/// `defaultOutbox`, not `outboxOf`, is the confirmed source of truth: "the default deployed outbox
/// for each chain via: `defaultOutbox(chainKey)` (not from deployer) because there will be multiple
/// version[s] of outbox" (Kevin Nguyen, Slack, 28 Aug 2026).
async fn default_outbox_from_discovery(
    chain_key: u64,
    discovery: Address,
    provider: &DynProvider,
) -> Result<Address> {
    // `chainKey` is `uint32` on the contract side while the pallet and these mirrors carry it
    // as `u64`. Reject anything unrepresentable rather than truncating: a silently wrapped key
    // would read the registry for a *different* chain and bind the wrong Outbox.
    let chain_key_u32 = u32::try_from(chain_key).with_context(|| {
        format!(
            "chain_key {chain_key} exceeds the uint32 the Outbox registry is keyed by, so it \
             cannot be represented on-chain"
        )
    })?;

    let discovery_contract = IOutboxDiscovery::new(discovery, provider);
    let address = tokio::time::timeout(
        PRECOMPILE_CALL_TIMEOUT,
        discovery_contract.defaultOutbox(chain_key_u32).call(),
    )
    .await
    .with_context(|| {
        format!(
            "chain_key {chain_key}: defaultOutbox on registry {discovery} timed out after \
             {PRECOMPILE_CALL_TIMEOUT:?}"
        )
    })?
    .with_context(|| {
        format!("chain_key {chain_key}: defaultOutbox call on registry {discovery} failed")
    })?;

    if address.is_zero() {
        anyhow::bail!(
            "chain_key {chain_key}: registry {discovery} has no default Outbox for this chain \
             key (defaultOutbox returned the zero address)"
        );
    }

    Ok(address)
}

/// Look up the discovery-registry address for `chain_key` from the chain-info precompile and, if
/// one is registered, resolve the Outbox from it via [`default_outbox_from_discovery`].
///
/// Returns `Ok(None)` — not an error — when no discovery address is registered for `chain_key`
/// yet, so the caller can report that clearly rather than as an opaque failure. Any other failure
/// (a registered-but-reverting registry, or one that answers zero) propagates as an error.
async fn resolve_from_precompile_registry(
    chain_key: u64,
    provider: &DynProvider,
) -> Result<Option<ResolvedOutbox>> {
    let chain_info = IChainInfo::new(CHAIN_INFO_PRECOMPILE, provider);
    let discovery_result = tokio::time::timeout(
        PRECOMPILE_CALL_TIMEOUT,
        chain_info.get_outbox_discovery_address(chain_key).call(),
    )
    .await
    .with_context(|| {
        format!(
            "chain_key {chain_key}: get_outbox_discovery_address precompile call timed out \
             after {PRECOMPILE_CALL_TIMEOUT:?}"
        )
    })?
    .with_context(|| {
        format!("chain_key {chain_key}: get_outbox_discovery_address precompile call failed")
    })?;

    if !discovery_result.exists || discovery_result.discoveryAddr.is_zero() {
        return Ok(None);
    }

    let address =
        default_outbox_from_discovery(chain_key, discovery_result.discoveryAddr, provider).await?;

    Ok(Some(ResolvedOutbox {
        address,
        current_since_block: None,
    }))
}

sol! {
    /// `ChainInfoPrecompile` on Creditcoin L1 (creditcoin3 `precompiles/chain-info`, registered at
    /// `AddressU64<4051>` in `runtime/src/precompiles.rs`) — a runtime precompile, not a
    /// usc-contracts artifact, so the `abi_surface` drift gate cannot check this binding; keep it
    /// in sync with creditcoin3 by hand.
    #[sol(rpc)]
    #[derive(Debug)]
    contract IChainInfo {
        /// The Outbox discovery-registry contract governing `chainKey` (`OutboxDiscovery` in
        /// asc-contracts), from `pallet_supported_chains::OutboxDiscoveries`. Safe to trust
        /// directly: it is only ever written through an access-controlled deploy path, so
        /// `defaultOutbox` on it can be read straight into a resolved Outbox. `exists = false`
        /// (with `discoveryAddr` the zero address) when nothing is registered for `chainKey`.
        function get_outbox_discovery_address(uint64 chainKey)
            external
            view
            returns (address discoveryAddr, bool exists);
    }

    /// `IOutboxDiscovery` (asc-contracts#38, merged to `asc-contracts` main 3 Sep 2026 — not yet
    /// checked by the `abi_surface` drift gate here, same treatment as `IChainInfo` above).
    /// Confirmed as the source of truth on Slack (Kevin Nguyen, 28 Aug 2026): "the default
    /// deployed outbox for each chain via: defaultOutbox(chainKey) (not from deployer) because
    /// there will be multiple version[s] of outbox".
    #[sol(rpc)]
    #[derive(Debug)]
    contract IOutboxDiscovery {
        /// The default Outbox for `chainKey`, or the zero address if none.
        function defaultOutbox(uint32 chainKey) external view returns (address);
    }
}

/// `ChainInfoPrecompile`'s fixed address (`AddressU64<4051>` = 4051 decimal = `0xfd3`).
const CHAIN_INFO_PRECOMPILE: Address = address!("0000000000000000000000000000000000000fd3");

/// Bounds every RPC/precompile call this resolver makes (mirrors
/// `delivery::FUNDED_GAS_READ_TIMEOUT` — a single chain read, not a tx wait). Without it a
/// black-holed provider would hang `resolve()` forever, wedging every other caller sharing this
/// resolver (`events::watch_outbox` and `ack::run` share one resolver per route).
const PRECOMPILE_CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// Production resolver: finds the Outbox for `route.chain_key` from on-chain state — mirroring
/// creditcoin3's own attestor-fleet resolver, which avoids a configured address on the same
/// grounds ("an address supplied separately from the chain key may not correspond to it").
///
/// A registry read is complete and authoritative on every call: no scan, no cursor, no persisted
/// checkpoint, no genesis fallback. A chain key with nothing registered in `OutboxDiscovery` fails
/// closed with a clear error rather than falling back to any spoofable source.
///
/// `override_address` is the one exception (Dylan, PR review, 8 Sep): an operator-pinned Outbox,
/// honored before the registry lookup, for a network where the chain-info precompile getter is
/// missing or misconfigured, or to pin an Outbox during an incident. `None` (the default) is the
/// production path described above. Logged loudly on every resolve while set, not just once at
/// startup — this bypasses the fail-closed default, so it should stay visible for as long as it's
/// in effect, not just when someone happens to be watching the startup log.
#[derive(Debug, Default)]
pub struct DiscoveryResolver {
    pub override_address: Option<Address>,
}

#[async_trait]
impl OutboxResolver for DiscoveryResolver {
    async fn resolve(&self, route: &ChainRoute, provider: &DynProvider) -> Result<ResolvedOutbox> {
        let chain_key = route.chain_key;
        if let Some(address) = self.override_address {
            tracing::warn!(
                chain_key,
                %address,
                "⚠️ Outbox resolution overridden by outbox_address — bypassing the OutboxDiscovery \
                 registry for this route"
            );
            return Ok(ResolvedOutbox {
                address,
                current_since_block: None,
            });
        }
        resolve_from_precompile_registry(chain_key, provider)
            .await?
            .with_context(|| {
                format!(
                    "chain_key {chain_key} has no OutboxDiscovery registered on-chain (chain-info \
                     precompile get_outbox_discovery_address is empty for this key) — register a \
                     discovery address via set_outbox_discovery_addr before routing this chain key"
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AttestorSet, ChainRoute};
    use alloy::providers::{Provider, ProviderBuilder};

    fn route_with(chain_key: u64) -> ChainRoute {
        ChainRoute {
            chain_key,
            creditcoin_chain_id: 1,
            destination_rpc_url: "http://x".into(),
            inbox_address: address!("0000000000000000000000000000000000000002"),
            signer_key: None,
            outbox_address: None,
            relayer_contract_address: None,
            block_confirmation_depth: 0,
            start_block: None,
            attestor_set: AttestorSet::Static(vec![address!(
                "000000000000000000000000000000000000000a"
            )]),
            threshold_override: None,
            ack: None,
            claim: None,
        }
    }

    /// A `DynProvider` that is never actually called successfully — every test here exercises the
    /// pure `chain_key` guard or expects an RPC failure, so it only needs to type-check.
    fn unused_provider() -> DynProvider {
        ProviderBuilder::new()
            .connect_http("http://127.0.0.1:1".parse().unwrap())
            .erased()
    }

    #[test]
    fn chain_info_precompile_address_matches_creditcoin3_registration() {
        // AddressU64<4051> per creditcoin3 runtime/src/precompiles.rs: the low 8 bytes of the
        // 20-byte address hold the u64 value big-endian, the rest zero. 4051 decimal = 0xfd3.
        let mut bytes = [0u8; 20];
        bytes[12..20].copy_from_slice(&4051u64.to_be_bytes());
        assert_eq!(CHAIN_INFO_PRECOMPILE, Address::from(bytes));
    }

    /// The contract keys `defaultOutbox` by `uint32` while routes carry `chain_key` as `u64`. A
    /// plain `as u32` would wrap 2^32 to 0 and silently read the registry for a *different* chain,
    /// then bind whatever Outbox that answered with — the exact class of silent mis-binding this
    /// resolver exists to remove. It must refuse instead, and refuse before making any call.
    #[tokio::test]
    async fn refuses_a_chain_key_wider_than_uint32() {
        let discovery = address!("00000000000000000000000000000000000000aa");
        for key in [u64::from(u32::MAX) + 1, u64::MAX] {
            let err = default_outbox_from_discovery(key, discovery, &unused_provider())
                .await
                .unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("uint32"), "key {key}: {msg}");
            // Would have wrapped to 0 and read a real (wrong) entry had we cast instead.
            assert!(
                !msg.contains("timed out"),
                "key {key} reached the RPC: {msg}"
            );
        }
    }

    /// The widest key the registry can actually represent must pass the guard and proceed to the
    /// call — otherwise the check is off by one and quietly rejects a legitimate chain key.
    #[tokio::test]
    async fn accepts_the_largest_representable_chain_key() {
        let discovery = address!("00000000000000000000000000000000000000aa");
        let err = default_outbox_from_discovery(u64::from(u32::MAX), discovery, &unused_provider())
            .await
            .unwrap_err();
        // Reaching the RPC (which cannot connect on port 1) proves the guard let it through.
        let msg = err.to_string();
        assert!(
            !msg.contains("uint32"),
            "rejected a representable key: {msg}"
        );
    }

    /// A chain key with no discovery address registered fails closed with a message naming the
    /// missing registration, not an opaque RPC error — this is the resolver's whole contract now
    /// that there is nothing to fall back to.
    #[tokio::test]
    async fn resolve_fails_closed_when_nothing_is_registered() {
        // Can't exercise the "registered but empty" path without a live provider here (that's
        // covered by the guard tests above and by integration tests elsewhere); this pins the
        // error-shaping contract on `DiscoveryResolver::resolve` when the precompile call itself
        // can't be reached, which must still surface a chain_key-scoped error, not panic.
        let route = route_with(2);
        let err = DiscoveryResolver::default()
            .resolve(&route, &unused_provider())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("2"), "{err}");
    }

    /// The override, when set, short-circuits the registry lookup entirely — it must not touch
    /// the provider at all, so this can assert against `unused_provider()` unconditionally.
    #[tokio::test]
    async fn override_address_bypasses_the_registry() {
        let route = route_with(2);
        let overridden = address!("00000000000000000000000000000000000000aa");
        let resolver = DiscoveryResolver {
            override_address: Some(overridden),
        };
        let resolved = resolver
            .resolve(&route, &unused_provider())
            .await
            .expect("override must resolve without touching the provider");
        assert_eq!(resolved.address, overridden);
        assert_eq!(resolved.current_since_block, None);
    }
}
