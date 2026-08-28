//! Outbox address resolution.
//!
//! Three [`OutboxResolver`] implementations, selected per route in `message-relayer::lib`'s
//! resolver-selection block: [`ConfigOverrideResolver`] for an explicit `outbox_address`;
//! [`RegistryResolver`] for a route pinned to a specific `outbox_registry_address`; and
//! [`FactoryResolver`] for everything else, which reads the discovery-registry address off the
//! chain-info precompile itself (see [`resolve_from_precompile_registry`]) and only falls back to
//! scanning the factory's permissionless `OutboxCreated` logs when no registry is registered for
//! the chain key yet.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{address, Address};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::Filter;
use alloy::sol;
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::abi::{IOutboxDeployer, IOutboxFactory};
use crate::checkpoint::{CheckpointStore, FactoryScan};
use crate::config::ChainRoute;
use write_ability::protocol::chain_key_to_bytes32;

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

/// PoC default: take whatever the operator put in `route.outbox_address` and refuse to start
/// otherwise. Used for any route with an explicit `outbox_address`; routes without one use
/// [`FactoryResolver`] (see `message-relayer::lib`'s resolver selection).
#[derive(Debug, Default)]
pub struct ConfigOverrideResolver;

#[async_trait]
impl OutboxResolver for ConfigOverrideResolver {
    async fn resolve(&self, route: &ChainRoute, _provider: &DynProvider) -> Result<ResolvedOutbox> {
        let address = route.outbox_address.with_context(|| {
            format!(
                "chain_key {} has no outbox_address and no factory-based resolution requested — \
                 set `outbox_address` in the route config",
                route.chain_key
            )
        })?;
        Ok(ResolvedOutbox {
            address,
            current_since_block: None,
        })
    }
}

/// Resolve the Outbox by reading the deployer/discovery registry, instead of scanning the
/// factory's `OutboxCreated` logs.
///
/// This exists for a security reason rather than a tidiness one. `OutboxFactory.deployOutbox` is
/// intentionally permissionless, and the CREATE2 salt binds `msg.sender`, so any account can
/// deploy an Outbox for any chain key and emit an `OutboxCreated` that is byte-indistinguishable
/// from a legitimate one. [`FactoryResolver`] binds the newest such log, so an attacker's
/// deployment is permanently newest and the fleet follows a contract they control — including its
/// fee registry and validator. The contract-side design comment justifies the permissionless
/// factory on the grounds that an unauthorised caller "only spends its own gas on an Outbox the
/// protocol never registers", which is true for a consumer that reads the registry and false for
/// one that reads logs.
///
/// The registry only records deployments performed through `OutboxDeployer` (owner-gated as of
/// asc-contracts#38), so it cannot be written by an outside caller.
///
/// Cheap by construction: one `eth_call` per resolve, no chunked `getLogs` sweep, no persisted
/// scan cursor, and no genesis-fallback recovery path — none of which this resolver needs, which
/// is why it is a fraction of [`FactoryResolver`]'s size.
#[derive(Debug, Default)]
pub struct RegistryResolver;

#[async_trait]
impl OutboxResolver for RegistryResolver {
    async fn resolve(&self, route: &ChainRoute, provider: &DynProvider) -> Result<ResolvedOutbox> {
        let chain_key = route.chain_key;
        let registry = route.outbox_registry_address.with_context(|| {
            format!(
                "chain_key {chain_key} selected registry resolution without an \
                 `outbox_registry_address` — this is a resolver-selection bug, not a config error"
            )
        })?;

        let address = outbox_from_registry(chain_key, registry, provider).await?;

        // No creation block to report: the registry stores the address only. `current_since_block`
        // is an optimisation for the message watcher's start height, and `None` simply means it
        // uses the route's configured start rather than the Outbox's creation block.
        Ok(ResolvedOutbox {
            address,
            current_since_block: None,
        })
    }
}

/// Call `outboxOf(chainKey)` on `registry` and turn a zero answer into an error. Used only by
/// [`RegistryResolver`]'s explicitly configured `registry` — kept on `outboxOf`/`OutboxDeployer`
/// deliberately, matching PR #45's original reasoning: `outboxOf` exists at the pinned
/// contracts SHA and is drift-gate-checked today, while the better long-term target,
/// `OutboxDiscovery.defaultOutbox` (see [`default_outbox_from_discovery`]), depends on
/// asc-contracts#38, still unmerged. Swapping this one too is a follow-up once that pin moves.
async fn outbox_from_registry(
    chain_key: u64,
    registry: Address,
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

    let deployer = IOutboxDeployer::new(registry, provider);
    let address = tokio::time::timeout(
        PRECOMPILE_CALL_TIMEOUT,
        deployer.outboxOf(chain_key_u32).call(),
    )
    .await
    .with_context(|| {
        format!(
            "chain_key {chain_key}: outboxOf on registry {registry} timed out after \
             {PRECOMPILE_CALL_TIMEOUT:?}"
        )
    })?
    .with_context(|| {
        format!("chain_key {chain_key}: outboxOf call on registry {registry} failed")
    })?;

    if address.is_zero() {
        anyhow::bail!(
            "chain_key {chain_key}: registry {registry} has no Outbox for this chain key \
             (outboxOf returned the zero address) — deploy through OutboxDeployer, or point \
             `outbox_registry_address` at the registry that holds it"
        );
    }

    Ok(address)
}

/// Call `defaultOutbox(chainKey)` on `discovery` and turn a zero answer into an error. Used only
/// by [`resolve_from_precompile_registry`], whose registry address comes from the chain-info
/// precompile rather than route config, so it is free to target the current interface directly
/// instead of `outboxOf`/`OutboxDeployer` (see [`outbox_from_registry`]'s doc for why that one
/// stays as-is). `defaultOutbox`, not `outboxOf`, is the confirmed source of truth: "the default
/// deployed outbox for each chain via: `defaultOutbox(chainKey)` (not from deployer) because
/// there will be multiple version[s] of outbox" (Kevin Nguyen, Slack, 28 Aug 2026).
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
/// one is registered, resolve the Outbox from it via [`default_outbox_from_discovery`]. This is
/// what makes registry-based resolution the automatic default for [`FactoryResolver`] rather than
/// something every route must opt into: no config change is needed once governance registers a
/// discovery address for a chain key.
///
/// Returns `Ok(None)` — not an error — when no discovery address is registered for `chain_key`
/// yet, so the caller falls through to the factory scan in that case. Any other failure (a
/// registered-but-reverting registry, or one that answers zero) propagates as an error rather than
/// silently falling back to the spoofable log scan.
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
    /// in sync with creditcoin3 by hand. Confirmed against `precompiles/metadata/abi/chain_info.json`
    /// on branch `writeability-off-usc-dev` (Aug 2026) — not yet on `main`/`usc-dev`.
    #[sol(rpc)]
    #[derive(Debug)]
    contract IChainInfo {
        /// The factory contract governing `chainKey`, from
        /// `pallet_supported_chains::OutboxFactories`. `exists = false` (with `factoryAddr` the
        /// zero address) when nothing is registered for `chainKey`.
        function get_outbox_factory_address(uint64 chainKey)
            external
            view
            returns (address factoryAddr, bool exists);

        /// The Outbox discovery-registry contract governing `chainKey` (`OutboxDiscovery` in
        /// asc-contracts), from `pallet_supported_chains::OutboxDiscoveries`. Unlike the factory
        /// above, this address is safe to trust directly: it is only ever written through an
        /// access-controlled deploy path, so `defaultOutbox` on it can be read straight into a
        /// resolved Outbox instead of scanning `OutboxCreated` logs. `exists = false` (with
        /// `discoveryAddr` the zero address) when nothing is registered for `chainKey`.
        function get_outbox_discovery_address(uint64 chainKey)
            external
            view
            returns (address discoveryAddr, bool exists);
    }

    /// `IOutboxDiscovery` (asc-contracts#38, unmerged as of this binding — not yet checked by the
    /// `abi_surface` drift gate, same treatment as `IChainInfo` above). Confirmed as the source of
    /// truth on Slack (Kevin Nguyen, 28 Aug 2026): "the default deployed outbox for each chain
    /// via: defaultOutbox(chainKey) (not from deployer) because there will be multiple version[s]
    /// of outbox".
    #[sol(rpc)]
    #[derive(Debug)]
    contract IOutboxDiscovery {
        /// The default Outbox for `chainKey`, or the zero address if none.
        function defaultOutbox(uint32 chainKey) external view returns (address);
    }
}

/// `ChainInfoPrecompile`'s fixed address (`AddressU64<4051>` = 4051 decimal = `0xfd3`).
const CHAIN_INFO_PRECOMPILE: Address = address!("0000000000000000000000000000000000000fd3");

/// Maximum block span per `eth_getLogs` chunk — mirrors `events::MAX_BLOCKS_PER_SCAN` /
/// `ack::MAX_BLOCKS_PER_SCAN`; bounded chunks advance the cursor incrementally instead of asking
/// an RPC for a range larger than it will serve.
const MAX_BLOCKS_PER_SCAN: u64 = 2_000;

/// Chunks processed per [`FactoryResolver::resolve`] call. Bounds one call's latency on a cold
/// start against a long block-range backlog; progress persists in `state`, so the next call (the
/// periodic re-resolution in `events::watch_outbox`, or a startup-bootstrap retry) resumes exactly
/// where this one stopped instead of rescanning.
const MAX_SCAN_CHUNKS_PER_CALL: usize = 20;

/// Bounds every individual RPC/precompile call this resolver makes (mirrors
/// `delivery::FUNDED_GAS_READ_TIMEOUT` — a single chain read, not a tx wait). Without it a
/// black-holed provider would hang `resolve()` forever while it holds `state`'s lock, wedging
/// every other caller sharing this resolver (`events::watch_outbox` and `ack::run` share one
/// `FactoryResolver` per route). Applied per call rather than once around the whole function so a
/// slow-but-alive provider can still make multiple chunks of progress in one `resolve()` call.
/// Split per call by expected cost: a plain block-number read is cheap and should fail fast;
/// `eth_getLogs` over up to `MAX_BLOCKS_PER_SCAN` blocks is the most expensive of the three and
/// gets the most headroom.
const PRECOMPILE_CALL_TIMEOUT: Duration = Duration::from_secs(20);
const BLOCK_NUMBER_TIMEOUT: Duration = Duration::from_secs(10);
const GET_LOGS_TIMEOUT: Duration = Duration::from_secs(30);

/// Env override for whether a detected factory rotation resumes the new factory's `OutboxCreated`
/// scan from the old factory's already-reached cursor, instead of rescanning from genesis. See
/// [`FactoryResolver::resolve`]'s doc for the reasoning; default `true`.
const ROTATION_RESUME_FROM_CHECKPOINT_ENV: &str = "RELAYER_FACTORY_ROTATION_RESUME_FROM_CHECKPOINT";

/// Env override for the block every *from-scratch* `OutboxCreated` scan starts at, replacing a
/// literal genesis: a first boot with no checkpoint, a rotation with
/// [`ROTATION_RESUME_FROM_CHECKPOINT_ENV`] disabled, and the genesis fallback below. Default 0.
///
/// A floor for scans with no position, never a rewind of one that has it: a persisted checkpoint,
/// or a rotation resuming from one, is kept even when it sits below this value. Raising it to a
/// height known to precede this chain key's factory deployment is what makes those scans cheap on a
/// long-lived chain — at the cost that an `OutboxCreated` *below* it becomes undiscoverable,
/// including via the fallback, which floors here too.
const FACTORY_SCAN_GENESIS_BLOCK_ENV: &str = "RELAYER_FACTORY_SCAN_GENESIS_BLOCK";

/// Per-`chain_key` scan progress, cached across [`FactoryResolver::resolve`] calls.
#[derive(Debug, Clone, Copy, Default)]
struct ScanState {
    /// Factory this progress applies to; a mismatch against a freshly-resolved factory means it's
    /// for a different log stream and must be discarded (handled in `resolve`).
    factory: Address,
    /// Highest block scanned so far (inclusive); the next scan starts at `scanned_to + 1`.
    scanned_to: u64,
    /// The latest `OutboxCreated` match found so far — its Outbox address, and `(block, log_index)`
    /// so "latest wins" is well-defined even when a permissionless redeploy lands in the same
    /// block as an earlier one.
    current: Option<(Address, u64, u64)>,
    /// Block this factory's scan *started* from. Everything below it has never been looked at for
    /// this factory, which is exactly what [`genesis_fallback_target`] needs: a completed scan that
    /// found nothing is only conclusive when this equals the configured floor. Moves with
    /// `scanned_to` whenever a scan (re)starts, and is persisted alongside it.
    scan_floor: u64,
    /// Whether the genesis fallback has already been spent on this factory. Reset on every factory
    /// change, so each factory gets exactly one — bounding the recovery to a single extra full scan
    /// rather than one per 60 s re-resolve.
    genesis_fallback_done: bool,
    /// The `confirmed` value the genesis fallback may not fire below, or `None` if a rotation was
    /// just (re)detected and the next `resolve()` call still needs to stamp it in with that call's
    /// `tip`. A factory just rotated to can have its own `OutboxCreated` sitting inside the last
    /// `block_confirmation_depth` blocks — real, but outside `confirmed` — so a scan that has merely
    /// caught up to `confirmed` and found nothing is not yet conclusive; it only becomes conclusive
    /// once `confirmed` reaches the tip observed at rotation-detection time, which guarantees that
    /// window has fully closed. `Some(0)` for a from-scratch scan or an in-place resume: neither is
    /// reacting to a freshly observed rotation, so there is no such window to wait out.
    fallback_eligible_from: Option<u64>,
}

impl ScanState {
    /// Fresh scan state for a rotation onto `factory`, starting at `floor` —
    /// [`rotation_scan_start`]'s result. Shared by both places a rotation is (re)detected: at
    /// startup, when a persisted checkpoint is recorded against a different factory
    /// (`FactoryResolver::initial_scan_state`), and mid-process, when the previously-resolved
    /// factory itself changes (`FactoryResolver::resolve`). One constructor means both legs get the
    /// identical reset — `scan_floor` seeded from `floor`, and a fresh `genesis_fallback_done` /
    /// `fallback_eligible_from` — instead of risking one silently drifting from the other, and the
    /// tests written against this constructor cover the mid-process leg too, not just the startup
    /// one that happens to be easy to unit-test directly.
    fn restarted_at(factory: Address, floor: u64) -> Self {
        ScanState {
            factory,
            scanned_to: floor,
            current: None,
            scan_floor: floor,
            genesis_fallback_done: false,
            fallback_eligible_from: None,
        }
    }

    /// Record an `OutboxCreated` match at `(block, log_index)`, keeping it only if it is more
    /// recent than whatever is already recorded — order-independent, so it does not matter what
    /// order a chunk's logs (or successive chunks) arrive in.
    fn record_if_latest(&mut self, address: Address, block: u64, log_index: u64) {
        let wins = match self.current {
            Some((_, cur_block, cur_index)) => (block, log_index) > (cur_block, cur_index),
            None => true,
        };
        if wins {
            self.current = Some((address, block, log_index));
        }
    }
}

/// The [`ScanState::scanned_to`] to assign when starting a fresh scan of a newly-detected factory:
/// `previous_scanned_to - 1` (the block height already reached under whatever this chain_key's
/// scan was tracking before — a persisted checkpoint recorded against a different factory, or the
/// in-memory state just before a mid-process rotation) when `resume_from_checkpoint` is set,
/// genesis (0) otherwise. Pure so the resume-vs-genesis decision is unit-testable without a live
/// provider.
///
/// The `- 1` matters: `scanned_to` means "scanned through this block, inclusive" and the next chunk
/// starts at `scanned_to + 1`, so assigning `previous_scanned_to` verbatim would skip that boundary
/// block on the new factory's log stream entirely — mirrors `events::outbox_rotation_is_safe`'s
/// identical `saturating_sub(1)` treatment of `current_since_block` for the same reason. The
/// `false` arm needs the identical treatment for the identical reason: assigning `genesis_block`
/// verbatim would skip the floor itself, the one block a from-scratch scan most needs to cover.
///
/// Resuming from near that height (rather than genesis) is an intentional trade: nothing strictly
/// before it could have driven any delivery through the not-yet-current new Outbox, so a real
/// "just rotated to" `OutboxCreated` is always at or after it. The risk is a permissionless
/// `deployOutbox` on the new factory that predates that height (a mirror/pre-deployed Outbox, as
/// opposed to one created as part of the rotation itself) — that event would never be found.
/// `false` restores the original always-genesis behavior for operators who need that guarantee —
/// as does [`genesis_fallback_target`] automatically, once such a scan has actually come up empty.
fn rotation_scan_start(
    previous_scanned_to: u64,
    resume_from_checkpoint: bool,
    genesis_block: u64,
) -> u64 {
    if resume_from_checkpoint {
        // Note the asymmetry with the `false` arm: a resume keeps the checkpoint verbatim even when
        // it sits *below* `genesis_block`. The floor answers "where does a scan with no usable
        // position start?", and a checkpoint is a position; raising it here would skip range the
        // previous scan had already proven worth covering.
        previous_scanned_to.saturating_sub(1)
    } else {
        genesis_block.saturating_sub(1)
    }
}

/// The three-way outcome of a completed (caught up to `confirmed`) but empty `OutboxCreated` scan.
/// Pure so the decision is unit-testable without a live provider, exactly like
/// [`rotation_scan_start`] beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenesisFallback {
    /// Rewind to this block and rescan once before reporting "no Outbox".
    Rewind(u64),
    /// A rewind is warranted — the scan began above the floor and the one shot hasn't been spent —
    /// but the factory just rotated to may still have its own `OutboxCreated` sitting inside the
    /// unconfirmed tail. Not yet conclusive either way: wait for `confirmed` to reach
    /// `fallback_eligible_from` before deciding, rather than reporting "no Outbox" prematurely.
    AwaitingConfirmation,
    /// Nothing left to try: a match was found, the scan already began at the floor, or the one
    /// shot has already been spent. "No Outbox" is the truth.
    Conclusive,
}

/// Where a completed-but-empty `OutboxCreated` scan should restart, or whether "this factory has
/// no Outbox" is (or isn't yet) final.
///
/// The fallback exists because [`rotation_scan_start`]'s resume is an *assumption* — that the
/// rotated-to factory was itself deployed at rotation time — and a wrong one is otherwise
/// unrecoverable: the scan runs to the tip, matches nothing, and the cursor is then persisted at
/// the tip against that very factory, so it reads back as a valid checkpoint and a restart makes
/// the state stickier rather than clearing it.
///
/// A rewind requires two conditions, both necessary:
/// - `scan_floor > genesis_block` — the scan began above the floor, so there is unlooked-at range
///   below it. A scan that already began at the floor has covered everything, and its "no Outbox"
///   verdict is the truth;
/// - `already_used` is false — one rewind per factory, so a factory that genuinely has no
///   `OutboxCreated` settles back into the cheap tip-following steady state instead of rescanning
///   the whole chain on every re-resolve.
///
/// A found match (`found_something`) short-circuits to [`GenesisFallback::Conclusive`] regardless
/// — a match makes the scan conclusive whatever floor it began at. Otherwise, whenever a rewind
/// would be warranted, `confirmed >= fallback_eligible_from` decides whether it fires now
/// ([`GenesisFallback::Rewind`]) or must wait ([`GenesisFallback::AwaitingConfirmation`]): a
/// factory just rotated to can have its own `OutboxCreated` sitting inside the last
/// `block_confirmation_depth` blocks, real but not yet inside `confirmed`. Firing before that
/// window closes would burn the one-shot rewind on a routine, healthy rotation whose event simply
/// has not reached confirmation depth yet — not on one that is genuinely absent. See
/// [`ScanState::fallback_eligible_from`].
fn genesis_fallback_target(
    found_something: bool,
    scan_floor: u64,
    genesis_block: u64,
    already_used: bool,
    confirmed: u64,
    fallback_eligible_from: u64,
) -> GenesisFallback {
    if found_something || already_used || scan_floor <= genesis_block {
        GenesisFallback::Conclusive
    } else if confirmed < fallback_eligible_from {
        GenesisFallback::AwaitingConfirmation
    } else {
        GenesisFallback::Rewind(genesis_block)
    }
}

/// Production resolver: finds the Outbox for `route.chain_key` entirely from on-chain state, no
/// operator-supplied address — mirroring creditcoin3's own attestor-fleet resolver, which avoids a
/// configured factory address on the same grounds ("an address supplied separately from the chain
/// key may not correspond to it").
///
///  1. `get_outbox_factory_address(chainKey)` on [`CHAIN_INFO_PRECOMPILE`] — the factory governing
///     this chain key.
///  2. Scan that factory's `OutboxCreated` logs for `chainKey`, latest by block order wins —
///     `deployOutbox` is permissionless, so more than one may exist over time.
///
/// Called both once at startup and periodically thereafter; progress is cached per `chain_key` in
/// `state`. Only returns `Ok` once fully caught up to that call's confirmed tip, never an
/// early/not-yet-final match — a more recent `OutboxCreated` could still be sitting unscanned.
///
/// `route.start_block` is deliberately not reused to seed a fresh scan: it backfills
/// `MessagePublished` on the Outbox, a different contract's history, and could start the scan
/// after the very `OutboxCreated` it needs to find.
///
/// When `checkpoint` is `Some`, a chain_key's scan progress (cursor + winner found so far, see
/// [`FactoryScan`]) is persisted after every call and reloaded the first time that chain_key is
/// seen in this process — so a restart resumes the scan instead of rescanning from genesis.
///
/// A persisted (or in-memory) scan recorded against a factory other than the one freshly resolved
/// — an Outbox-factory rotation, observed either while the relayer was down or while it was
/// running — resumes the *new* factory's scan from the *old* one's already-reached cursor rather
/// than genesis, when [`ROTATION_RESUME_FROM_CHECKPOINT_ENV`] is enabled (default; see
/// [`rotation_scan_start`]). Without that env var (or with it disabled), a rotation always
/// rescans the new factory from genesis — safe, but a full-history `eth_getLogs` scan on both the
/// rotate and the eventual restore, which on a long-lived chain can take minutes even though
/// nothing before the old factory's cursor could have driven a delivery through the not-yet-current
/// new outbox. `checkpoint: None` keeps the old in-memory-only behaviour (used in tests and when
/// persistence is disabled entirely) but still honors the rotation-resume setting.
///
/// `state`'s lock is held across every RPC call in a `resolve()` invocation (simplest way to keep
/// a chain_key's scan progress consistent across its chunk loop) — a caller sharing this resolver
/// with another route worker (see `lib.rs`'s resolver selection) waits behind it. Bounded by
/// [`PRECOMPILE_CALL_TIMEOUT`]/[`BLOCK_NUMBER_TIMEOUT`]/[`GET_LOGS_TIMEOUT`] on every call, so that
/// wait is minutes at worst, never indefinite.
#[derive(Debug, Default)]
pub struct FactoryResolver {
    state: Mutex<HashMap<u64, ScanState>>,
    checkpoint: Option<Arc<CheckpointStore>>,
    /// Cached once at construction (see [`ROTATION_RESUME_FROM_CHECKPOINT_ENV`]) rather than
    /// re-read on every `resolve()` call — this only needs to change with a restart.
    resume_rotation_from_checkpoint: bool,
    /// Cached once at construction (see [`FACTORY_SCAN_GENESIS_BLOCK_ENV`]), same reasoning.
    genesis_block: u64,
}

impl FactoryResolver {
    pub fn new(checkpoint: Option<Arc<CheckpointStore>>) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            checkpoint,
            resume_rotation_from_checkpoint: crate::config::bool_env_override(
                ROTATION_RESUME_FROM_CHECKPOINT_ENV,
                true,
            ),
            genesis_block: crate::config::block_env_override(FACTORY_SCAN_GENESIS_BLOCK_ENV, 0),
        }
    }

    /// The checkpoint-store key this resolver persists `chain_key`'s scan progress under.
    fn checkpoint_key(chain_key: u64) -> String {
        format!("factory:{chain_key}")
    }

    /// The [`ScanState`] to start a fresh-in-this-process scan of `factory` with, given whatever
    /// was previously persisted for this chain_key (if anything). Pulled out of `resolve` as a
    /// pure function so the resume-vs-discard decision is unit-testable without a live provider.
    ///
    /// `persisted` is reused verbatim only when it was recorded against this same `factory`. A
    /// mismatch (an Outbox-factory rotation that happened while the relayer was down) resumes from
    /// the persisted cursor's height when `resume_from_checkpoint` is set (see
    /// [`rotation_scan_start`]), exactly like the in-memory `scan.factory != factory` check in
    /// `resolve` does for a rotation observed while running; otherwise it restarts from genesis,
    /// same as "nothing persisted".
    fn initial_scan_state(
        factory: Address,
        persisted: Option<&FactoryScan>,
        resume_from_checkpoint: bool,
        genesis_block: u64,
    ) -> ScanState {
        match persisted {
            Some(persisted) if persisted.factory == factory.to_string() => ScanState {
                factory,
                scanned_to: persisted.scanned_to,
                current: persisted
                    .winner
                    .as_ref()
                    .and_then(|(address, block, log_index)| {
                        address
                            .parse::<Address>()
                            .ok()
                            .map(|a| (a, *block, *log_index))
                    }),
                // Carried, not recomputed: the floor this scan actually began at is what lets the
                // genesis fallback still recognise a stranded cursor after a restart — the very
                // moment the "just restart it" reflex would otherwise entrench it.
                scan_floor: persisted.scan_floor,
                genesis_fallback_done: false,
                // Carried, not reset to "already eligible": a restart mid-grace-window (a healthy
                // rotation whose OutboxCreated hasn't reached confirmation depth yet) must keep
                // waiting out the same threshold, not reopen as eligible and fire the one-shot
                // fallback on a scan that was never actually conclusive.
                fallback_eligible_from: Some(persisted.fallback_eligible_from),
            },
            Some(persisted) => {
                let floor = rotation_scan_start(
                    persisted.scanned_to,
                    resume_from_checkpoint,
                    genesis_block,
                );
                ScanState::restarted_at(factory, floor)
            }
            None => ScanState {
                factory,
                // `- 1`, not `genesis_block` verbatim: see `rotation_scan_start`'s doc above for why
                // assigning the floor straight to `scanned_to` would skip it. `scan_floor` takes the
                // unadjusted value — it's "where the scan started", not a cursor.
                scanned_to: genesis_block.saturating_sub(1),
                current: None,
                scan_floor: genesis_block,
                genesis_fallback_done: false,
                // Not a rotation, and scan_floor == genesis_block here anyway, so the fallback's own
                // `scan_floor > genesis_block` condition already excludes this scan — set for
                // consistency with the other non-rotation arm, not because it changes behavior.
                fallback_eligible_from: Some(0),
            },
        }
    }
}

#[async_trait]
impl OutboxResolver for FactoryResolver {
    async fn resolve(&self, route: &ChainRoute, provider: &DynProvider) -> Result<ResolvedOutbox> {
        let chain_key = route.chain_key;

        // Prefer a registered discovery registry over the factory's log stream — see
        // `resolve_from_precompile_registry`. Falls through unchanged to the factory scan below
        // when no registry is registered for this chain key yet, so migration is automatic and
        // gradual: no config change needed once governance sets the discovery address on-chain,
        // and a chain key not yet migrated keeps resolving exactly as before.
        if let Some(resolved) = resolve_from_precompile_registry(chain_key, provider).await? {
            info!(
                chain_key,
                address = %resolved.address,
                "🧭 resolved Outbox on-chain (discovery registry)"
            );
            return Ok(resolved);
        }

        let chain_info = IChainInfo::new(CHAIN_INFO_PRECOMPILE, provider);
        let factory_result = tokio::time::timeout(
            PRECOMPILE_CALL_TIMEOUT,
            chain_info.get_outbox_factory_address(chain_key).call(),
        )
        .await
        .with_context(|| {
            format!(
                "chain_key {chain_key}: get_outbox_factory_address precompile call timed out \
                 after {PRECOMPILE_CALL_TIMEOUT:?}"
            )
        })?
        .with_context(|| {
            format!("chain_key {chain_key}: get_outbox_factory_address precompile call failed")
        })?;
        if !factory_result.exists || factory_result.factoryAddr.is_zero() {
            anyhow::bail!(
                "chain_key {chain_key} has no OutboxFactory registered on-chain \
                 (pallet supportedChains.OutboxFactories is empty for this key)"
            );
        }
        let factory = factory_result.factoryAddr;

        let mut states = self.state.lock().await;
        let first_use_in_process = !states.contains_key(&chain_key);
        let scan = states.entry(chain_key).or_default();

        if first_use_in_process {
            let persisted = self
                .checkpoint
                .as_ref()
                .and_then(|cp| cp.get_factory_scan(&Self::checkpoint_key(chain_key)));
            match &persisted {
                Some(p) if p.factory == factory.to_string() => info!(
                    chain_key,
                    %factory,
                    scanned_to = p.scanned_to,
                    winner = ?p.winner,
                    "↩️ resuming OutboxCreated discovery from persisted factory-scan checkpoint"
                ),
                Some(p) => info!(
                    chain_key,
                    %factory,
                    persisted_factory = %p.factory,
                    resume_from_checkpoint = self.resume_rotation_from_checkpoint,
                    genesis_block = self.genesis_block,
                    "factory-scan checkpoint is recorded against a different factory (rotated \
                     while down); its winner is discarded and the new factory's scan restarts \
                     from the checkpoint height or the configured genesis block"
                ),
                None => {}
            }
            *scan = Self::initial_scan_state(
                factory,
                persisted.as_ref(),
                self.resume_rotation_from_checkpoint,
                self.genesis_block,
            );
        }

        if scan.factory != factory {
            // Factory rotation observed mid-process (not just at startup): scan the new factory's
            // history starting from the old factory's cursor (default) or from genesis — see
            // `rotation_scan_start` and the doc on `resolve` above.
            let resume_from = rotation_scan_start(
                scan.scanned_to,
                self.resume_rotation_from_checkpoint,
                self.genesis_block,
            );
            info!(
                chain_key,
                old_factory = %scan.factory,
                new_factory = %factory,
                resume_from,
                resume_from_checkpoint = self.resume_rotation_from_checkpoint,
                genesis_block = self.genesis_block,
                "🔁 factory rotation detected mid-process; restarting OutboxCreated discovery on \
                 the new factory"
            );
            // A fresh factory earns a fresh fallback: this is the transition that can overshoot.
            *scan = ScanState::restarted_at(factory, resume_from);
        }

        let tip = tokio::time::timeout(BLOCK_NUMBER_TIMEOUT, provider.get_block_number())
            .await
            .with_context(|| {
                format!(
                    "chain_key {chain_key}: reading chain head timed out after \
                     {BLOCK_NUMBER_TIMEOUT:?}"
                )
            })?
            .with_context(|| format!("chain_key {chain_key}: failed to read chain head"))?;
        let confirmed = tip.saturating_sub(route.block_confirmation_depth);

        // Stamp the fallback's grace threshold with this call's tip the first time it's needed
        // (i.e. exactly the call that just (re)detected a rotation, above or on a prior call) —
        // see `ScanState::fallback_eligible_from`. A no-op once it's already `Some`.
        if scan.fallback_eligible_from.is_none() {
            scan.fallback_eligible_from = Some(tip);
        }

        let mut chunks = 0;
        while scan.scanned_to < confirmed && chunks < MAX_SCAN_CHUNKS_PER_CALL {
            let from_block = scan.scanned_to + 1;
            let to_block = confirmed.min(scan.scanned_to.saturating_add(MAX_BLOCKS_PER_SCAN));

            let filter = Filter::new()
                .address(factory)
                .event_signature(IOutboxFactory::OutboxCreated::SIGNATURE_HASH)
                .topic2(chain_key_to_bytes32(chain_key))
                .from_block(from_block)
                .to_block(to_block);

            let logs = tokio::time::timeout(GET_LOGS_TIMEOUT, provider.get_logs(&filter))
                .await
                .with_context(|| {
                    format!(
                        "chain_key {chain_key}: eth_getLogs OutboxCreated on factory {factory} \
                         from {from_block} to {to_block} timed out after {GET_LOGS_TIMEOUT:?}"
                    )
                })?
                .with_context(|| {
                    format!(
                        "chain_key {chain_key}: eth_getLogs OutboxCreated on factory {factory} \
                         from {from_block} to {to_block} failed"
                    )
                })?;

            for log in logs {
                let (Some(block), Some(log_index)) = (log.block_number, log.log_index) else {
                    warn!(
                        chain_key,
                        %factory,
                        "OutboxCreated log missing block number or log index; skipping"
                    );
                    continue;
                };
                match IOutboxFactory::OutboxCreated::decode_log(&log.inner) {
                    Ok(decoded) => {
                        scan.record_if_latest(decoded.data.outbox, block, log_index);
                    }
                    Err(err) => {
                        warn!(chain_key, %factory, %err, "could not decode OutboxCreated log; skipping");
                    }
                }
            }

            scan.scanned_to = to_block;
            chunks += 1;
        }

        // Only meaningful once the chunk loop has actually caught up: mid-backlog the scan is
        // incomplete by construction, and the `scan.scanned_to < confirmed` bail below handles it.
        let mut awaiting_confirmation = false;
        if scan.scanned_to >= confirmed {
            match genesis_fallback_target(
                scan.current.is_some(),
                scan.scan_floor,
                self.genesis_block,
                scan.genesis_fallback_done,
                confirmed,
                scan.fallback_eligible_from.unwrap_or(0),
            ) {
                GenesisFallback::Rewind(rewind_to) => {
                    warn!(
                        chain_key,
                        %factory,
                        scanned_from = scan.scan_floor,
                        scanned_to = scan.scanned_to,
                        rewind_to,
                        "🪃 no OutboxCreated found above the resumed checkpoint; the factory's own \
                         event may predate it (a rotation onto a pre-existing factory). Rescanning \
                         once from the configured genesis block before reporting no Outbox"
                    );
                    scan.genesis_fallback_done = true;
                    // `- 1`, not `rewind_to` verbatim — same reasoning as `rotation_scan_start`'s
                    // doc: assigning the floor straight to `scanned_to` would skip it on the rescan.
                    scan.scanned_to = rewind_to.saturating_sub(1);
                    scan.scan_floor = rewind_to;
                }
                GenesisFallback::AwaitingConfirmation => awaiting_confirmation = true,
                GenesisFallback::Conclusive => {}
            }
        }

        // Persisted *after* the rewind above, so a fallback that has been decided is durable: a
        // restart mid-recovery resumes the rescan instead of reloading the very checkpoint that
        // stranded this chain key. Also carries `fallback_eligible_from` forward unconditionally —
        // by this point `resolve` has always stamped it (see the call right after `confirmed` is
        // computed above) — so a restart mid-grace-window keeps waiting out the same threshold
        // instead of reopening as "already eligible".
        if let Some(cp) = &self.checkpoint {
            let to_persist = FactoryScan {
                factory: factory.to_string(),
                scanned_to: scan.scanned_to,
                winner: scan
                    .current
                    .map(|(address, block, log_index)| (address.to_string(), block, log_index)),
                scan_floor: scan.scan_floor,
                fallback_eligible_from: scan.fallback_eligible_from.unwrap_or(0),
            };
            if let Err(err) = cp.set_factory_scan(&Self::checkpoint_key(chain_key), &to_persist) {
                warn!(chain_key, %err, "failed to persist factory-resolver scan checkpoint");
            }
        }

        if scan.scanned_to < confirmed {
            // Not yet caught up to the confirmed tip — a match found so far could still be
            // superseded by a more recent one further ahead. Bail so the caller retries, resuming
            // this cursor rather than rescanning.
            anyhow::bail!(
                "chain_key {chain_key}: still scanning OutboxCreated backlog on factory {factory} \
                 ({} of {confirmed} blocks); resolution not final yet",
                scan.scanned_to
            );
        }

        if awaiting_confirmation {
            // The scan itself is caught up, but a rewind decision is still pending on the
            // confirmation-depth window — reporting "no Outbox" now would be premature (the
            // Conclusive case doesn't set this flag, so this leg is exactly, and only, the still-
            // settling-rotation case). Bail the same way an incomplete scan does: retryable, not
            // final.
            anyhow::bail!(
                "chain_key {chain_key}: OutboxCreated scan on factory {factory} reached the \
                 confirmed tip ({confirmed}) with no match, but the factory was only just \
                 (re)detected; waiting for the confirmation-depth window to close before treating \
                 that as conclusive — resolution not final yet"
            );
        }

        match scan.current {
            Some((address, block, _)) => Ok(ResolvedOutbox {
                address,
                current_since_block: Some(block),
            }),
            None => {
                // A nonzero floor is indistinguishable at runtime from a genuinely Outbox-less
                // chain_key — the fallback that would otherwise catch it is disabled by the very
                // same misconfiguration — so name it as a candidate cause whenever it could be one,
                // the one breadcrumb on-call has no other way to find.
                let genesis_hint = if self.genesis_block > 0 {
                    format!(
                        "; if this chain_key does have a deployed Outbox, verify its OutboxCreated \
                         predates RELAYER_FACTORY_SCAN_GENESIS_BLOCK ({}) — a floor set above it \
                         makes the event permanently unscannable, including by the genesis fallback",
                        self.genesis_block
                    )
                } else {
                    String::new()
                };
                anyhow::bail!(
                    "chain_key {chain_key}: no OutboxCreated event found for factory {factory} \
                     (scanned {} to {confirmed}); this chain_key has no deployed Outbox yet{genesis_hint}",
                    scan.scan_floor
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AttestorSet, ChainRoute};
    use alloy::providers::ProviderBuilder;

    fn route_with(outbox: Option<Address>) -> ChainRoute {
        ChainRoute {
            chain_key: 2,
            creditcoin_chain_id: 1,
            outbox_address: outbox,
            outbox_registry_address: None,
            destination_rpc_url: "http://x".into(),
            inbox_address: address!("0000000000000000000000000000000000000002"),
            signer_key: None,
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

    fn route_with_registry(registry: Option<Address>, chain_key: u64) -> ChainRoute {
        ChainRoute {
            chain_key,
            outbox_registry_address: registry,
            ..route_with(None)
        }
    }

    /// A `DynProvider` that is never actually called — `ConfigOverrideResolver` ignores its
    /// provider argument entirely, so this only needs to type-check, not connect.
    fn unused_provider() -> DynProvider {
        ProviderBuilder::new()
            .connect_http("http://127.0.0.1:1".parse().unwrap())
            .erased()
    }

    #[tokio::test]
    async fn config_override_returns_set_value() {
        let r = ConfigOverrideResolver;
        let addr = address!("0000000000000000000000000000000000000099");
        let out = r
            .resolve(&route_with(Some(addr)), &unused_provider())
            .await
            .unwrap();
        assert_eq!(out.address, addr);
        assert_eq!(out.current_since_block, None);
    }

    #[tokio::test]
    async fn config_override_fails_without_value() {
        let r = ConfigOverrideResolver;
        let err = r
            .resolve(&route_with(None), &unused_provider())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("outbox_address"));
    }

    /// Selecting registry resolution without an address is a wiring mistake in `lib.rs`, not
    /// something an operator can cause, so the message says so rather than blaming the config.
    #[tokio::test]
    async fn registry_resolver_fails_without_a_registry_address() {
        let err = RegistryResolver
            .resolve(&route_with_registry(None, 2), &unused_provider())
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("outbox_registry_address"), "{msg}");
        assert!(msg.contains("resolver-selection bug"), "{msg}");
    }

    /// The contract keys `outboxOf` by `uint32` while routes carry `chain_key` as `u64`. A plain
    /// `as u32` would wrap 2^32 to 0 and silently read the registry for a *different* chain, then
    /// bind whatever Outbox that answered with — the exact class of silent mis-binding this
    /// resolver exists to remove. It must refuse instead, and refuse before making any call.
    #[tokio::test]
    async fn registry_resolver_refuses_a_chain_key_wider_than_uint32() {
        let registry = address!("00000000000000000000000000000000000000aa");
        for key in [u64::from(u32::MAX) + 1, u64::MAX] {
            let err = RegistryResolver
                .resolve(
                    &route_with_registry(Some(registry), key),
                    &unused_provider(),
                )
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
    async fn registry_resolver_accepts_the_largest_representable_chain_key() {
        let registry = address!("00000000000000000000000000000000000000aa");
        let err = RegistryResolver
            .resolve(
                &route_with_registry(Some(registry), u64::from(u32::MAX)),
                &unused_provider(),
            )
            .await
            .unwrap_err();
        // Reaching the RPC (which cannot connect on port 1) proves the guard let it through.
        let msg = err.to_string();
        assert!(
            !msg.contains("uint32"),
            "rejected a representable key: {msg}"
        );
    }

    #[test]
    fn chain_info_precompile_address_matches_creditcoin3_registration() {
        // AddressU64<4051> per creditcoin3 runtime/src/precompiles.rs: the low 8 bytes of the
        // 20-byte address hold the u64 value big-endian, the rest zero. 4051 decimal = 0xfd3.
        let mut bytes = [0u8; 20];
        bytes[12..20].copy_from_slice(&4051u64.to_be_bytes());
        assert_eq!(CHAIN_INFO_PRECOMPILE, Address::from(bytes));
    }

    /// "Latest wins" tie-break: `(block, log_index)` ordering, not insertion order — a permissionless
    /// redeploy landing in the same block as an earlier one must still resolve deterministically
    /// to the higher log index, regardless of the order `eth_getLogs` happens to return them in.
    #[test]
    fn scan_state_latest_wins_by_block_then_log_index() {
        let a = address!("0000000000000000000000000000000000000001");
        let b = address!("0000000000000000000000000000000000000002");
        let c = address!("0000000000000000000000000000000000000003");

        let mut scan = ScanState::default();
        // Processing order deliberately does not match log_index order — the winner must be
        // decided by (block, log_index), not by arrival order.
        scan.record_if_latest(a, 10, 0);
        scan.record_if_latest(c, 10, 2);
        scan.record_if_latest(b, 10, 1);
        // Highest log_index within the same block wins, regardless of processing order.
        assert_eq!(scan.current, Some((c, 10, 2)));

        // A later block always beats an earlier one, even at log_index 0.
        scan.record_if_latest(a, 11, 0);
        assert_eq!(scan.current, Some((a, 11, 0)));

        // An earlier (block, log_index) than the current winner must not overwrite it.
        scan.record_if_latest(b, 10, 5);
        assert_eq!(scan.current, Some((a, 11, 0)));
    }

    /// No persisted checkpoint at all (first boot, or persistence disabled): start from genesis
    /// regardless of the rotation-resume setting — there is no cursor to resume from.
    #[test]
    fn initial_scan_state_with_nothing_persisted_starts_from_genesis() {
        let factory = address!("0000000000000000000000000000000000000001");
        for resume_from_checkpoint in [true, false] {
            let scan =
                FactoryResolver::initial_scan_state(factory, None, resume_from_checkpoint, 0);
            assert_eq!(scan.factory, factory);
            assert_eq!(scan.scanned_to, 0);
            assert_eq!(scan.current, None);
        }
    }

    /// A checkpoint persisted against this same factory resumes exactly where it left off,
    /// winner included — the entire point of persisting it. Not a rotation, so the resume setting
    /// is irrelevant here.
    #[test]
    fn initial_scan_state_resumes_when_factory_matches() {
        let factory = address!("0000000000000000000000000000000000000001");
        let winner = address!("0000000000000000000000000000000000000002");
        let persisted = FactoryScan {
            factory: factory.to_string(),
            scanned_to: 12_345,
            winner: Some((winner.to_string(), 100, 3)),
            scan_floor: 0,
            fallback_eligible_from: 0,
        };
        let scan = FactoryResolver::initial_scan_state(factory, Some(&persisted), true, 0);
        assert_eq!(scan.factory, factory);
        assert_eq!(scan.scanned_to, 12_345);
        assert_eq!(scan.current, Some((winner, 100, 3)));
    }

    /// A checkpoint persisted against a *different* factory (rotation while the relayer was down),
    /// with the default resume-from-checkpoint behavior enabled: resume the new factory's scan
    /// from just before the old one's cursor instead of genesis, so the boundary block itself is
    /// still scanned on the new factory rather than skipped — the winner does NOT carry over (it
    /// belongs to the old factory's log stream), but the scanned height does.
    #[test]
    fn initial_scan_state_resumes_from_checkpoint_for_a_different_factory_by_default() {
        let old_factory = address!("0000000000000000000000000000000000000001");
        let new_factory = address!("0000000000000000000000000000000000000002");
        let persisted = FactoryScan {
            factory: old_factory.to_string(),
            scanned_to: 12_345,
            winner: Some((
                address!("0000000000000000000000000000000000000003").to_string(),
                100,
                3,
            )),
            scan_floor: 0,
            fallback_eligible_from: 0,
        };
        let scan = FactoryResolver::initial_scan_state(new_factory, Some(&persisted), true, 0);
        assert_eq!(scan.factory, new_factory);
        assert_eq!(scan.scanned_to, 12_344);
        assert_eq!(scan.current, None);
    }

    /// Same rotation-while-down scenario, but with the resume setting disabled: restart from
    /// genesis — the conservative behavior, for operators who need the guarantee that a
    /// permissionless `deployOutbox` predating the old factory's cursor is still found.
    #[test]
    fn initial_scan_state_discards_checkpoint_for_a_different_factory_when_resume_disabled() {
        let old_factory = address!("0000000000000000000000000000000000000001");
        let new_factory = address!("0000000000000000000000000000000000000002");
        let persisted = FactoryScan {
            factory: old_factory.to_string(),
            scanned_to: 12_345,
            winner: Some((
                address!("0000000000000000000000000000000000000003").to_string(),
                100,
                3,
            )),
            scan_floor: 0,
            fallback_eligible_from: 0,
        };
        let scan = FactoryResolver::initial_scan_state(new_factory, Some(&persisted), false, 0);
        assert_eq!(scan.factory, new_factory);
        assert_eq!(scan.scanned_to, 0);
        assert_eq!(scan.current, None);
    }

    /// A checkpoint persisted with no winner yet (scanned some of the range, found nothing) still
    /// resumes the cursor — there is nothing to carry forward as `current`, but the scanned range
    /// itself must not be rescanned.
    #[test]
    fn initial_scan_state_resumes_cursor_with_no_winner_yet() {
        let factory = address!("0000000000000000000000000000000000000001");
        let persisted = FactoryScan {
            factory: factory.to_string(),
            scanned_to: 2_000,
            winner: None,
            scan_floor: 0,
            fallback_eligible_from: 0,
        };
        let scan = FactoryResolver::initial_scan_state(factory, Some(&persisted), true, 0);
        assert_eq!(scan.scanned_to, 2_000);
        assert_eq!(scan.current, None);
    }

    /// `rotation_scan_start` is the pure decision `initial_scan_state` and the mid-process rotation
    /// branch in `resolve` both delegate to: resume just before the old cursor when enabled (so the
    /// boundary block is scanned on the new factory, not skipped), else genesis.
    #[test]
    fn rotation_scan_start_resumes_or_restarts_from_genesis() {
        assert_eq!(rotation_scan_start(691_905, true, 0), 691_904);
        assert_eq!(rotation_scan_start(691_905, false, 0), 0);
        assert_eq!(rotation_scan_start(0, true, 0), 0);
    }

    /// The T4-shaped failure this fallback exists for, in scan-state terms: a rotation onto a
    /// **pre-existing** factory resumes at the old factory's checkpoint, scans to the confirmed
    /// tip, and matches nothing — because the new factory's `OutboxCreated` was emitted far below.
    /// The scan is complete but not conclusive, so it rewinds to the configured floor. The grace
    /// window has already closed (`confirmed` has reached `fallback_eligible_from`) in every case
    /// below unless a test is specifically about that window — see
    /// `genesis_fallback_waits_out_the_confirmation_window_after_a_rotation` for that.
    #[test]
    fn genesis_fallback_rewinds_a_resumed_scan_that_found_nothing() {
        assert_eq!(
            genesis_fallback_target(false, 705_530, 0, false, 705_530, 0),
            GenesisFallback::Rewind(0)
        );
    }

    /// The three ways it's conclusive with no rewind warranted, each for a different reason.
    #[test]
    fn genesis_fallback_declines_when_the_scan_is_already_conclusive() {
        assert_eq!(
            genesis_fallback_target(true, 705_530, 0, false, 705_530, 0),
            GenesisFallback::Conclusive,
            "a match makes the scan conclusive whatever floor it began at"
        );
        assert_eq!(
            genesis_fallback_target(false, 0, 0, false, 0, 0),
            GenesisFallback::Conclusive,
            "a scan that began at the floor has covered everything; no Outbox is the truth"
        );
        assert_eq!(
            genesis_fallback_target(false, 705_530, 0, true, 705_530, 0),
            GenesisFallback::Conclusive,
            "one rewind per factory — otherwise an Outbox-less factory rescans every re-resolve"
        );
    }

    /// The floor is honoured, not hardcoded to 0, and a scan already at or below it is conclusive.
    #[test]
    fn genesis_fallback_targets_the_configured_genesis_block() {
        assert_eq!(
            genesis_fallback_target(false, 705_530, 300_000, false, 705_530, 0),
            GenesisFallback::Rewind(300_000)
        );
        assert_eq!(
            genesis_fallback_target(false, 300_000, 300_000, false, 300_000, 0),
            GenesisFallback::Conclusive
        );
        assert_eq!(
            genesis_fallback_target(false, 250_000, 300_000, false, 300_000, 0),
            GenesisFallback::Conclusive,
            "already below the floor: nothing above it went unscanned"
        );
    }

    /// The confirmation-depth condition: a factory just rotated to can have its own
    /// `OutboxCreated` sitting inside the unconfirmed tail, real but outside `confirmed` — an
    /// empty scan that has only caught up to `confirmed` is not yet conclusive until `confirmed`
    /// reaches the tip observed at rotation-detection time (`fallback_eligible_from`). Neither
    /// rewinds nor reports conclusive while that window is still open; rewinds the instant it
    /// closes.
    #[test]
    fn genesis_fallback_waits_out_the_confirmation_window_after_a_rotation() {
        assert_eq!(
            genesis_fallback_target(false, 705_530, 0, false, 705_540, 705_550),
            GenesisFallback::AwaitingConfirmation,
            "confirmed hasn't yet reached the tip observed when the rotation was detected"
        );
        assert_eq!(
            genesis_fallback_target(false, 705_530, 0, false, 705_550, 705_550),
            GenesisFallback::Rewind(0),
            "confirmed has now caught up to that tip; the window has closed"
        );
    }

    /// `rotation_scan_start`'s two arms treat the floor differently on purpose: the from-scratch
    /// arm takes it, the resume arm keeps the checkpoint verbatim — even below the floor, since a
    /// checkpoint is a position and the floor only answers "where does a scan without one start?".
    /// Both arms return `floor - 1`, though: whichever floor is picked, it is still a `scanned_to`
    /// value, and the floor itself must not be skipped by the next chunk's `scanned_to + 1`.
    #[test]
    fn rotation_scan_start_floors_only_the_from_scratch_arm() {
        assert_eq!(rotation_scan_start(691_905, false, 300_000), 299_999);
        assert_eq!(
            rotation_scan_start(250_000, true, 300_000),
            249_999,
            "a resume below the floor is kept, not raised"
        );
    }

    /// With nothing persisted, a fresh scan starts at the configured floor rather than block 0 —
    /// and its `scan_floor` matches, so a first scan that finds nothing is immediately conclusive
    /// instead of triggering a pointless rewind to the same place. `scanned_to` sits one below the
    /// floor (not at it) so the floor itself is the first block the next chunk actually scans.
    #[test]
    fn initial_scan_state_with_nothing_persisted_starts_at_the_configured_genesis() {
        let factory = address!("0000000000000000000000000000000000000001");
        let scan = FactoryResolver::initial_scan_state(factory, None, true, 300_000);
        assert_eq!(scan.scanned_to, 299_999);
        assert_eq!(
            scan.scanned_to + 1,
            300_000,
            "the floor itself must be scanned, not skipped"
        );
        assert_eq!(scan.scan_floor, 300_000);
        assert_eq!(
            scan.fallback_eligible_from,
            Some(0),
            "not a rotation; no window to wait out"
        );
        assert_eq!(
            genesis_fallback_target(
                false,
                scan.scan_floor,
                300_000,
                scan.genesis_fallback_done,
                300_000,
                scan.fallback_eligible_from.unwrap_or(0),
            ),
            GenesisFallback::Conclusive
        );
    }

    /// A checkpoint reloaded from disk carries both the floor its scan actually began at AND the
    /// confirmation-depth grace threshold, so a restart mid-recovery still recognises the scan as
    /// unresolved rather than reading either the tip-height cursor or a freshly-reset "already
    /// eligible" grace back as a completed, conclusive scan. Losing either one on a restart would
    /// entrench the failure this whole mechanism exists to close — the floor by reading a stranded
    /// cursor as healthy, the grace by firing the one-shot fallback on a rotation that simply
    /// hadn't finished settling when the process happened to restart.
    #[test]
    fn initial_scan_state_carries_the_floor_and_grace_threshold_across_a_restart() {
        let factory = address!("0000000000000000000000000000000000000002");
        let persisted = FactoryScan {
            factory: factory.to_string(),
            scanned_to: 705_600,
            winner: None,
            scan_floor: 705_530,
            fallback_eligible_from: 705_650,
        };
        let scan = FactoryResolver::initial_scan_state(factory, Some(&persisted), true, 0);
        assert_eq!(scan.scanned_to, 705_600);
        assert_eq!(scan.scan_floor, 705_530);
        assert!(!scan.genesis_fallback_done, "a reload re-arms the fallback");
        assert_eq!(
            scan.fallback_eligible_from,
            Some(705_650),
            "carried forward, not reset to 0 — the window from before the restart still applies"
        );
        assert_eq!(
            genesis_fallback_target(
                false,
                scan.scan_floor,
                0,
                scan.genesis_fallback_done,
                705_600,
                scan.fallback_eligible_from.unwrap_or(0),
            ),
            GenesisFallback::AwaitingConfirmation,
            "confirmed hasn't caught up to the carried-forward threshold yet"
        );
        assert_eq!(
            genesis_fallback_target(
                false,
                scan.scan_floor,
                0,
                scan.genesis_fallback_done,
                705_650,
                scan.fallback_eligible_from.unwrap_or(0),
            ),
            GenesisFallback::Rewind(0),
            "once confirmed catches up, the same carried-forward threshold still lets it fire"
        );
    }

    /// A rotation seeds `scan_floor` to wherever the new factory's scan begins, which is the whole
    /// input the fallback turns on — resumed high means "rewind if empty", genesis means "final".
    #[test]
    fn initial_scan_state_seeds_the_floor_from_where_the_rotation_starts() {
        let old_factory = address!("0000000000000000000000000000000000000001");
        let new_factory = address!("0000000000000000000000000000000000000002");
        let persisted = FactoryScan {
            factory: old_factory.to_string(),
            scanned_to: 12_345,
            winner: None,
            scan_floor: 0,
            fallback_eligible_from: 0,
        };
        let resumed = FactoryResolver::initial_scan_state(new_factory, Some(&persisted), true, 0);
        assert_eq!(resumed.scan_floor, 12_344);
        assert_eq!(
            resumed.fallback_eligible_from, None,
            "a rotation always needs the next resolve() call to stamp the grace threshold in"
        );
        // Simulates that stamp having already happened and the window having closed — this test is
        // about the floor condition, not the grace one (see the `_waits_out_` test for that).
        assert_eq!(
            genesis_fallback_target(false, resumed.scan_floor, 0, false, 12_344, 0),
            GenesisFallback::Rewind(0),
            "resumed above genesis: an empty result must rewind"
        );

        let from_scratch =
            FactoryResolver::initial_scan_state(new_factory, Some(&persisted), false, 0);
        assert_eq!(from_scratch.scan_floor, 0);
        assert_eq!(
            genesis_fallback_target(false, from_scratch.scan_floor, 0, false, 0, 0),
            GenesisFallback::Conclusive,
            "already scanning from genesis: an empty result is final"
        );
    }

    /// Both rotation-detection sites — startup, when a persisted checkpoint is recorded against a
    /// different factory, and mid-process, when the resolved factory itself changes — reset through
    /// this one constructor, so a future edit to the reset invariant is guaranteed to cover both
    /// legs rather than only whichever call site happens to have a direct test.
    #[test]
    fn restarted_at_resets_for_a_fresh_rotation() {
        let factory = address!("0000000000000000000000000000000000000003");
        let scan = ScanState::restarted_at(factory, 12_344);
        assert_eq!(scan.factory, factory);
        assert_eq!(scan.scanned_to, 12_344);
        assert_eq!(scan.scan_floor, 12_344);
        assert_eq!(scan.current, None);
        assert!(!scan.genesis_fallback_done);
        assert_eq!(
            scan.fallback_eligible_from, None,
            "needs the next resolve() call's tip to set the grace threshold"
        );
    }
}
