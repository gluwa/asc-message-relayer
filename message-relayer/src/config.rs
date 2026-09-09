//! Runtime configuration for the message relayer.
//!
//! The shape mirrors `proof-gen-api-server/src/config.rs`: a [`ConfigFile`] that maps to YAML
//! verbatim and a [`Config`] that holds the validated, typed runtime values. CLI overrides are
//! applied in `bin/relayer.rs`.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use alloy::primitives::Address;
use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// Default vote cache TTL (seconds). Drops incomplete aggregates to bound RAM (PoC §9).
pub const DEFAULT_VOTE_CACHE_TTL_SECS: u64 = 30 * 60;
/// Default vote cache size cap (number of distinct messages tracked at once).
pub const DEFAULT_VOTE_CACHE_MAX_MESSAGES: usize = 10_000;
/// Default `simulate_before_send`; we always simulate in PoC to catch `validateVotes` reverts.
pub const DEFAULT_SIMULATE_BEFORE_SEND: bool = true;
/// Default delivery retry budget per message before giving up.
pub const DEFAULT_DELIVERY_MAX_RETRIES: u32 = 5;
/// Default gas multiplier (estimated gas * this) for `deliverMessage`.
pub const DEFAULT_GAS_MULTIPLIER: f64 = 1.2;
/// Default P2P TCP port.
pub const DEFAULT_P2P_PORT: u16 = 9100;
/// Default reorg lag (blocks) for source chain finality.
pub const DEFAULT_BLOCK_CONFIRMATION_DEPTH: u64 = 0;
/// Default blocks to rewind the persisted scan cursors on startup. Pool/ack state is memory-only,
/// so a message indexed-but-not-finished before a crash would otherwise be skipped forever (the
/// cursor is already past it and stray votes are dropped by the chain-first allowlist). Re-scanning
/// a recent window is idempotent: already-delivered messages resolve as "Already validated" at
/// simulate, already-acknowledged ones are skipped by the canAck pre-check.
pub const DEFAULT_SCAN_LOOKBACK_BLOCKS: u64 = 600;
/// Default cadence (seconds) at which the ack submitter re-asks proof-gen for a delivery proof it
/// answered "not ready" for (HTTP 422 `BlockNotReady`, or 404 while proof-gen's view of the
/// destination chain lags the tx). Flat, not growing: the proof appears on its own once the block
/// is attested, and the ack should land within one interval of that. See
/// [`crate::pending::NotReadyPolicy`].
pub const DEFAULT_ACK_NOT_READY_POLL_SECS: u64 = 20;
/// Default length (seconds) of the flat not-ready polling window per delivery, measured from when
/// the delivery was first seen. Past it the ack slides into the 30 s → 10 min slow backoff, so a
/// proof that never appears does not hot-loop until the 24 h give-up. Healthy destination
/// finality + attestation is minutes; 30 min is far outside it.
pub const DEFAULT_ACK_NOT_READY_POLL_WINDOW_SECS: u64 = 30 * 60;

// ---------------------------------------------------------------------------
// Validated runtime config
// ---------------------------------------------------------------------------

/// Validated runtime configuration assembled by [`Config::from_yaml_file`] or by the CLI
/// `--single-route` quickstart.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind_host: String,
    pub bind_port: u16,
    /// Creditcoin Substrate RPC. Reserved for future on-chain attestor-set resolution; not
    /// strictly required when all routes use a static `attestor_set`.
    pub cc3_rpc_url: String,
    /// Creditcoin EVM RPC. The relayer reads `MessagePublished` events from the configured
    /// Outboxes and `eth_chainId` from this endpoint.
    pub creditcoin_eth_rpc_url: String,
    pub p2p: P2pConfig,
    /// When set, the relayer sources votes from a spy node's WebSocket subscription instead of
    /// embedding its own libp2p swarm — and publishes reobservation requests through that spy
    /// (which must run `allow_publish: true`). The `p2p` section is ignored in this mode.
    pub spy: Option<crate::spy_client::SpyClientConfig>,
    pub vote_cache: VoteCacheConfig,
    pub delivery: DeliveryConfig,
    pub routes: Vec<ChainRoute>,
    /// Where to persist per-watcher block cursors so the relayer resumes from the last processed
    /// block after a restart (never silently skips on-chain events emitted while it was down).
    /// `None` disables persistence (watchers start from the chain head).
    pub checkpoint_path: Option<PathBuf>,
    /// Blocks to rewind persisted cursors on startup so in-flight work lost with the process
    /// (pool votes, pending acks) is re-discovered. See [`DEFAULT_SCAN_LOOKBACK_BLOCKS`];
    /// 0 disables the rewind.
    pub scan_lookback_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct ChainRoute {
    pub chain_key: u64,
    pub creditcoin_chain_id: u64,
    pub destination_rpc_url: String,
    pub inbox_address: Address,
    pub signer_key: Option<String>,
    /// Operator-pinned Outbox address, honored before the on-chain `OutboxDiscovery` registry
    /// lookup (`DiscoveryResolver::override_address`). The registry is the default and the only
    /// source of truth resolution otherwise trusts; set this only for a network where the
    /// chain-info precompile getter is missing or misconfigured, or to pin an Outbox during an
    /// incident. Logged loudly (`WARN`) at startup and on every resolve while set.
    pub outbox_address: Option<Address>,
    /// `RelayerContract(Lite)` on the *source* (Creditcoin) chain — the contract holding the
    /// per-message fee ledger (`getMessageInfo`) and `claimDelivery` since usc-contracts #23 moved
    /// both off the RelayerFeeVault (the vault holds tokens only now). When set, the delivery
    /// worker reads the funded `gasLimit` for each message and pins the destination
    /// `deliverMessage` tx to it, so the relayer can later claim its fee (`claimDelivery` requires
    /// the proven delivery tx's gasLimit to match a funded tier), and the ack worker additionally
    /// submits `claimDelivery` for each delivered message. `None` falls back to gas estimation
    /// (fee not claimable).
    pub relayer_contract_address: Option<Address>,
    /// Reorg guard in blocks. For the Creditcoin **Outbox scan** this is only the *fallback*
    /// boundary: the watcher scans up to the finalized head (Creditcoin has deterministic
    /// finality, and that is where the attestors sign) and uses `tip - depth` only when the
    /// `finalized` tag is unavailable or finality has stalled (`events::finality`). The Outbox
    /// factory scan and the destination-side workers still use it as a plain depth.
    pub block_confirmation_depth: u64,
    /// First block to scan on first run when no persisted checkpoint exists.
    pub start_block: Option<u64>,
    pub attestor_set: AttestorSet,
    pub threshold_override: Option<u32>,
    /// Opt-in trust-minimized acknowledgment. When set, the relayer watches the destination
    /// Inbox for `MessageDelivered`, fetches a native USC delivery proof from the proof-gen API,
    /// and submits it to the source-chain `AcknowledgmentValidator`. `None` disables ack for the
    /// route (the default).
    pub ack: Option<AckConfig>,
    /// Opt-in claim submission ("relayer on both sides"). When set, the relayer watches the
    /// destination (client) chain for the configured intent event (`Locked` on the bridge),
    /// fetches a native USC proof, and submits it to the Creditcoin-side claim target so the
    /// user never has to claim manually. `None` disables it for the route (the default).
    pub claim: Option<ClaimConfig>,
}

/// Off-chain acknowledgment submitter config (research §05/§10). See [`ChainRoute::ack`].
#[derive(Debug, Clone)]
pub struct AckConfig {
    /// Base URL of the proof-gen API server (e.g. `http://127.0.0.1:8080`). The submitter calls
    /// `GET {base}/api/v1/proof-by-tx/{chain_key}/{tx_hash}`.
    pub proof_gen_url: String,
    /// `AcknowledgmentValidator` contract on the Creditcoin (source) chain — the submit target.
    pub validator_address: Address,
    /// EVM key used to sign `submitAcknowledgment` txs on the Creditcoin chain. Submission is
    /// permissionless (the proof is self-validating), so this only needs gas, not authority.
    pub signer_key: String,
    /// Blocks to lag behind the destination chain tip when scanning for `MessageDelivered`, so the
    /// ack watcher does not act on the unsafe head (a destination reorg could otherwise enqueue an
    /// ack for a delivery that later disappears). 0 for instant-finality destinations.
    pub confirmation_depth: u64,
    /// First destination block to scan on first run when no persisted ack checkpoint exists.
    pub start_block: Option<u64>,
    /// Flat re-poll cadence while proof-gen answers "not ready" for a delivery proof. Non-zero.
    /// Default [`DEFAULT_ACK_NOT_READY_POLL_SECS`].
    pub not_ready_poll_secs: u64,
    /// How long (from first sighting of the delivery) to keep that flat cadence before sliding
    /// into the slow backoff. Default [`DEFAULT_ACK_NOT_READY_POLL_WINDOW_SECS`].
    pub not_ready_poll_window_secs: u64,
}

impl AckConfig {
    /// The not-ready retry schedule these settings describe.
    pub fn not_ready_policy(&self) -> crate::pending::NotReadyPolicy {
        crate::pending::NotReadyPolicy {
            poll_interval: std::time::Duration::from_secs(self.not_ready_poll_secs),
            poll_window: std::time::Duration::from_secs(self.not_ready_poll_window_secs),
        }
    }
}

/// Reject a zero not-ready poll cadence: it would re-ask proof-gen on every 6 s ack tick for
/// every pending delivery, for the whole window. Shared by the YAML and CLI paths.
pub fn validate_ack_not_ready_poll_secs(secs: u64, origin: &str) -> Result<()> {
    if secs == 0 {
        bail!("{origin}: ack not_ready_poll_secs must be > 0 (a zero cadence would hot-loop proof-gen)");
    }
    Ok(())
}

/// Claim submitter config ("relayer on both sides"). See [`ChainRoute::claim`].
#[derive(Debug, Clone)]
pub struct ClaimConfig {
    /// Base URL of the proof-gen API server (e.g. `http://127.0.0.1:3100`). The submitter calls
    /// `GET {base}/api/v1/proof-by-tx/{chain_key}/{tx_hash}`.
    pub proof_gen_url: String,
    /// Contract on the destination (client) chain whose intent events are watched — currently the
    /// bridge emitting `Locked(address indexed, uint256, uint256)`.
    pub source_bridge_address: Address,
    /// Proof consumer on Creditcoin the claim is submitted to — currently `CcBridge.claim(..)`;
    /// swaps to `IUSCBridgeInbound.bridgeFromIntent(..)` when the generic contract deploys.
    pub target_address: Address,
    /// EVM key used to sign claim txs on Creditcoin. Claims are permissionless (payouts go to the
    /// recipients proven in the logs), so this only needs gas, not authority.
    pub signer_key: String,
    /// Blocks to lag behind the client-chain tip when scanning for locks. Should approximate the
    /// chain's finality (e.g. 64 for Sepolia's EvmFinalized); proof-gen additionally gates on
    /// attestation, so a smaller value just means more BlockNotReady deferrals.
    pub confirmation_depth: u64,
    /// First client-chain block to scan on first run when no persisted claim checkpoint exists.
    pub start_block: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum AttestorSet {
    /// Static EVM-address allowlist supplied in config. Used for the PoC.
    Static(Vec<Address>),
    /// On-chain `IVoteValidator` introspection (stub until validator contract is finalized).
    OnChain { source: AttestorSource },
}

#[derive(Debug, Clone)]
pub enum AttestorSource {
    /// Validator contract on the destination chain.
    Evm { address: Address },
    /// Active attestor set on the Creditcoin runtime for `chain_key`.
    Cc3 { chain_key: u64 },
}

#[derive(Debug, Clone)]
pub struct P2pConfig {
    pub port: u16,
    pub public_addr: Option<String>,
    pub boot_nodes: Vec<String>,
    pub no_mdns: bool,
    pub identity: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VoteCacheConfig {
    pub ttl_seconds: u64,
    pub max_messages: usize,
}

#[derive(Debug, Clone)]
pub struct DeliveryConfig {
    pub simulate_before_send: bool,
    pub max_retries: u32,
    pub gas_multiplier: f64,
}

impl Config {
    /// Build a [`Config`] from a YAML file. The Creditcoin RPC URLs are supplied separately
    /// because they are commonly overridden from CLI/env (mirrors `proof-gen-api-server`).
    pub fn from_yaml_file(
        path: impl AsRef<Path>,
        cc3_rpc_url: String,
        creditcoin_eth_rpc_url: String,
        checkpoint_path: Option<PathBuf>,
    ) -> Result<Self> {
        let text = fs::read_to_string(path.as_ref()).with_context(|| {
            format!(
                "Failed to read message-relayer config file {}",
                path.as_ref().display()
            )
        })?;
        let file: ConfigFile = serde_yaml::from_str(&text).context("Invalid YAML config")?;
        file.into_config(cc3_rpc_url, creditcoin_eth_rpc_url, checkpoint_path)
    }

    /// Build a single-route [`Config`] from CLI flags (`--single-route`). Used for development.
    #[allow(clippy::too_many_arguments)]
    pub fn single_route(
        bind_host: String,
        bind_port: u16,
        cc3_rpc_url: String,
        creditcoin_eth_rpc_url: String,
        route: ChainRoute,
        p2p: P2pConfig,
        checkpoint_path: Option<PathBuf>,
    ) -> Self {
        Self {
            bind_host,
            bind_port,
            cc3_rpc_url,
            creditcoin_eth_rpc_url,
            p2p,
            spy: None,
            vote_cache: VoteCacheConfig::default(),
            delivery: DeliveryConfig::default(),
            routes: vec![route],
            checkpoint_path,
            scan_lookback_blocks: DEFAULT_SCAN_LOOKBACK_BLOCKS,
        }
    }

    /// Set of distinct `chain_key`s served by this process — used to filter CC3 events and to
    /// drive metrics labels.
    pub fn chain_keys(&self) -> HashSet<u64> {
        self.routes.iter().map(|r| r.chain_key).collect()
    }
}

impl Default for VoteCacheConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: DEFAULT_VOTE_CACHE_TTL_SECS,
            max_messages: DEFAULT_VOTE_CACHE_MAX_MESSAGES,
        }
    }
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            simulate_before_send: DEFAULT_SIMULATE_BEFORE_SEND,
            max_retries: DEFAULT_DELIVERY_MAX_RETRIES,
            gas_multiplier: DEFAULT_GAS_MULTIPLIER,
        }
    }
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_P2P_PORT,
            public_addr: None,
            boot_nodes: Vec::new(),
            no_mdns: false,
            identity: None,
        }
    }
}

// ---------------------------------------------------------------------------
// On-disk YAML shape
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ConfigFile {
    pub bind_host: String,
    pub bind_port: u16,
    #[serde(default)]
    pub p2p: P2pConfigFile,
    #[serde(default)]
    pub spy: Option<crate::spy_client::SpyClientConfig>,
    #[serde(default)]
    pub vote_cache: VoteCacheConfigFile,
    #[serde(default)]
    pub delivery: DeliveryConfigFile,
    #[serde(default = "default_scan_lookback_blocks")]
    pub scan_lookback_blocks: u64,
    pub routes: Vec<ChainRouteFile>,
}

#[derive(Debug, Default, Deserialize)]
pub struct P2pConfigFile {
    #[serde(default = "default_p2p_port")]
    pub port: u16,
    #[serde(default)]
    pub public_addr: Option<String>,
    #[serde(default)]
    pub boot_nodes: Vec<String>,
    #[serde(default)]
    pub no_mdns: bool,
    #[serde(default)]
    pub identity: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VoteCacheConfigFile {
    #[serde(default = "default_vote_cache_ttl_secs")]
    pub ttl_seconds: u64,
    #[serde(default = "default_vote_cache_max_messages")]
    pub max_messages: usize,
}

impl Default for VoteCacheConfigFile {
    fn default() -> Self {
        Self {
            ttl_seconds: DEFAULT_VOTE_CACHE_TTL_SECS,
            max_messages: DEFAULT_VOTE_CACHE_MAX_MESSAGES,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DeliveryConfigFile {
    #[serde(default = "default_simulate_before_send")]
    pub simulate_before_send: bool,
    #[serde(default = "default_delivery_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_gas_multiplier")]
    pub gas_multiplier: f64,
}

impl Default for DeliveryConfigFile {
    fn default() -> Self {
        Self {
            simulate_before_send: DEFAULT_SIMULATE_BEFORE_SEND,
            max_retries: DEFAULT_DELIVERY_MAX_RETRIES,
            gas_multiplier: DEFAULT_GAS_MULTIPLIER,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ChainRouteFile {
    pub chain_key: u64,
    pub creditcoin_chain_id: u64,
    pub destination_rpc_url: String,
    pub inbox_address: String,
    #[serde(default)]
    pub signer_key: Option<String>,
    /// See [`ChainRoute::outbox_address`].
    #[serde(default)]
    pub outbox_address: Option<String>,
    /// Accepts the pre-#23 key `relayer_fee_vault_address` as an alias so existing configs keep
    /// working; the ledger the relayer talks to is the RelayerContract now.
    #[serde(default, alias = "relayer_fee_vault_address")]
    pub relayer_contract_address: Option<String>,
    #[serde(default)]
    pub block_confirmation_depth: u64,
    #[serde(default)]
    pub start_block: Option<u64>,
    pub attestor_set: AttestorSetFile,
    #[serde(default)]
    pub threshold_override: Option<u32>,
    #[serde(default)]
    pub ack: Option<AckConfigFile>,
    #[serde(default)]
    pub claim: Option<ClaimConfigFile>,
}

#[derive(Debug, Deserialize)]
pub struct AckConfigFile {
    pub proof_gen_url: String,
    pub validator_address: String,
    pub signer_key: String,
    #[serde(default)]
    pub confirmation_depth: u64,
    #[serde(default)]
    pub start_block: Option<u64>,
    #[serde(default = "default_ack_not_ready_poll_secs")]
    pub not_ready_poll_secs: u64,
    #[serde(default = "default_ack_not_ready_poll_window_secs")]
    pub not_ready_poll_window_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct ClaimConfigFile {
    pub proof_gen_url: String,
    pub source_bridge_address: String,
    pub target_address: String,
    pub signer_key: String,
    #[serde(default)]
    pub confirmation_depth: u64,
    #[serde(default)]
    pub start_block: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum AttestorSetFile {
    Static { addresses: Vec<String> },
    EvmContract { address: String },
    Cc3ActiveSet { chain_key: u64 },
}

fn default_p2p_port() -> u16 {
    DEFAULT_P2P_PORT
}
fn default_vote_cache_ttl_secs() -> u64 {
    DEFAULT_VOTE_CACHE_TTL_SECS
}
fn default_vote_cache_max_messages() -> usize {
    DEFAULT_VOTE_CACHE_MAX_MESSAGES
}
fn default_simulate_before_send() -> bool {
    DEFAULT_SIMULATE_BEFORE_SEND
}
fn default_delivery_max_retries() -> u32 {
    DEFAULT_DELIVERY_MAX_RETRIES
}
fn default_gas_multiplier() -> f64 {
    DEFAULT_GAS_MULTIPLIER
}
fn default_scan_lookback_blocks() -> u64 {
    DEFAULT_SCAN_LOOKBACK_BLOCKS
}
fn default_ack_not_ready_poll_secs() -> u64 {
    DEFAULT_ACK_NOT_READY_POLL_SECS
}
fn default_ack_not_ready_poll_window_secs() -> u64 {
    DEFAULT_ACK_NOT_READY_POLL_WINDOW_SECS
}

impl ConfigFile {
    fn into_config(
        self,
        cc3_rpc_url: String,
        creditcoin_eth_rpc_url: String,
        checkpoint_path: Option<PathBuf>,
    ) -> Result<Config> {
        if self.routes.is_empty() {
            bail!("config must include at least one entry in `routes`");
        }
        let mut seen: HashSet<u64> = HashSet::new();
        let mut routes = Vec::with_capacity(self.routes.len());
        for r in self.routes {
            if !seen.insert(r.chain_key) {
                bail!("duplicate chain_key {} in config", r.chain_key);
            }
            routes.push(r.into_route()?);
        }

        Ok(Config {
            bind_host: self.bind_host,
            bind_port: self.bind_port,
            cc3_rpc_url,
            creditcoin_eth_rpc_url,
            p2p: P2pConfig {
                port: self.p2p.port,
                public_addr: self.p2p.public_addr,
                boot_nodes: self.p2p.boot_nodes,
                no_mdns: self.p2p.no_mdns,
                identity: self.p2p.identity,
            },
            spy: self.spy,
            vote_cache: VoteCacheConfig {
                ttl_seconds: self.vote_cache.ttl_seconds,
                max_messages: self.vote_cache.max_messages,
            },
            delivery: DeliveryConfig {
                simulate_before_send: self.delivery.simulate_before_send,
                max_retries: self.delivery.max_retries,
                gas_multiplier: self.delivery.gas_multiplier,
            },
            routes,
            checkpoint_path,
            scan_lookback_blocks: self.scan_lookback_blocks,
        })
    }
}

impl ChainRouteFile {
    fn into_route(self) -> Result<ChainRoute> {
        let inbox_address = parse_address(&self.inbox_address)
            .with_context(|| format!("invalid inbox_address for chain_key {}", self.chain_key))?;
        let outbox_address = self
            .outbox_address
            .as_deref()
            .map(parse_address)
            .transpose()
            .with_context(|| format!("invalid outbox_address for chain_key {}", self.chain_key))?;
        let relayer_contract_address = self
            .relayer_contract_address
            .as_deref()
            .map(parse_address)
            .transpose()
            .with_context(|| {
                format!(
                    "invalid relayer_contract_address for chain_key {}",
                    self.chain_key
                )
            })?;

        let attestor_set = match self.attestor_set {
            AttestorSetFile::Static { addresses } => {
                let mut parsed = Vec::with_capacity(addresses.len());
                for raw in addresses {
                    parsed.push(parse_address(&raw).with_context(|| {
                        format!(
                            "invalid attestor address `{raw}` for chain_key {}",
                            self.chain_key
                        )
                    })?);
                }
                if parsed.is_empty() {
                    bail!(
                        "attestor_set.static.addresses must be non-empty for chain_key {}",
                        self.chain_key
                    );
                }
                AttestorSet::Static(parsed)
            }
            AttestorSetFile::EvmContract { address } => {
                let address = parse_address(&address).with_context(|| {
                    format!(
                        "invalid attestor_set.evm_contract.address for chain_key {}",
                        self.chain_key
                    )
                })?;
                AttestorSet::OnChain {
                    source: AttestorSource::Evm { address },
                }
            }
            AttestorSetFile::Cc3ActiveSet { chain_key } => AttestorSet::OnChain {
                source: AttestorSource::Cc3 { chain_key },
            },
        };

        let ack = self
            .ack
            .map(|a| {
                let validator_address = parse_address(&a.validator_address).with_context(|| {
                    format!(
                        "invalid ack.validator_address for chain_key {}",
                        self.chain_key
                    )
                })?;
                validate_ack_not_ready_poll_secs(
                    a.not_ready_poll_secs,
                    &format!("chain_key {}", self.chain_key),
                )?;
                anyhow::Ok(AckConfig {
                    proof_gen_url: a.proof_gen_url,
                    validator_address,
                    signer_key: a.signer_key,
                    confirmation_depth: a.confirmation_depth,
                    start_block: a.start_block,
                    not_ready_poll_secs: a.not_ready_poll_secs,
                    not_ready_poll_window_secs: a.not_ready_poll_window_secs,
                })
            })
            .transpose()?;

        let claim = self
            .claim
            .map(|c| {
                let source_bridge_address =
                    parse_address(&c.source_bridge_address).with_context(|| {
                        format!(
                            "invalid claim.source_bridge_address for chain_key {}",
                            self.chain_key
                        )
                    })?;
                let target_address = parse_address(&c.target_address).with_context(|| {
                    format!(
                        "invalid claim.target_address for chain_key {}",
                        self.chain_key
                    )
                })?;
                anyhow::Ok(ClaimConfig {
                    proof_gen_url: c.proof_gen_url,
                    source_bridge_address,
                    target_address,
                    signer_key: c.signer_key,
                    confirmation_depth: c.confirmation_depth,
                    start_block: c.start_block,
                })
            })
            .transpose()?;

        Ok(ChainRoute {
            chain_key: self.chain_key,
            creditcoin_chain_id: self.creditcoin_chain_id,
            destination_rpc_url: self.destination_rpc_url,
            inbox_address,
            signer_key: self.signer_key,
            outbox_address,
            relayer_contract_address,
            block_confirmation_depth: self.block_confirmation_depth,
            start_block: self.start_block,
            attestor_set,
            threshold_override: self.threshold_override,
            ack,
            claim,
        })
    }
}

fn parse_address(raw: &str) -> Result<Address> {
    Address::from_str(raw.trim()).with_context(|| format!("not a valid 0x-hex EVM address: {raw}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_yaml() -> &'static str {
        r#"
bind_host: "0.0.0.0"
bind_port: 3200

p2p:
  port: 9100
  no_mdns: true

vote_cache:
  ttl_seconds: 1800
  max_messages: 1000

delivery:
  simulate_before_send: true
  max_retries: 3
  gas_multiplier: 1.5

routes:
  - chain_key: 2
    creditcoin_chain_id: 102031
    destination_rpc_url: "http://localhost:8545"
    inbox_address: "0x0000000000000000000000000000000000000002"
    block_confirmation_depth: 12
    attestor_set:
      kind: static
      addresses:
        - "0x000000000000000000000000000000000000000a"
        - "0x000000000000000000000000000000000000000b"
    ack:
      proof_gen_url: "http://localhost:3100"
      validator_address: "0x0000000000000000000000000000000000000005"
      signer_key: "0x0000000000000000000000000000000000000000000000000000000000000001"
    claim:
      proof_gen_url: "http://localhost:3100"
      source_bridge_address: "0x0000000000000000000000000000000000000003"
      target_address: "0x0000000000000000000000000000000000000004"
      signer_key: "0x0000000000000000000000000000000000000000000000000000000000000001"
      confirmation_depth: 64
"#
    }

    #[test]
    fn yaml_round_trip_validates() {
        let file: ConfigFile = serde_yaml::from_str(sample_yaml()).unwrap();
        let cfg = file
            .into_config("ws://cc3:9944".into(), "http://cc3-eth:9933".into(), None)
            .unwrap();
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.routes[0].chain_key, 2);
        assert_eq!(cfg.cc3_rpc_url, "ws://cc3:9944");
        assert!(matches!(cfg.routes[0].attestor_set, AttestorSet::Static(_)));
        let claim = cfg.routes[0].claim.as_ref().expect("claim block parsed");
        assert_eq!(claim.confirmation_depth, 64);
        assert_eq!(
            claim.source_bridge_address,
            "0x0000000000000000000000000000000000000003"
                .parse::<Address>()
                .unwrap()
        );
        // The not-ready polling knobs are optional and default to the flat 20 s / 30 min schedule.
        let ack = cfg.routes[0].ack.as_ref().expect("ack block parsed");
        assert_eq!(ack.not_ready_poll_secs, DEFAULT_ACK_NOT_READY_POLL_SECS);
        assert_eq!(
            ack.not_ready_poll_window_secs,
            DEFAULT_ACK_NOT_READY_POLL_WINDOW_SECS
        );
        let policy = ack.not_ready_policy();
        assert_eq!(policy.poll_interval, std::time::Duration::from_secs(20));
        assert_eq!(policy.poll_window, std::time::Duration::from_secs(30 * 60));
    }

    #[test]
    fn ack_not_ready_polling_is_configurable_and_rejects_zero_cadence() {
        let tuned = sample_yaml().replace(
            "validator_address: \"0x0000000000000000000000000000000000000005\"\n",
            "validator_address: \"0x0000000000000000000000000000000000000005\"\n      \
             not_ready_poll_secs: 30\n      not_ready_poll_window_secs: 600\n",
        );
        let file: ConfigFile = serde_yaml::from_str(&tuned).unwrap();
        let cfg = file
            .into_config("ws://cc3:9944".into(), "http://cc3-eth:9933".into(), None)
            .unwrap();
        let ack = cfg.routes[0].ack.as_ref().unwrap();
        assert_eq!(ack.not_ready_poll_secs, 30);
        assert_eq!(ack.not_ready_poll_window_secs, 600);

        // A zero cadence would re-ask proof-gen every ack tick for the whole window.
        let zero = sample_yaml().replace(
            "validator_address: \"0x0000000000000000000000000000000000000005\"\n",
            "validator_address: \"0x0000000000000000000000000000000000000005\"\n      \
             not_ready_poll_secs: 0\n",
        );
        let file: ConfigFile = serde_yaml::from_str(&zero).unwrap();
        let err = file
            .into_config("ws://cc3:9944".into(), "http://cc3-eth:9933".into(), None)
            .expect_err("zero cadence must be rejected");
        assert!(err.to_string().contains("not_ready_poll_secs"), "{err}");
    }

    #[test]
    fn duplicate_chain_keys_rejected() {
        let yaml = r#"
bind_host: "0.0.0.0"
bind_port: 3200
routes:
  - chain_key: 2
    creditcoin_chain_id: 1
    destination_rpc_url: "http://x"
    inbox_address: "0x0000000000000000000000000000000000000002"
    attestor_set:
      kind: static
      addresses: ["0x000000000000000000000000000000000000000a"]
  - chain_key: 2
    creditcoin_chain_id: 1
    destination_rpc_url: "http://y"
    inbox_address: "0x0000000000000000000000000000000000000003"
    attestor_set:
      kind: static
      addresses: ["0x000000000000000000000000000000000000000a"]
"#;
        let file: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        let err = file
            .into_config("ws://cc3".into(), "http://cc3-eth".into(), None)
            .unwrap_err();
        assert!(err.to_string().contains("duplicate chain_key"));
    }

    #[test]
    fn empty_routes_rejected() {
        let yaml = "bind_host: 0.0.0.0\nbind_port: 3200\nroutes: []\n";
        let file: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        let err = file
            .into_config("ws://cc3".into(), "http://cc3-eth".into(), None)
            .unwrap_err();
        assert!(err.to_string().contains("at least one entry"));
    }

    #[test]
    fn empty_static_attestor_set_rejected() {
        let yaml = r#"
bind_host: "0.0.0.0"
bind_port: 3200
routes:
  - chain_key: 2
    creditcoin_chain_id: 1
    destination_rpc_url: "http://x"
    inbox_address: "0x0000000000000000000000000000000000000002"
    attestor_set:
      kind: static
      addresses: []
"#;
        let file: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        let err = file
            .into_config("ws://cc3".into(), "http://cc3-eth".into(), None)
            .unwrap_err();
        assert!(err.to_string().contains("must be non-empty"));
    }

    #[test]
    fn invalid_address_rejected() {
        let yaml = r#"
bind_host: "0.0.0.0"
bind_port: 3200
routes:
  - chain_key: 2
    creditcoin_chain_id: 1
    destination_rpc_url: "http://x"
    inbox_address: "not-an-address"
    attestor_set:
      kind: static
      addresses: ["0x000000000000000000000000000000000000000a"]
"#;
        let file: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        let err = file
            .into_config("ws://cc3".into(), "http://cc3-eth".into(), None)
            .unwrap_err();
        assert!(err.to_string().contains("invalid inbox_address"));
    }
}

/// Upper bound on poll-interval overrides. A poll that fires less often than the health
/// watchdog's [`crate::health::PROGRESS_DEADLINE`] (5 min) can never heartbeat in time, so an
/// oversized override would put the whole process in a liveness-restart loop (bugbot). 120s keeps
/// a wide margin for the iteration's own runtime.
const POLL_OVERRIDE_MAX_SECS: u64 = 120;

/// Environment override for a poll interval, in whole seconds. Returns `default_secs` when the
/// variable is unset, empty, or unparseable (never fails startup on a typo — the default is
/// always safe). Zero is rejected (busy spin) and values above [`POLL_OVERRIDE_MAX_SECS`] are
/// clamped (liveness-restart loop — see the constant).
///
/// Used by the claim/ack discovery loops so shared, RPS-capped deployments (usc-dev on one
/// Chainstack key, 2026-08-07) can trade discovery latency for collision rate without a rebuild:
/// the 6s default is tuned for CI/e2e snappiness, while a fleet-sharing deployment wants 30s+.
pub fn poll_secs_override(var: &str, default_secs: u64) -> u64 {
    match std::env::var(var) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => {
                let clamped = secs.min(POLL_OVERRIDE_MAX_SECS);
                if clamped != secs {
                    tracing::warn!(
                        var,
                        secs,
                        clamped,
                        "poll-interval override exceeds the health-deadline-safe maximum — clamping"
                    );
                } else if clamped != default_secs {
                    tracing::info!(var, secs, default_secs, "⏱️ poll interval overridden");
                }
                clamped
            }
            _ => {
                tracing::warn!(
                    var,
                    raw,
                    default_secs,
                    "invalid poll-interval override — using default"
                );
                default_secs
            }
        },
        Err(_) => default_secs,
    }
}

#[cfg(test)]
mod poll_override_tests {
    #[test]
    fn parses_overrides_and_falls_back_safely() {
        // Unique var names per case — tests share a process environment.
        std::env::set_var("TEST_POLL_A", "30");
        assert_eq!(super::poll_secs_override("TEST_POLL_A", 6), 30);
        // An oversized override must clamp below the health watchdog's deadline, or the
        // process liveness-restarts forever (bugbot).
        std::env::set_var("TEST_POLL_D", "86400");
        assert_eq!(
            super::poll_secs_override("TEST_POLL_D", 6),
            super::POLL_OVERRIDE_MAX_SECS,
            "clamped to the deadline-safe maximum"
        );
        std::env::set_var("TEST_POLL_B", "0");
        assert_eq!(
            super::poll_secs_override("TEST_POLL_B", 6),
            6,
            "zero rejected"
        );
        std::env::set_var("TEST_POLL_C", "fast");
        assert_eq!(
            super::poll_secs_override("TEST_POLL_C", 6),
            6,
            "garbage rejected"
        );
        assert_eq!(super::poll_secs_override("TEST_POLL_UNSET", 6), 6);
    }
}
