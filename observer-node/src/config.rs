//! Observer-node configuration (YAML, relayer conventions).

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Default cap on concurrent WS subscribers.
const DEFAULT_MAX_CLIENTS: usize = 256;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// USC chain keys whose message-vote + reobservation topics the observer subscribes to.
    pub chain_keys: Vec<u64>,
    pub p2p: P2pConfig,
    /// WebSocket + health/metrics bind host (e.g. "0.0.0.0").
    pub bind_host: String,
    /// WebSocket + health/metrics bind port.
    pub bind_port: u16,
    /// Allow WS clients to publish reobservation requests through this observer (the one write path —
    /// needed when a relayer fronts its gossip through the observer). Off by default: a public
    /// observer deployment should be read-only.
    #[serde(default)]
    pub allow_publish: bool,
    /// Maximum concurrent WS subscribers. Slow consumers are bounded by the shared event ring
    /// (a subscriber lagging past it is disconnected — fire-hose semantics), so there is no
    /// per-client buffer knob.
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct P2pConfig {
    /// libp2p listen port (TCP + QUIC).
    pub port: u16,
    /// Boot node multiaddrs (must include `/p2p/<peer-id>`), same as attestor/relayer bootnodes.
    #[serde(default)]
    pub boot_nodes: Vec<String>,
    /// Optional DNS name to advertise as an external address.
    #[serde(default)]
    pub public_addr: Option<String>,
    /// Optional stable identity: `0x`-prefixed 32-byte hex seed or a BIP39 mnemonic. Ephemeral
    /// key (fresh `PeerId` each restart) when unset — fine for a read-only observer.
    #[serde(default)]
    pub identity: Option<String>,
    /// Disable mDNS local discovery (recommended outside local dev clusters).
    #[serde(default)]
    pub no_mdns: bool,
}

fn default_max_clients() -> usize {
    DEFAULT_MAX_CLIENTS
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let config: Config = serde_yaml::from_str(&text).context("Invalid YAML config")?;
        anyhow::ensure!(
            !config.chain_keys.is_empty(),
            "config must list at least one chain_key to observe"
        );
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_yaml_with_defaults() {
        let yaml = r#"
chain_keys: [102]
bind_host: "0.0.0.0"
bind_port: 9190
p2p:
  port: 10333
  boot_nodes:
    - "/dns4/boot.example/tcp/30333/p2p/12D3KooWExample"
"#;
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.chain_keys, vec![102]);
        assert!(!cfg.allow_publish, "publish must default off");
        assert_eq!(cfg.max_clients, DEFAULT_MAX_CLIENTS);
        assert!(!cfg.p2p.no_mdns);
        assert!(cfg.p2p.identity.is_none());
    }

    #[test]
    fn rejects_unknown_fields() {
        let yaml = r#"
chain_keys: [102]
bind_host: "0.0.0.0"
bind_port: 9190
typo_field: true
p2p:
  port: 10333
"#;
        assert!(serde_yaml::from_str::<Config>(yaml).is_err());
    }
}
