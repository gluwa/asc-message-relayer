//! Signer balance monitoring.
//!
//! Every tx-sending role runs off a plain EOA that only needs gas — delivery on the destination
//! chain, ack and claim submission on the Creditcoin chain. When one runs dry, its sends start
//! failing with whatever wording that node gives an underfunded sender, which is indistinguishable
//! at a glance from an RPC problem; nothing anywhere pointed at the wallet. Industry relayers
//! (Hyperlane's `hyperlane_wallet_balance`, OpenZeppelin Defender's balance monitors) treat signer
//! balance as a headline metric for exactly this reason.
//!
//! This worker polls each configured signer's balance every [`POLL_INTERVAL`] and publishes
//! `relayer_signer_balance_ether{chain_key, role, address}`, so a dashboard threshold
//! (`< 0.1` say) warns while there is still time to top up rather than when deliveries are
//! already failing.

use std::time::Duration;

use alloy::primitives::{utils::format_ether, Address};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use anyhow::Result;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::config::ChainRoute;
use crate::prom::MetricsTrait;

/// How often each signer balance is read. Balances only move when we send (or someone tops up), so
/// this is deliberately lazy; it exists for trend lines and low-balance alerts, not per-tx
/// accounting.
pub const POLL_INTERVAL: Duration = Duration::from_secs(60);

/// One signer to watch: which chain to ask, and how to label the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BalanceTarget {
    pub chain_key: u64,
    /// Which job this signer funds: `delivery`, `ack` or `claim`. Part of the label set because the
    /// same key is often reused across roles and the operator question is "which *pipeline* is
    /// about to stall", not just "which address is low".
    pub role: &'static str,
    pub rpc_url: String,
    pub address: Address,
}

/// Derive the watch list from the routes: every configured signing key, on the chain it actually
/// spends gas on. Delivery signs on the route's destination chain; ack and claim both submit on
/// the Creditcoin (source) chain, `creditcoin_eth_rpc_url`. A key that fails to parse is skipped
/// with a warning rather than erroring — the worker that *uses* that key reports the real failure
/// with full context, and a broken balance watcher must never take precedence over it.
pub fn targets_from_routes(
    routes: &[ChainRoute],
    creditcoin_eth_rpc_url: &str,
) -> Vec<BalanceTarget> {
    let mut targets = Vec::new();
    let mut push =
        |chain_key: u64, role: &'static str, rpc_url: &str, key: &str| match key
            .trim()
            .parse::<PrivateKeySigner>(
        ) {
            Ok(signer) => targets.push(BalanceTarget {
                chain_key,
                role,
                rpc_url: rpc_url.to_owned(),
                address: signer.address(),
            }),
            Err(err) => {
                warn!(chain_key, role, %err, "signer_key does not parse; not watching its balance")
            }
        };

    for route in routes {
        if let Some(key) = &route.signer_key {
            push(route.chain_key, "delivery", &route.destination_rpc_url, key);
        }
        if let Some(ack) = &route.ack {
            push(
                route.chain_key,
                "ack",
                creditcoin_eth_rpc_url,
                &ack.signer_key,
            );
        }
        if let Some(claim) = &route.claim {
            push(
                route.chain_key,
                "claim",
                creditcoin_eth_rpc_url,
                &claim.signer_key,
            );
        }
    }
    targets
}

/// Poll each target's balance until `cancel` fires.
///
/// Providers are built lazily and dropped on a failed read, so the next tick re-dials rather than
/// retrying a dead socket forever. Health is heartbeated once per completed sweep — including a
/// sweep where every RPC read failed. That is deliberately weaker than the indexing workers'
/// success-only heartbeat: an unreachable RPC already starves *their* heartbeats and trips the
/// restart, and this auxiliary worker adding a second finger to that trigger would only make the
/// restart storm worse while the metric it maintains is a nice-to-have.
pub async fn run(
    targets: Vec<BalanceTarget>,
    metrics: Arc<dyn MetricsTrait>,
    health: Arc<crate::health::Health>,
    cancel: CancellationToken,
) -> Result<()> {
    const HEALTH_KEY: &str = "balance";

    // Register with /health only when there is actual work. Registering first and then parking
    // would leave a registered-but-silent component, and past PROGRESS_DEADLINE the liveness
    // probe would restart-loop a relayer that is idle by design (Bugbot, #54).
    if targets.is_empty() {
        debug!("no signing keys configured; balance watcher idle");
        cancel.cancelled().await;
        return Ok(());
    }
    health.heartbeat(HEALTH_KEY);

    let mut providers: Vec<Option<Box<dyn Provider>>> = targets.iter().map(|_| None).collect();
    loop {
        for (target, slot) in targets.iter().zip(providers.iter_mut()) {
            if slot.is_none() {
                match ProviderBuilder::new().connect(&target.rpc_url).await {
                    Ok(p) => *slot = Some(Box::new(p)),
                    Err(err) => {
                        warn!(chain_key = target.chain_key, role = target.role, %err,
                            "balance watcher cannot connect; will retry next tick");
                        continue;
                    }
                }
            }
            let provider = slot.as_ref().expect("filled above");
            match provider.get_balance(target.address).await {
                Ok(wei) => {
                    // f64 loses integer precision above 2^53 wei (~0.009 ETH) — irrelevant here,
                    // where the consumer is a low-balance threshold, not accounting.
                    let ether: f64 = format_ether(wei).parse().unwrap_or(f64::NAN);
                    metrics.set_signer_balance(
                        target.chain_key,
                        target.role,
                        target.address,
                        ether,
                    );
                }
                Err(err) => {
                    warn!(chain_key = target.chain_key, role = target.role,
                        address = %target.address, %err,
                        "balance read failed; rebuilding provider next tick");
                    *slot = None;
                }
            }
        }
        health.heartbeat(HEALTH_KEY);

        tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            () = tokio::time::sleep(POLL_INTERVAL) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AckConfig, AttestorSet};
    use alloy::primitives::address;

    // Anvil's default #0 key — appears in every e2e config, safe to use as a fixture.
    const KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const KEY_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    fn route(chain_key: u64) -> ChainRoute {
        ChainRoute {
            chain_key,
            creditcoin_chain_id: 1,
            destination_rpc_url: "http://dest:1".into(),
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

    /// The watch list must put each role on the chain it actually spends gas on: delivery on the
    /// route's destination RPC, ack on the Creditcoin RPC. Watching the right address on the wrong
    /// chain would report a healthy balance for a wallet that is empty where it matters.
    #[test]
    fn roles_are_watched_on_the_chain_they_spend_on() {
        let mut r = route(8);
        r.signer_key = Some(KEY.into());
        r.ack = Some(AckConfig {
            proof_gen_url: "http://pg:1".into(),
            validator_address: address!("0000000000000000000000000000000000000003"),
            signer_key: KEY.into(),
            confirmation_depth: 0,
            start_block: None,
            not_ready_poll_secs: crate::config::DEFAULT_ACK_NOT_READY_POLL_SECS,
            not_ready_poll_window_secs: crate::config::DEFAULT_ACK_NOT_READY_POLL_WINDOW_SECS,
        });

        let targets = targets_from_routes(&[r], "http://source:2");
        let expect_addr: Address = KEY_ADDR.parse().unwrap();
        assert_eq!(
            targets,
            vec![
                BalanceTarget {
                    chain_key: 8,
                    role: "delivery",
                    rpc_url: "http://dest:1".into(),
                    address: expect_addr,
                },
                BalanceTarget {
                    chain_key: 8,
                    role: "ack",
                    rpc_url: "http://source:2".into(),
                    address: expect_addr,
                },
            ]
        );
    }

    /// A watcher with nothing to watch must not register with /health: registered-then-parked
    /// means a permanently stale component, and the liveness probe would restart-loop a relayer
    /// that simply has no signing keys configured.
    #[tokio::test]
    async fn an_idle_watcher_never_registers_with_health() {
        let health = crate::health::Health::new(std::time::Duration::ZERO);
        let cancel = CancellationToken::new();
        cancel.cancel();
        run(
            Vec::new(),
            Arc::new(crate::prom::NoopMetrics),
            health.clone(),
            cancel,
        )
        .await
        .unwrap();
        // `Health::status` compares age with a strict `>`, so with the zero deadline a
        // registration made in this same millisecond would still read as alive and mask a
        // reintroduced register-then-park bug (Bugbot, #54). Let the clock tick first: after
        // any positive age, a registered component is stale and only a never-registered one
        // keeps /health green.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let (alive, stale) = health.status();
        assert!(alive, "idle balance watcher poisoned /health via {stale:?}");
    }

    /// An unparseable key is the used-by worker's error to raise with full context; the balance
    /// watcher just skips it. If this were an error the relayer would refuse to start over its
    /// least important worker.
    #[test]
    fn a_bad_key_is_skipped_not_fatal() {
        let mut r = route(8);
        r.signer_key = Some("not-a-key".into());
        assert!(targets_from_routes(&[r], "http://source:2").is_empty());
    }
}
