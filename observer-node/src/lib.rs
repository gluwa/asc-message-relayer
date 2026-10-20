//! USC write-ability **observer node** — a passive p2p observer, in the spirit of Wormhole's Spy.
//!
//! Joins the attestor/relayer gossipsub mesh as just another peer (same topics, same bootnode
//! discovery), performs **no validation duties, no voting, no delivery**, and fans out every
//! observed message-attestation event over a WebSocket subscription API as JSON — so indexers,
//! explorers, monitors (and eventually the relayer itself) in any language can watch the p2p
//! process of message voting without reimplementing libp2p + SCALE + ECDSA.
//!
//! Spec: `usc-write-ability-research/documents/confluence-observer-node-spec.md`.
//!
//! Two tasks under one supervisor, mirroring the relayer's runtime shape:
//!  * [`swarm::run`] — the libp2p observer (reusing the relayer's behavior + the shared
//!    `write-ability` envelopes), publishing [`events::ObserverEvent`]s into the [`hub::Hub`].
//!  * an axum server — `/ws` subscriptions (per-connection filters), `/health` (progress-aware),
//!    `/metrics`.
//!
//! Shutdown is one [`CancellationToken`] fanned out to both; any task exiting tears down the
//! process (fail-fast — orchestration restarts an observer whose swarm died).

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

pub mod config;
pub mod events;
pub mod hub;
pub mod metrics;
pub mod swarm;
pub mod ws;

pub use config::Config;

/// Capacity of the WS→swarm reobservation-publish queue. Requests are rare (one per stalled
/// message per client cadence); a small buffer absorbs bursts.
const PUBLISH_CHANNEL_CAP: usize = 64;

pub struct Server {
    config: Config,
}

impl Server {
    #[must_use]
    pub fn new(config: Config) -> Self {
        info!(
            chain_keys = ?config.chain_keys,
            allow_publish = config.allow_publish,
            "🕵️ Configured observer node"
        );
        Self { config }
    }

    pub async fn run(self) -> Result<()> {
        let cancel = CancellationToken::new();
        let hub = hub::Hub::new();
        let metrics = metrics::ObserverMetrics::new();
        // Progress-aware liveness: the swarm loop pulses; a wedged swarm flips /health to 503 so
        // orchestration restarts the observer (same pattern as the relayer).
        let health =
            message_relayer::health::Health::new(message_relayer::health::PROGRESS_DEADLINE);

        let (publish_tx, publish_rx) = mpsc::channel::<swarm::PublishRequest>(PUBLISH_CHANNEL_CAP);

        let mut tasks = JoinSet::new();

        // Swarm observer.
        {
            let hub = hub.clone();
            let metrics = metrics.clone();
            let health = health.clone();
            let cancel = cancel.clone();
            let p2p = self.config.p2p.clone();
            let chain_keys = self.config.chain_keys.clone();
            spawn_worker(
                &mut tasks,
                "observer swarm",
                swarm::run(p2p, chain_keys, hub, publish_rx, metrics, health, cancel),
            );
        }

        // HTTP: /ws + /health + /metrics.
        let ip: IpAddr = self.config.bind_host.parse().with_context(|| {
            format!(
                "Invalid bind host: '{}'. Expected IP address (e.g. '0.0.0.0', '::1')",
                self.config.bind_host
            )
        })?;
        let bind_addr = SocketAddr::new(ip, self.config.bind_port);
        let state = ws::WsState {
            hub,
            metrics,
            health,
            publish_tx: self.config.allow_publish.then_some(publish_tx),
            chain_keys: self.config.chain_keys,
            max_clients: self.config.max_clients,
        };
        let app = ws::build_router(state);
        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind HTTP listener at {bind_addr}"))?;
        info!("🌐 WS + health + metrics listening on {bind_addr}");
        let axum_cancel = cancel.clone();
        spawn_worker(&mut tasks, "HTTP server", async move {
            let shutdown = async move { axum_cancel.cancelled().await };
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await?;
            Ok(())
        });

        info!("✅ observer node online");

        tokio::select! {
            () = message_relayer::shutdown_signal() => {
                info!("🛑 Global shutdown requested");
            }
            _ = tasks.join_next() => {
                warn!("a worker exited; tearing down the rest");
            }
        }
        cancel.cancel();
        while tasks.join_next().await.is_some() {}
        info!("🛑 observer node drained, exiting");
        Ok(())
    }
}

/// Spawn a fallible worker, tagging failures with `label` (mirrors the relayer's supervisor).
fn spawn_worker(
    tasks: &mut JoinSet<()>,
    label: &'static str,
    fut: impl std::future::Future<Output = Result<()>> + Send + 'static,
) {
    tasks.spawn(async move {
        if let Err(err) = fut.await {
            error!(worker = label, %err, "worker exited with error");
        }
    });
}
