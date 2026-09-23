//! Prometheus metrics for the message relayer.
//!
//! Layout follows `proof-gen-api-server/src/prom/mod.rs`: a [`MetricsTrait`] that the runtime
//! talks to, a [`RelayerMetrics`] struct that owns the registry, and a [`NoopMetrics`]
//! implementation for tests. The metric set covers the signals the PoC PDF §10 calls out.

use std::fmt::Debug;
use std::sync::atomic::{AtomicI64, AtomicU64};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::Address;
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::metrics::info::Info;
use prometheus_client::registry::Registry;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

/// Trait for the metrics surface the runtime depends on. Allows swapping in a no-op for tests.
pub trait MetricsTrait: Send + Sync + Debug {
    fn inc_messages_indexed(&self, chain_key: u64);
    fn inc_vote(&self, chain_key: u64, outcome: VoteOutcome);
    fn observe_votes_per_message(&self, count: u64);
    fn inc_deliver_tx(&self, chain_key: u64, status: DeliveryStatus);
    fn observe_time_to_threshold(&self, duration: Duration);
    fn observe_time_to_deliver(&self, duration: Duration);
    fn set_p2p_peer_count(&self, chain_key: u64, count: i64);
    fn set_pool_messages_pending(&self, count: i64);
    /// Current size of the active attestor allowlist the pool is enforcing for `chain_key`.
    fn set_attestor_set_size(&self, chain_key: u64, size: i64);
    /// A hot-reload of the on-chain attestor set was applied for `chain_key` (set and/or threshold
    /// changed). Watch this for unexpected churn.
    fn inc_attestor_set_reload(&self, chain_key: u64);
    /// One `submitAcknowledgment` settlement attempt resolved, on the source-chain
    /// `AcknowledgmentValidator` (see `crate::ack`). Separate from delivery so a dead settlement
    /// path (proof-gen down, signer unfunded) is visible even while messages keep delivering
    /// normally — see the `relayer_claim_*`/`relayer_ack_*` gap write-up this closes.
    fn inc_ack_submission(&self, chain_key: u64, outcome: SettlementOutcome);
    /// One proof-gen `proof-by-tx` fetch by the ack submitter, by outcome. Splits the two reasons
    /// an ack can be waiting: `NotReady` (proof-gen says "not yet" — 422 `BlockNotReady`, or 404
    /// while its chain view lags; polled flat, expected to clear on its own) versus `Error` (5xx,
    /// connection failure, undecodable proof; backed off exponentially, operator-relevant). Before
    /// this split both showed up only as `relayer_ack_submissions{outcome="Failed"}` and a
    /// four-minute pure-backoff stall after a 404 was indistinguishable from an outage.
    fn inc_ack_proof_fetch(&self, chain_key: u64, outcome: ProofFetchOutcome);
    /// One `claimDelivery` relay-fee-claim attempt resolved, on the source-chain `RelayerContract`
    /// (see `crate::ack`'s `AckAndClaim` mode). Independent of `inc_ack_submission` since
    /// usc-contracts #23 decoupled the two settlements.
    fn inc_claim_submission(&self, chain_key: u64, outcome: SettlementOutcome);
    /// Depth of the settlement queue for `chain_key` — delivered txs discovered but not yet
    /// settled. Published every ack tick, so unlike the per-outcome counters it is present whether
    /// or not any settlement work exists, which is what makes it usable as a liveness signal.
    ///
    /// A queue that *never returns to zero* is the silent-outage shape: a tx whose proof fetch
    /// keeps failing is re-deferred rather than resolved, so it stays here indefinitely while the
    /// outcome counters may barely move. Alert on `min_over_time(...) > 0` over a couple of hours,
    /// and on `absent()` for the worker never having ticked at all.
    fn set_settlement_queue_depth(&self, chain_key: u64, depth: i64);
    /// Native-token balance (in ether units) of the signer funding `role` on `chain_key`. Polled
    /// by `crate::balance`; the low-balance dashboard threshold hangs off this.
    fn set_signer_balance(&self, chain_key: u64, role: &'static str, address: Address, ether: f64);
    /// A watcher's checkpoint write (`CheckpointStore::set`/`set_with_outbox`) failed for
    /// `chain_key` (disk full, permissions, …). The checkpoint is what makes a restart resume
    /// instead of re-scanning from the chain head or losing the cursor holdback on an in-flight
    /// message, so a write failure degrading silently into "only visible in logs" would hide a
    /// real durability regression. A rising count with no matching recovery is worth paging on.
    fn inc_checkpoint_write_failure(&self, chain_key: u64);
    /// A message's delivery-attempt count crossed `DELIVERY_MAX_DISPATCH_ATTEMPTS` and is still
    /// being retried (uncapped by design — see `crate::pool`). Previously only a `warn!` log line;
    /// a message stuck here for a persistently misbehaving destination (bad gas limit, dead
    /// signer) is now dashboard-visible instead of log-grep-only.
    fn inc_delivery_retries_exceeded(&self, chain_key: u64);
}

/// Shared trait object — used to plumb metrics through services without leaking the concrete type.
pub type Metrics = Arc<dyn MetricsTrait>;

/// No-op metrics for testing or when metrics are disabled.
#[derive(Debug, Default)]
pub struct NoopMetrics;

impl NoopMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl MetricsTrait for NoopMetrics {
    fn inc_messages_indexed(&self, _chain_key: u64) {}
    fn inc_vote(&self, _chain_key: u64, _outcome: VoteOutcome) {}
    fn observe_votes_per_message(&self, _count: u64) {}
    fn inc_deliver_tx(&self, _chain_key: u64, _status: DeliveryStatus) {}
    fn observe_time_to_threshold(&self, _duration: Duration) {}
    fn observe_time_to_deliver(&self, _duration: Duration) {}
    fn set_p2p_peer_count(&self, _chain_key: u64, _count: i64) {}
    fn set_pool_messages_pending(&self, _count: i64) {}
    fn set_attestor_set_size(&self, _chain_key: u64, _size: i64) {}
    fn inc_attestor_set_reload(&self, _chain_key: u64) {}
    fn inc_ack_submission(&self, _chain_key: u64, _outcome: SettlementOutcome) {}
    fn inc_ack_proof_fetch(&self, _chain_key: u64, _outcome: ProofFetchOutcome) {}
    fn inc_claim_submission(&self, _chain_key: u64, _outcome: SettlementOutcome) {}
    fn set_settlement_queue_depth(&self, _chain_key: u64, _depth: i64) {}
    fn set_signer_balance(
        &self,
        _chain_key: u64,
        _role: &'static str,
        _address: Address,
        _ether: f64,
    ) {
    }
    fn inc_checkpoint_write_failure(&self, _chain_key: u64) {}
    fn inc_delivery_retries_exceeded(&self, _chain_key: u64) {}
}

/// Concrete metrics container.
#[derive(Debug)]
pub struct RelayerMetrics {
    registry: Registry,
    messages_indexed: Family<LabelChain, Counter<u64, AtomicU64>>,
    votes: Family<LabelVote, Counter<u64, AtomicU64>>,
    votes_per_message: Histogram,
    deliver_tx: Family<LabelDelivery, Counter<u64, AtomicU64>>,
    time_to_threshold_seconds: Histogram,
    time_to_deliver_seconds: Histogram,
    p2p_peer_count: Family<LabelChain, Gauge<i64, AtomicI64>>,
    pool_messages_pending: Gauge<i64, AtomicI64>,
    attestor_set_size: Family<LabelChain, Gauge<i64, AtomicI64>>,
    attestor_set_reloads: Family<LabelChain, Counter<u64, AtomicU64>>,
    ack_submissions: Family<LabelSettlement, Counter<u64, AtomicU64>>,
    ack_proof_fetches: Family<LabelProofFetch, Counter<u64, AtomicU64>>,
    claim_submissions: Family<LabelSettlement, Counter<u64, AtomicU64>>,
    settlement_queue_depth: Family<LabelChain, Gauge<i64, AtomicI64>>,
    signer_balance: Family<LabelSigner, Gauge<f64, AtomicU64>>,
    cpu_usage_percent: Gauge<f64, AtomicU64>,
    memory_usage_bytes: Gauge<f64, AtomicU64>,
    thread_count: Gauge<i64, AtomicI64>,
    #[allow(dead_code)]
    start_time_seconds: Gauge<f64, AtomicU64>,
    worker_last_success: Family<LabelWorker, Gauge<f64, AtomicU64>>,
    worker_degraded: Family<LabelWorker, Gauge<i64, AtomicI64>>,
    checkpoint_write_failures: Family<LabelChain, Counter<u64, AtomicU64>>,
    delivery_retries_exceeded: Family<LabelChain, Counter<u64, AtomicU64>>,
    outcome_store_size: Gauge<i64, AtomicI64>,
    outcome_store_evictions: Gauge<i64, AtomicI64>,
}

impl RelayerMetrics {
    pub fn new(chain_keys: &[u64]) -> Self {
        let mut registry = Registry::default();

        let messages_indexed = Family::default();
        registry.register(
            "relayer_messages_indexed",
            "Finalized MessagePublished events seen",
            messages_indexed.clone(),
        );

        let votes = Family::default();
        registry.register(
            "relayer_votes_received",
            "Attestor votes received over the P2P mesh, by outcome",
            votes.clone(),
        );

        let votes_per_message = Histogram::new(exponential_buckets(1.0, 2.0, 10));
        registry.register(
            "relayer_votes_per_message",
            "Distinct signers per message at the moment of delivery",
            votes_per_message.clone(),
        );

        let deliver_tx = Family::default();
        registry.register(
            "relayer_deliver_tx",
            "Inbox.deliverMessage transaction outcomes",
            deliver_tx.clone(),
        );

        let time_to_threshold_seconds = Histogram::new(exponential_buckets(0.1, 2.0, 14));
        registry.register(
            "relayer_time_to_threshold_seconds",
            "Time from MessagePublished to threshold reached",
            time_to_threshold_seconds.clone(),
        );

        let time_to_deliver_seconds = Histogram::new(exponential_buckets(0.1, 2.0, 14));
        registry.register(
            "relayer_time_to_deliver_seconds",
            "Time from threshold reached to delivery confirmed",
            time_to_deliver_seconds.clone(),
        );

        let p2p_peer_count = Family::default();
        registry.register(
            "relayer_p2p_peer_count",
            "Number of peers in the gossipsub mesh per chain_key",
            p2p_peer_count.clone(),
        );

        let pool_messages_pending = Gauge::default();
        registry.register(
            "relayer_pool_messages_pending",
            "Messages currently held in the vote pool awaiting threshold",
            pool_messages_pending.clone(),
        );

        let attestor_set_size = Family::default();
        registry.register(
            "relayer_attestor_set_size",
            "Size of the active attestor allowlist enforced by the pool per chain_key",
            attestor_set_size.clone(),
        );

        let attestor_set_reloads = Family::default();
        registry.register(
            "relayer_attestor_set_reloads",
            "Count of on-chain attestor-set hot-reloads applied per chain_key",
            attestor_set_reloads.clone(),
        );

        let ack_submissions = Family::default();
        registry.register(
            "relayer_ack_submissions",
            "submitAcknowledgment settlement attempts on the AcknowledgmentValidator, by outcome",
            ack_submissions.clone(),
        );

        let ack_proof_fetches = Family::default();
        registry.register(
            "relayer_ack_proof_fetches",
            "proof-gen proof-by-tx fetches by the ack submitter, by outcome: Ready, NotReady \
             (proof-gen 422/404 — destination block not attested yet or proof-gen's chain view \
             lagging; polled flat and expected to clear on its own) or Error (5xx, connection, \
             undecodable proof; exponential backoff, operator-relevant)",
            ack_proof_fetches.clone(),
        );

        let claim_submissions = Family::default();
        registry.register(
            "relayer_claim_submissions",
            "claimDelivery relay-fee-claim attempts on the RelayerContract, by outcome",
            claim_submissions.clone(),
        );

        let settlement_queue_depth = Family::default();
        registry.register(
            "relayer_settlement_queue_depth",
            "Delivered txs discovered but not yet settled, per chain_key — published every ack \
             tick so it is present even when there is no settlement work",
            settlement_queue_depth.clone(),
        );

        let signer_balance = Family::default();
        registry.register(
            "relayer_signer_balance_ether",
            "Native-token balance, in ether units, of each signing wallet on the chain it spends \
             gas on (delivery: the route's destination chain; ack/claim: the Creditcoin chain). \
             Alert on a low threshold — an empty wallet fails sends with wording that reads like \
             an RPC problem",
            signer_balance.clone(),
        );

        let cpu_usage_percent = Gauge::default();
        registry.register(
            "relayer_cpu_usage_percent",
            "Process CPU usage percentage",
            cpu_usage_percent.clone(),
        );

        let memory_usage_bytes = Gauge::default();
        registry.register(
            "relayer_memory_usage_bytes",
            "Process memory usage in bytes",
            memory_usage_bytes.clone(),
        );

        let thread_count = Gauge::default();
        registry.register(
            "relayer_thread_count",
            "Number of active threads",
            thread_count.clone(),
        );

        let start_time_seconds = Gauge::default();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before Unix epoch")
            .as_secs_f64();
        start_time_seconds.set(now);
        registry.register(
            "relayer_start_time_seconds",
            "Process start time as Unix timestamp (use time() - this for uptime)",
            start_time_seconds.clone(),
        );

        let worker_last_success = Family::default();
        registry.register(
            "relayer_worker_last_success_timestamp_seconds",
            "Unix time of each worker's last successful poll iteration, from the same registry \
             that backs /health. Workers heartbeat only on a successful iteration, so \
             `time() - this` is how long the worker has made no forward progress — the signal \
             that separates a healthy-but-idle relayer from a wedged one. Synced at scrape time.",
            worker_last_success.clone(),
        );

        let worker_degraded = Family::default();
        registry.register(
            "relayer_worker_degraded",
            "1 while the worker has made no successful poll within the health deadline but is \
             still ticking and erroring (upstream outage, rate limit) — alive, retrying and \
             rebuilding its provider, so /health stays 200 and no restart happens; 0 otherwise. A \
             worker that is silent (neither success nor error) is not degraded but stale, which \
             fails /health — see relayer_worker_last_success_timestamp_seconds. Synced at scrape \
             time from the /health registry.",
            worker_degraded.clone(),
        );

        let checkpoint_write_failures = Family::default();
        registry.register(
            "relayer_checkpoint_write_failures",
            "Failed CheckpointStore writes per chain_key (disk full, permissions, …). The \
             checkpoint is what lets a restart resume instead of re-scanning from the chain head \
             or losing cursor-holdback protection for an in-flight message, so this should stay \
             at zero.",
            checkpoint_write_failures.clone(),
        );

        let delivery_retries_exceeded = Family::default();
        registry.register(
            "relayer_delivery_retries_exceeded",
            "Delivery attempts on a message past DELIVERY_MAX_DISPATCH_ATTEMPTS, per chain_key. \
             Retries are uncapped by design, so this is not an error budget — it flags a message \
             stuck retrying against a persistently misbehaving destination (bad gas limit, dead \
             signer) that was previously visible only via log-grep.",
            delivery_retries_exceeded.clone(),
        );

        let outcome_store_size = Gauge::default();
        registry.register(
            "relayer_outcome_store_size",
            "Current number of entries in the bounded per-message outcome store. Synced at \
             scrape time.",
            outcome_store_size.clone(),
        );

        let outcome_store_evictions = Gauge::default();
        registry.register(
            "relayer_outcome_store_evictions_total",
            "Cumulative count of outcomes evicted from the bounded store past its capacity. A \
             rising count means /outcomes/{id} 404s can no longer be assumed to mean \"never \
             recorded\" — the id may have aged out. Synced at scrape time.",
            outcome_store_evictions.clone(),
        );

        registry.register(
            "relayer_server",
            "Relayer information",
            Info::new(items::ServerInfo {
                chain_keys: chain_keys
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            }),
        );

        Self {
            registry,
            messages_indexed,
            votes,
            votes_per_message,
            deliver_tx,
            time_to_threshold_seconds,
            time_to_deliver_seconds,
            p2p_peer_count,
            pool_messages_pending,
            attestor_set_size,
            attestor_set_reloads,
            ack_submissions,
            ack_proof_fetches,
            claim_submissions,
            settlement_queue_depth,
            signer_balance,
            cpu_usage_percent,
            memory_usage_bytes,
            thread_count,
            start_time_seconds,
            worker_last_success,
            worker_degraded,
            checkpoint_write_failures,
            delivery_retries_exceeded,
            outcome_store_size,
            outcome_store_evictions,
        }
    }

    /// Publish per-worker progress from the `/health` registry into the gauge family. Called at
    /// scrape time by the `/metrics` handler rather than on every heartbeat: the registry is the
    /// single source of truth, workers keep a single reporting call, and the gauge appears the
    /// moment a worker registers (a gauge that exists-at-some-value is the whole point — an
    /// unincremented counter family would emit nothing and absence is indistinguishable from
    /// health, the exact trap this metric closes).
    pub fn sync_worker_progress(&self, health: &crate::health::Health) {
        let report = health.status();
        for (worker, last_ms) in health.snapshot() {
            let degraded = i64::from(report.degraded.contains(&worker));
            #[allow(clippy::cast_precision_loss)] // unix millis fit f64 exactly until year 287396
            self.worker_last_success
                .get_or_create(&LabelWorker {
                    worker: worker.clone(),
                })
                .set(last_ms as f64 / 1000.0);
            self.worker_degraded
                .get_or_create(&LabelWorker { worker })
                .set(degraded);
        }
    }

    /// Publish the outcome store's size and cumulative eviction count. Called at scrape time,
    /// mirroring [`Self::sync_worker_progress`]: the store is the single source of truth and stays
    /// free of a metrics-crate dependency, rather than threading a `Metrics` handle into it just to
    /// push two numbers.
    pub fn sync_outcome_store(&self, outcomes: &crate::outcome::OutcomeStore) {
        #[allow(clippy::cast_possible_wrap)]
        // bounded by OutcomeStore's cap, nowhere near i64::MAX
        self.outcome_store_size.set(outcomes.len() as i64);
        #[allow(clippy::cast_possible_wrap)]
        self.outcome_store_evictions
            .set(outcomes.evictions() as i64);
    }

    pub fn encode(&self) -> String {
        let mut buffer = String::new();
        prometheus_client::encoding::text::encode(&mut buffer, &self.registry).unwrap();
        buffer
    }

    pub fn build_metrics_response(&self) -> axum::response::Response {
        axum::response::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header(
                axum::http::header::CONTENT_TYPE,
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            )
            .body(axum::body::Body::from(self.encode()))
            .unwrap()
    }

    /// Periodically refresh the hardware gauges until `cancel` fires. Runs as a **managed** worker
    /// (spawned into the `Server::run` `JoinSet`), so it shuts down and drains with the rest of the
    /// relayer instead of being a detached task the runtime aborts. Mirrors the helper in
    /// `proof-gen-api-server`.
    pub async fn run_hardware_updater(metrics: Arc<Self>, cancel: CancellationToken) -> Result<()> {
        let specifics = sysinfo::RefreshKind::nothing()
            .with_cpu(sysinfo::CpuRefreshKind::nothing().with_cpu_usage())
            .with_memory(sysinfo::MemoryRefreshKind::nothing().with_ram())
            .with_processes(
                sysinfo::ProcessRefreshKind::nothing()
                    .with_cpu()
                    .with_memory(),
            );
        let mut sys = sysinfo::System::new_with_specifics(specifics);

        // CPU usage needs a warm-up gap between two refreshes before the first reading is valid.
        tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            () = tokio::time::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL) => {}
        }
        sys.refresh_specifics(specifics);

        let mut tick = tokio::time::interval(Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                _ = tick.tick() => {
                    metrics.update_gauges_from_system(&sys);
                    sys.refresh_specifics(specifics);
                }
            }
        }
    }

    fn update_gauges_from_system(&self, sys: &sysinfo::System) {
        if let Ok(pid) = sysinfo::get_current_pid() {
            if let Some(process) = sys.process(pid) {
                let cpu_process = f64::from(process.cpu_usage());
                let cpu_count = sys.cpus().len() as f64;
                let cpu_percent = if cpu_count > 0.0 {
                    cpu_process / cpu_count
                } else {
                    0.0
                };
                self.cpu_usage_percent.set(cpu_percent);
                self.memory_usage_bytes.set(process.memory() as f64);
                if let Some(tasks) = process.tasks() {
                    self.thread_count.set(tasks.len() as i64);
                }
            }
        }
    }
}

impl MetricsTrait for RelayerMetrics {
    fn inc_messages_indexed(&self, chain_key: u64) {
        self.messages_indexed
            .get_or_create(&LabelChain { chain_key })
            .inc();
    }

    fn inc_vote(&self, chain_key: u64, outcome: VoteOutcome) {
        self.votes
            .get_or_create(&LabelVote { chain_key, outcome })
            .inc();
    }

    fn observe_votes_per_message(&self, count: u64) {
        self.votes_per_message.observe(count as f64);
    }

    fn inc_deliver_tx(&self, chain_key: u64, status: DeliveryStatus) {
        self.deliver_tx
            .get_or_create(&LabelDelivery { chain_key, status })
            .inc();
    }

    fn observe_time_to_threshold(&self, duration: Duration) {
        self.time_to_threshold_seconds
            .observe(duration.as_secs_f64());
    }

    fn observe_time_to_deliver(&self, duration: Duration) {
        self.time_to_deliver_seconds.observe(duration.as_secs_f64());
    }

    fn set_p2p_peer_count(&self, chain_key: u64, count: i64) {
        self.p2p_peer_count
            .get_or_create(&LabelChain { chain_key })
            .set(count);
    }

    fn set_pool_messages_pending(&self, count: i64) {
        self.pool_messages_pending.set(count);
    }

    fn set_attestor_set_size(&self, chain_key: u64, size: i64) {
        self.attestor_set_size
            .get_or_create(&LabelChain { chain_key })
            .set(size);
    }

    fn inc_attestor_set_reload(&self, chain_key: u64) {
        self.attestor_set_reloads
            .get_or_create(&LabelChain { chain_key })
            .inc();
    }

    fn inc_ack_submission(&self, chain_key: u64, outcome: SettlementOutcome) {
        self.ack_submissions
            .get_or_create(&LabelSettlement { chain_key, outcome })
            .inc();
    }

    fn inc_ack_proof_fetch(&self, chain_key: u64, outcome: ProofFetchOutcome) {
        self.ack_proof_fetches
            .get_or_create(&LabelProofFetch { chain_key, outcome })
            .inc();
    }

    fn inc_claim_submission(&self, chain_key: u64, outcome: SettlementOutcome) {
        self.claim_submissions
            .get_or_create(&LabelSettlement { chain_key, outcome })
            .inc();
    }

    fn set_settlement_queue_depth(&self, chain_key: u64, depth: i64) {
        self.settlement_queue_depth
            .get_or_create(&LabelChain { chain_key })
            .set(depth);
    }

    fn set_signer_balance(&self, chain_key: u64, role: &'static str, address: Address, ether: f64) {
        self.signer_balance
            .get_or_create(&LabelSigner {
                chain_key,
                role,
                address: address.to_string(),
            })
            .set(ether);
    }

    fn inc_checkpoint_write_failure(&self, chain_key: u64) {
        self.checkpoint_write_failures
            .get_or_create(&LabelChain { chain_key })
            .inc();
    }

    fn inc_delivery_retries_exceeded(&self, chain_key: u64) {
        self.delivery_retries_exceeded
            .get_or_create(&LabelChain { chain_key })
            .inc();
    }
}

/// Build the HTTP surface (`/metrics` + `/health` + `/votes/{message_hash}` + `/outcomes`).
/// `query_tx` reaches the vote pool so the votes endpoint can serve the live accumulated bundle for
/// a message; `outcomes` is the delivery workers' record of terminal verdicts.
pub fn build_router(
    metrics: Arc<RelayerMetrics>,
    query_tx: tokio::sync::mpsc::Sender<crate::pool::PoolQuery>,
    health: Arc<crate::health::Health>,
    outcomes: Arc<crate::outcome::OutcomeStore>,
) -> axum::Router {
    use axum::routing::get;
    use axum::Extension;

    axum::Router::new()
        .route("/health", get(health_handler))
        .route("/outcomes/{message_id}", get(outcome_handler))
        .route("/outcomes", get(outcomes_handler))
        .route(
            "/metrics",
            get(
                |Extension(m): Extension<Arc<RelayerMetrics>>,
                 Extension(health): Extension<Arc<crate::health::Health>>,
                 Extension(outcomes): Extension<Arc<crate::outcome::OutcomeStore>>| async move {
                    m.sync_worker_progress(&health);
                    m.sync_outcome_store(&outcomes);
                    m.build_metrics_response()
                },
            ),
        )
        .route("/votes/{message_hash}", get(votes_handler))
        .layer(Extension(metrics))
        .layer(Extension(query_tx))
        .layer(Extension(health))
        .layer(Extension(outcomes))
}

/// `GET /outcomes/{message_id}` — the delivery worker's terminal verdict for one message
/// (`delivered` with the destination tx, `destination_failed`, `pending`, `undeliverable`,
/// `terminal`). 404 when the relayer reached no verdict: never seen, still in flight (ask
/// `/votes`), or evicted from the bounded store.
async fn outcome_handler(
    axum::extract::Path(id_str): axum::extract::Path<String>,
    axum::Extension(outcomes): axum::Extension<Arc<crate::outcome::OutcomeStore>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Ok(message_id) = id_str.parse::<alloy::primitives::B256>() else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "message_id must be 0x-prefixed 32-byte hex",
        )
            .into_response();
    };
    match outcomes.get(&message_id) {
        Some(outcome) => axum::Json(outcome).into_response(),
        None => (axum::http::StatusCode::NOT_FOUND, "no outcome recorded").into_response(),
    }
}

/// Upper bound on ids per `/outcomes?ids=` request — one dashboard page of messages.
const OUTCOMES_BATCH_MAX: usize = 256;

#[derive(serde::Deserialize)]
struct OutcomesQuery {
    /// Comma-separated 0x-prefixed 32-byte message ids.
    ids: String,
}

/// `GET /outcomes?ids=0x…,0x…` — batch form of [`outcome_handler`]: a JSON object keyed by message
/// id holding the verdict for every id that has one. Ids without a verdict are simply absent, so
/// one round trip answers a whole table. 400 on a malformed id or more than
/// [`OUTCOMES_BATCH_MAX`] ids.
async fn outcomes_handler(
    axum::extract::Query(q): axum::extract::Query<OutcomesQuery>,
    axum::Extension(outcomes): axum::Extension<Arc<crate::outcome::OutcomeStore>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let mut ids = Vec::new();
    for part in q.ids.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match part.parse::<alloy::primitives::B256>() {
            Ok(id) => ids.push(id),
            Err(_) => {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    format!("bad message id: {part}"),
                )
                    .into_response();
            }
        }
    }
    if ids.len() > OUTCOMES_BATCH_MAX {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            format!("at most {OUTCOMES_BATCH_MAX} ids per request"),
        )
            .into_response();
    }
    let found: std::collections::BTreeMap<String, crate::outcome::DeliveryOutcome> = outcomes
        .get_many(&ids)
        .into_iter()
        .map(|(id, o)| (format!("{id:#x}"), o))
        .collect();
    axum::Json(found).into_response()
}

/// `GET /health` — `200 ok` when every registered worker has reported progress within the deadline;
/// `200` naming the *degraded* worker(s) when some are erroring without progress (alive, retrying,
/// not restart-worthy — see `crate::health`); `503` naming the *stale* worker(s) when one has gone
/// silent, so the k8s liveness probe restarts a wedged relayer. Uses `Health::report`, which logs
/// each transition, so the probe failure is attributable from the pod log.
async fn health_handler(
    axum::Extension(health): axum::Extension<Arc<crate::health::Health>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let report = health.report();
    let degraded = if report.degraded.is_empty() {
        String::new()
    } else {
        format!("degraded workers: {}", report.degraded.join(", "))
    };
    if !report.is_alive() {
        let mut body = format!("stale workers: {}", report.stale.join(", "));
        if !degraded.is_empty() {
            body.push_str("; ");
            body.push_str(&degraded);
        }
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, body).into_response();
    }
    if degraded.is_empty() {
        (axum::http::StatusCode::OK, "ok").into_response()
    } else {
        (axum::http::StatusCode::OK, degraded).into_response()
    }
}

/// `GET /votes/{message_hash}` — return the votes the relayer has accumulated for a message, so it
/// acts as a queryable spy node (an operator or sibling relayer can ask what we have and act on it).
/// `message_hash` is a 0x-prefixed 32-byte hex string. 404 if we have not indexed it.
async fn votes_handler(
    axum::extract::Path(hash_str): axum::extract::Path<String>,
    axum::Extension(query_tx): axum::Extension<tokio::sync::mpsc::Sender<crate::pool::PoolQuery>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let Ok(message_hash) = hash_str.parse::<alloy::primitives::B256>() else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "message_hash must be 0x-prefixed 32-byte hex",
        )
            .into_response();
    };

    let (reply, rx) = tokio::sync::oneshot::channel();
    if query_tx
        .send(crate::pool::PoolQuery {
            message_hash,
            reply,
        })
        .await
        .is_err()
    {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "vote pool unavailable",
        )
            .into_response();
    }
    match rx.await {
        Ok(Some(bundle)) => axum::Json(bundle).into_response(),
        Ok(None) => (axum::http::StatusCode::NOT_FOUND, "message not indexed").into_response(),
        Err(_) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "vote pool dropped query",
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum VoteOutcome {
    Accept,
    Reject,
    Ignore,
    /// Dropped at the libp2p→pool hand-off because the pool was saturated (backpressure). The
    /// vote is not lost to the network — it is re-gossiped — so this is a safe shed under load.
    Dropped,
    /// Verified, but its message was not indexed yet, so it is held until the Outbox watcher
    /// catches up (see `pool::RouteState::early_votes`). Distinct from `Ignore` on purpose: these
    /// used to be discarded, which cost every message a stall-detector timeout before its votes
    /// were re-gossiped. A rising `Buffered` count with a healthy `Accept` count is the system
    /// working; `Buffered` without `Accept` means messages are never getting indexed.
    Buffered,
}

/// Outcome label on `relayer_deliver_tx`. One increment per classified attempt/outcome; a job that
/// is refused before any tx is sent still counts (the `Refused*` arms), so a route that silently
/// drops every message is visible.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum DeliveryStatus {
    Submitted,
    Succeeded,
    Reverted,
    AlreadyValidated,
    /// Votes validated, dApp callback deferred/reverted — stored for `retryPendingMessage`.
    Pending,
    /// asc-contracts #36: delivered AND consumed, but the destination call failed
    /// (`MessageExecutionFailed` alongside `MessageDelivered`). Not retryable; the relayer is still
    /// paid on claim. A rising count here is a destination-dApp problem, not a relayer one.
    DestinationFailed,
    /// The envelope asked the relayer to front more native value than the route's
    /// `max_native_coin_value_wei`. Terminal (quoter/publisher-side fix).
    RefusedNativeValue,
    /// The attested envelope `gasLimit` exceeds the route's `max_gas_limit`, so no relayer can ever
    /// fit it in a destination block. Terminal (publisher-side fix).
    RefusedGasLimit,
    /// `deliverMessage` reverted `ValidationFailedWithNativeValue`: the votes failed validation
    /// while value was attached. Terminal for these votes.
    ValidationFailedWithNativeValue,
    /// `deliverMessage` reverted `InvalidMessageDispatcher`: the Inbox's dispatcher has no code
    /// and value was attached. Terminal until the Inbox is reconfigured.
    InvalidDispatcher,
    /// `deliverMessage` reverted with a shape `classify_delivery_revert` does not recognize —
    /// distinct from the generic `Reverted` bucket (which also covers non-revert failures and
    /// `InsufficientGasForDestination`) on purpose: the classifier's string/selector matching is
    /// known to be fragile across node-client dialects (see the `MessageAlreadyProcessed` incident
    /// documented on `revert_duplicate_delivery`), so a rising count here — as opposed to a rising
    /// `Reverted` count — is the signal that a revert shape needs a new classifier arm, not just a
    /// misbehaving publisher.
    Unclassified,
}

/// Outcome of one settlement attempt (`submitAcknowledgment` or `claimDelivery`) — shared shape
/// for [`RelayerMetrics::inc_ack_submission`]/`inc_claim_submission`, matching how `crate::ack`
/// already classifies a submit (see `SubmitOutcome`/`classify_submit`).
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum SettlementOutcome {
    /// Mined and confirmed on-chain.
    Confirmed,
    /// A permanent on-chain condition (already settled, nothing to ack/claim, proof rejected, …) —
    /// resolved, not an error.
    Terminal,
    /// The attempt did not resolve (proof-gen error, RPC failure, no receipt in time, …) and will
    /// be retried. A sustained rise with no matching `Confirmed`/`Terminal` growth is exactly the
    /// silent-outage shape the settlement path has no other signal for (see the module docs).
    Failed,
    /// Nothing was outstanding: no message in the tx required an ack, or no unsettled relay fee
    /// remained. Counted rather than left silent so an idle settlement path is distinguishable
    /// from a dead one — previously this case incremented nothing at all, which meant a route
    /// that legitimately had no work and a route whose worker had stopped produced identical
    /// (empty) metrics.
    NothingToSettle,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct LabelChain {
    pub chain_key: u64,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct LabelSigner {
    pub chain_key: u64,
    pub role: &'static str,
    /// Checksummed 0x address. A label, not a value, so one wallet reused across roles/chains
    /// stays correlatable in queries.
    pub address: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct LabelWorker {
    pub worker: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct LabelVote {
    pub chain_key: u64,
    pub outcome: VoteOutcome,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct LabelDelivery {
    pub chain_key: u64,
    pub status: DeliveryStatus,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct LabelSettlement {
    pub chain_key: u64,
    pub outcome: SettlementOutcome,
}

/// Outcome of one proof-gen `proof-by-tx` fetch by the ack submitter — the label on
/// [`MetricsTrait::inc_ack_proof_fetch`]. Mirrors `crate::proofgen::ProofFetch` plus the error arm.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum ProofFetchOutcome {
    /// A proof came back and was handed to the submit path.
    Ready,
    /// Proof-gen answered "not yet" (HTTP 422 `BlockNotReady`, or 404 while its view of the
    /// destination chain lags the tx). Re-polled on the flat not-ready cadence; a steady stream
    /// here with matching `Ready` growth is attestation latency, not a fault.
    NotReady,
    /// A real failure (5xx, connection error, undecodable body). Backed off exponentially; a
    /// sustained rise with no `Ready` growth is the proof-gen-outage shape.
    Error,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct LabelProofFetch {
    pub chain_key: u64,
    pub outcome: ProofFetchOutcome,
}

mod items {
    use prometheus_client::encoding::EncodeLabelSet;

    #[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
    pub struct ServerInfo {
        pub chain_keys: String,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of these two additions is that an idle settlement path is distinguishable
    /// from a dead one. That requires the queue-depth gauge to be *present at zero* (a gauge set to
    /// Pins the wire shape the low-balance alert will query: metric name, the three labels, and
    /// ether units (0.5, not 5e17) — a rename or a wei/ether mixup must fail here, not in a
    /// silently never-firing alert.
    #[test]
    fn signer_balance_encodes_name_labels_and_ether_units() {
        let m = RelayerMetrics::new(&[8]);
        let addr: Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            .parse()
            .unwrap();
        m.set_signer_balance(8, "delivery", addr, 0.5);
        let body = m.encode();
        let line = body
            .lines()
            .find(|l| l.starts_with("relayer_signer_balance_ether{"))
            .unwrap_or_else(|| panic!("no signer balance sample:\n{body}"));
        for needle in ["chain_key=\"8\"", "role=\"delivery\"", "0xf39Fd6e5", " 0.5"] {
            assert!(line.contains(needle), "missing {needle} in: {line}");
        }
    }

    /// The idle-vs-hung gap this closes: on 2026-08-30 the relayer went silent for a day and the
    /// only way to tell "healthy and idle" from "wedged" was log forensics — /health knew the
    /// per-worker progress the whole time but Prometheus could not see it. The gauge must (a)
    /// carry the worker name from the health registry verbatim, and (b) encode a plausible unix
    /// time in SECONDS, so `time() - metric` alerting works.
    #[test]
    fn worker_progress_reaches_the_scrape_body() {
        let m = RelayerMetrics::new(&[8]);
        let h = crate::health::Health::new(crate::health::PROGRESS_DEADLINE);
        h.heartbeat("outbox:8");
        m.sync_worker_progress(&h);
        let body = m.encode();
        let line = body
            .lines()
            .find(|l| {
                l.contains("relayer_worker_last_success_timestamp_seconds")
                    && l.contains("outbox:8")
            })
            .unwrap_or_else(|| panic!("no sample for worker=\"outbox:8\":\n{body}"));
        let value: f64 = line
            .rsplit(' ')
            .next()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("unparseable sample line: {line}"));
        // A milliseconds value would be ~1.7e12 — three orders of magnitude past this bound.
        assert!(
            (1.0e9..1.0e10).contains(&value),
            "expected unix SECONDS (~1.7e9), got {value} — a ms/seconds mixup breaks time()-based alerts"
        );
    }

    /// The 2026-09-17 shape on the wire: a Base worker erroring past the deadline must show as
    /// `relayer_worker_degraded{worker="ack:9"} 1` while a healthy worker on the same scrape is
    /// present at 0 — present, so `absent()` alerting cannot confuse "healthy" with "never
    /// registered".
    #[test]
    fn degraded_worker_reaches_the_scrape_body() {
        let m = RelayerMetrics::new(&[8, 9]);
        let h = crate::health::Health::new(Duration::from_secs(5 * 60));
        h.set_for_test(
            "ack:9",
            Duration::from_secs(6 * 60),
            Some(Duration::from_secs(20)),
        );
        h.heartbeat("ack:8");
        m.sync_worker_progress(&h);
        let body = m.encode();
        assert!(
            body.contains("relayer_worker_degraded{worker=\"ack:9\"} 1"),
            "erroring-without-progress worker must be degraded=1:\n{body}"
        );
        assert!(
            body.contains("relayer_worker_degraded{worker=\"ack:8\"} 0"),
            "healthy worker must be present at degraded=0:\n{body}"
        );
    }

    /// 0 still encodes; an unincremented counter family emits nothing) and the no-op outcome to
    /// carry its own label value.
    #[test]
    fn an_idle_settlement_path_is_still_visible() {
        let m = RelayerMetrics::new(&[8]);
        m.set_settlement_queue_depth(8, 0);
        m.inc_ack_submission(8, SettlementOutcome::NothingToSettle);
        let body = m.encode();
        assert!(
            body.contains("relayer_settlement_queue_depth{chain_key=\"8\"} 0"),
            "a zero queue depth must still be scrapeable, else absent() cannot tell idle from dead:\n{body}"
        );
        assert!(
            body.contains("outcome=\"NothingToSettle\""),
            "the no-op outcome needs its own label value:\n{body}"
        );
    }

    #[test]
    fn metrics_encode_round_trips() {
        let m = RelayerMetrics::new(&[2, 7]);
        m.inc_messages_indexed(2);
        m.inc_vote(2, VoteOutcome::Accept);
        m.inc_deliver_tx(7, DeliveryStatus::Submitted);
        m.inc_ack_submission(7, SettlementOutcome::Confirmed);
        m.inc_claim_submission(7, SettlementOutcome::Failed);
        m.set_settlement_queue_depth(7, 3);
        m.inc_ack_proof_fetch(7, ProofFetchOutcome::NotReady);
        m.inc_ack_proof_fetch(7, ProofFetchOutcome::NotReady);
        m.inc_ack_proof_fetch(7, ProofFetchOutcome::Error);
        let body = m.encode();
        assert!(body.contains("relayer_messages_indexed"));
        assert!(body.contains("relayer_votes_received"));
        assert!(body.contains("relayer_deliver_tx"));
        assert!(body.contains("relayer_ack_submissions"));
        // The not-ready / error split must be visible as distinct label values on one family.
        assert!(
            body.contains(
                "relayer_ack_proof_fetches_total{chain_key=\"7\",outcome=\"NotReady\"} 2"
            ),
            "{body}"
        );
        assert!(
            body.contains("relayer_ack_proof_fetches_total{chain_key=\"7\",outcome=\"Error\"} 1"),
            "{body}"
        );
        assert!(body.contains("relayer_claim_submissions"));
        assert!(body.contains("relayer_settlement_queue_depth"));
        assert!(body.contains("chain_keys=\"2,7\""));
    }

    /// The #36 outcomes must be distinct label values on the existing `relayer_deliver_tx` family
    /// (dashboards select on `status`), not folded into `Succeeded`/`Reverted`.
    #[test]
    fn post_36_delivery_outcomes_are_distinct_labels() {
        let m = RelayerMetrics::new(&[8]);
        m.inc_deliver_tx(8, DeliveryStatus::DestinationFailed);
        m.inc_deliver_tx(8, DeliveryStatus::RefusedNativeValue);
        m.inc_deliver_tx(8, DeliveryStatus::RefusedGasLimit);
        m.inc_deliver_tx(8, DeliveryStatus::ValidationFailedWithNativeValue);
        m.inc_deliver_tx(8, DeliveryStatus::InvalidDispatcher);
        let body = m.encode();
        for status in [
            "DestinationFailed",
            "RefusedNativeValue",
            "RefusedGasLimit",
            "ValidationFailedWithNativeValue",
            "InvalidDispatcher",
        ] {
            let needle =
                format!("relayer_deliver_tx_total{{chain_key=\"8\",status=\"{status}\"}} 1");
            assert!(body.contains(&needle), "missing {needle} in:\n{body}");
        }
    }

    #[test]
    fn noop_metrics_compile() {
        let m = NoopMetrics::new();
        m.inc_messages_indexed(1);
        m.inc_vote(1, VoteOutcome::Reject);
        m.inc_deliver_tx(1, DeliveryStatus::Succeeded);
        m.observe_votes_per_message(7);
        m.observe_time_to_threshold(Duration::from_millis(100));
        m.observe_time_to_deliver(Duration::from_millis(200));
        m.set_p2p_peer_count(1, 4);
        m.set_pool_messages_pending(3);
        m.inc_ack_submission(1, SettlementOutcome::Terminal);
        m.inc_ack_proof_fetch(1, ProofFetchOutcome::Ready);
        m.inc_claim_submission(1, SettlementOutcome::Confirmed);
        m.inc_checkpoint_write_failure(1);
        m.inc_delivery_retries_exceeded(1);
    }

    /// A checkpoint write failure must be attributable to a chain_key, not just a log line — the
    /// checkpoint is load-bearing for restart safety (see `crate::checkpoint`).
    #[test]
    fn checkpoint_write_failure_is_labeled_by_chain() {
        let m = RelayerMetrics::new(&[8]);
        m.inc_checkpoint_write_failure(8);
        m.inc_checkpoint_write_failure(8);
        let body = m.encode();
        assert!(
            body.contains("relayer_checkpoint_write_failures_total{chain_key=\"8\"} 2"),
            "{body}"
        );
    }

    /// A message stuck past the retry-exceeded threshold must be a countable series, not just a
    /// `warn!` line — see `pool::State::note_delivery_result`.
    #[test]
    fn delivery_retries_exceeded_is_labeled_by_chain() {
        let m = RelayerMetrics::new(&[8]);
        m.inc_delivery_retries_exceeded(8);
        let body = m.encode();
        assert!(
            body.contains("relayer_delivery_retries_exceeded_total{chain_key=\"8\"} 1"),
            "{body}"
        );
    }

    /// The outcome store's size and cumulative evictions must reach the scrape body, synced from
    /// the store rather than pushed on every record/evict — mirrors `sync_worker_progress`.
    #[test]
    fn outcome_store_stats_reach_the_scrape_body() {
        let m = RelayerMetrics::new(&[8]);
        let store = crate::outcome::OutcomeStore::new(2);
        for n in 1..=3u8 {
            store.record(
                alloy::primitives::B256::repeat_byte(n),
                crate::outcome::DeliveryOutcome::new(crate::outcome::OutcomeKind::Delivered, 8),
            );
        }
        m.sync_outcome_store(&store);
        let body = m.encode();
        assert!(
            body.contains("relayer_outcome_store_size 2"),
            "store is capped at 2:\n{body}"
        );
        assert!(
            body.contains("relayer_outcome_store_evictions_total 1"),
            "one of the three records must have evicted the oldest:\n{body}"
        );
    }

    /// `Unclassified` must be its own label value on the existing `relayer_deliver_tx` family, not
    /// folded into the generic `Reverted` bucket — see the `DeliveryStatus::Unclassified` doc.
    #[test]
    fn unclassified_revert_is_a_distinct_label() {
        let m = RelayerMetrics::new(&[8]);
        m.inc_deliver_tx(8, DeliveryStatus::Unclassified);
        let body = m.encode();
        assert!(
            body.contains("relayer_deliver_tx_total{chain_key=\"8\",status=\"Unclassified\"} 1"),
            "{body}"
        );
    }
}
