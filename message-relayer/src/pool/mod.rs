//! Vote pool — the heart of relayer aggregation logic.
//!
//! Receives [`IndexedMessage`]s from the outbox watcher and [`MessageVote`]s from the libp2p
//! worker, then enforces PoC §6.2 validation rules (chain-first allowlist, ecrecover, signer
//! allowlist, dedup) before counting. When a `messageHash` accumulates `>= threshold` distinct
//! signers, the pool builds a [`DeliveryJob`] and dispatches it to the per-route delivery
//! channel.
//!
//! The pool runs as a single tokio task. State is **not** shared with other tasks — workers
//! talk to it strictly through mpsc channels. This keeps locking trivial and makes RAM-bound
//! invariants (PoC §9) easy to reason about.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use alloy::primitives::{Address, Signature, B256, U256};
use anyhow::Result;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use write_ability::envelope::ReobservationRequest;

use crate::config::VoteCacheConfig;
use crate::delivery::encode::encode_votes;
use crate::delivery::{DeliveryJob, DeliveryResult, DeliveryResultKind};
use crate::events::IndexedMessage;
use crate::p2p::MessageVote;
use crate::prom::{Metrics, VoteOutcome};

/// Quorum: 2N/3 + 1 unique signers (PoC §6.3).
#[must_use]
pub fn calculate_threshold(n: usize) -> usize {
    (2 * n) / 3 + 1
}

/// How long a message may sit below quorum before the relayer starts broadcasting reobservation
/// requests for it (liveness recovery — see [`ReobservationRequest`]). Well above the normal
/// vote-collection latency so healthy messages never trigger a request.
const REOBS_STALL_AFTER: Duration = Duration::from_secs(60);
/// Minimum gap between successive reobservation requests for the same stalled message.
const REOBS_REPEAT_EVERY: Duration = Duration::from_secs(60);
const DELIVERY_RETRY_BASE: Duration = Duration::from_secs(30);
const DELIVERY_RETRY_MAX: Duration = Duration::from_secs(5 * 60);
const DELIVERY_MAX_DISPATCH_ATTEMPTS: u32 = 5;
/// Short delay before re-dispatching a job whose per-route delivery channel was full (backpressure).
/// Long enough for the worker to drain an in-flight job, short enough that delivery isn't needlessly
/// delayed once the channel clears.
const DELIVERY_CHANNEL_FULL_REQUEUE_DELAY: Duration = Duration::from_secs(2);

/// Snapshot of the votes accumulated for one message, answered by the pool over [`PoolQuery`] and
/// served read-only at `GET /votes/{message_hash}`. Lets a relayer act as a queryable "spy node":
/// an operator (or a sibling relayer) can ask what we have for a message and merge / act on it.
#[derive(Clone, Debug, serde::Serialize)]
pub struct VoteBundle {
    pub chain_key: u64,
    pub message_id: B256,
    pub message_hash: B256,
    pub threshold: usize,
    pub signer_count: usize,
    pub delivered: bool,
    /// Addresses whose (validated) signatures we have counted so far.
    pub signers: Vec<Address>,
}

/// A read-only request for the [`VoteBundle`] of a `message_hash`, with a oneshot to reply on.
pub struct PoolQuery {
    pub message_hash: B256,
    pub reply: oneshot::Sender<Option<VoteBundle>>,
}

/// Pre-resolved attestor allowlist for a route. The runtime resolves [`AttestorSet`] (which may
/// be `OnChain`) into this concrete shape during `Server::new`, so the pool only deals with
/// EVM addresses + a fixed threshold.
///
/// [`AttestorSet`]: crate::config::AttestorSet
#[derive(Clone, Debug)]
pub struct RouteAttestors {
    pub chain_key: u64,
    pub attestors: Vec<Address>,
    pub threshold: usize,
}

/// Inputs / outputs for the pool task.
pub struct PoolHandles {
    pub indexed_rx: mpsc::Receiver<IndexedMessage>,
    pub vote_rx: mpsc::Receiver<MessageVote>,
    pub delivery_txs: HashMap<u64, mpsc::Sender<DeliveryJob>>,
    pub delivery_result_rx: mpsc::Receiver<DeliveryResult>,
    /// Hot-reloaded attestor sets from the per-route on-chain watchers. Each update replaces a
    /// route's allowlist + threshold and re-evaluates its pending messages. Routes with a static
    /// set never send here.
    pub set_update_rx: mpsc::Receiver<RouteAttestors>,
    /// Reobservation requests this pool emits for messages stalled below quorum; the p2p worker
    /// gossips them so attestors re-sign.
    pub reobs_tx: mpsc::Sender<ReobservationRequest>,
    /// Read-only vote-bundle queries (served at `GET /votes/{message_hash}`).
    pub query_rx: mpsc::Receiver<PoolQuery>,
    /// Outbox-cursor holdback the pool feeds on its prune tick (oldest unfinished message block per
    /// route) so the watchers never persist a cursor past an undelivered message. See
    /// [`crate::checkpoint::CursorHoldback`].
    pub holdback: std::sync::Arc<crate::checkpoint::CursorHoldback>,
}

/// Run the pool task. Returns when `cancel` fires or both inputs close.
pub async fn run(
    routes: Vec<RouteAttestors>,
    cache: VoteCacheConfig,
    handles: PoolHandles,
    metrics: Metrics,
    health: std::sync::Arc<crate::health::Health>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut state = State::new(routes, cache);
    let PoolHandles {
        mut indexed_rx,
        mut vote_rx,
        delivery_txs,
        mut delivery_result_rx,
        mut set_update_rx,
        reobs_tx,
        mut query_rx,
        holdback,
    } = handles;

    // Publish the starting allowlist sizes (static routes report their configured size; on-chain
    // routes start empty until their watcher resolves the set).
    state.report_set_sizes(metrics.as_ref());

    // Once every set-update sender is dropped (e.g. no on-chain routes, or all watchers exited),
    // `recv()` yields `None` forever; flip this off so the branch stops being polled.
    let mut set_updates_open = true;
    // Same guard for the query channel (sender held by the HTTP layer until shutdown).
    let mut query_open = true;

    let mut prune_tick = tokio::time::interval(Duration::from_secs(30));
    prune_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Register at startup so a pool that wedges before its first prune tick still goes stale (C2r).
    health.heartbeat("pool");

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!("🛑 vote pool exiting on cancel");
                return Ok(());
            }
            maybe = set_update_rx.recv(), if set_updates_open => {
                let Some(update) = maybe else {
                    set_updates_open = false;
                    continue;
                };
                for job in state.apply_attestor_set(update, metrics.as_ref()) {
                    if let Err((ck, mh)) = dispatch_delivery_job(&delivery_txs, job, "set-reload dispatch") {
                        state.requeue_delivery(ck, mh, Instant::now());
                    }
                }
            }
            maybe = indexed_rx.recv() => {
                let Some(indexed) = maybe else {
                    info!("indexed_rx channel closed; shutting pool down");
                    return Ok(());
                };
                if let Some(job) = state.note_indexed(indexed, metrics.as_ref()) {
                    let label = "buffered-vote dispatch";
                    if let Err((ck, mh)) = dispatch_delivery_job(&delivery_txs, job, label) {
                        state.requeue_delivery(ck, mh, Instant::now());
                    }
                }
            }
            maybe = vote_rx.recv() => {
                let Some(vote) = maybe else {
                    info!("vote_rx channel closed; shutting pool down");
                    return Ok(());
                };
                if let Some(job) = state.note_vote(vote, metrics.as_ref()) {
                    if let Err((ck, mh)) = dispatch_delivery_job(&delivery_txs, job, "vote dispatch") {
                        state.requeue_delivery(ck, mh, Instant::now());
                    }
                }
            }
            maybe = delivery_result_rx.recv() => {
                let Some(result) = maybe else {
                    warn!("delivery result channel closed");
                    continue;
                };
                if let Some(job) = state.note_delivery_result(result, metrics.as_ref()) {
                    if let Err((ck, mh)) = dispatch_delivery_job(&delivery_txs, job, "delivery retry dispatch") {
                        state.requeue_delivery(ck, mh, Instant::now());
                    }
                }
            }
            maybe = query_rx.recv(), if query_open => {
                let Some(query) = maybe else {
                    query_open = false;
                    continue;
                };
                let _ = query.reply.send(state.query_bundle(&query.message_hash));
            }
            _ = prune_tick.tick() => {
                // The prune tick fires unconditionally, so it is the pool's liveness pulse: a
                // deadlocked/stopped pool stops reaching here and /health trips a restart (C2r).
                health.heartbeat("pool");
                state.prune_expired();
                metrics.set_pool_messages_pending(state.total_pending() as i64);
                // Publish the oldest unfinished message block per route so the outbox watchers
                // clamp their persisted cursors — restart-recovery then always re-indexes every
                // undelivered message, however old (checkpoint-past-unfinished-work fix).
                for (ck, oldest) in state.oldest_unfinished_blocks() {
                    holdback.update(ck, oldest);
                }
                // Nudge attestors to re-sign anything stuck below quorum. Best effort: a full
                // request channel just means we try again on the next tick.
                for req in state.collect_stalled_reobservations(Instant::now()) {
                    if let Err(err) = reobs_tx.try_send(req) {
                        debug!(%err, "reobservation request channel full/closed");
                    }
                }
                for job in state.collect_ready_deliveries(metrics.as_ref()) {
                    if let Err((ck, mh)) = dispatch_delivery_job(&delivery_txs, job, "ready retry dispatch") {
                        state.requeue_delivery(ck, mh, Instant::now());
                    }
                }
            }
        }
    }
}

/// Hand a delivery job to its route's worker **without blocking**. `Ok(())` when sent (or dropped
/// for a misconfigured/closed channel); `Err((chain_key, message_hash))` when the per-route channel
/// is full — the caller returns that slot to the pool via [`State::requeue_delivery`] for a
/// near-term retry. (Returning just the keys, not the whole `DeliveryJob`, keeps the `Err` variant
/// small.)
///
/// Previously this `await`ed `tx.send`, so a slow or wedged destination on one route filled its cap
/// channel and stalled the single pool task — blocking vote aggregation and indexing for *every*
/// route (S3r). `try_send` keeps the pool turning; the job isn't lost (its slot stays pending and is
/// re-dispatched), and shutdown is handled by the run loop's own cancel arm rather than here.
fn dispatch_delivery_job(
    delivery_txs: &HashMap<u64, mpsc::Sender<DeliveryJob>>,
    job: DeliveryJob,
    context: &'static str,
) -> Result<(), (u64, B256)> {
    let chain_key = job.chain_key;
    let Some(tx) = delivery_txs.get(&chain_key) else {
        // Impossible with today's wiring (delivery_txs is built from the same route list), but if
        // it ever happens the slot must not be stranded `in_flight` — undelivered slots are no
        // longer TTL-evicted, so a leaked in_flight slot would live forever, invisible to retry
        // and reobservation. Requeue instead: correct, and loudly repetitive rather than silent.
        warn!(
            chain_key,
            context, "no delivery worker registered for chain_key; requeueing"
        );
        return Err((chain_key, job.message_hash));
    };

    match tx.try_send(job) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(job)) => Err((job.chain_key, job.message_hash)),
        Err(mpsc::error::TrySendError::Closed(job)) => {
            // The delivery worker exited — the supervisor is tearing the process down; requeue
            // (rather than drop) so the slot isn't left in_flight if teardown races slowly.
            warn!(
                chain_key = job.chain_key,
                context, "delivery channel closed; requeueing (process is shutting down)"
            );
            Err((job.chain_key, job.message_hash))
        }
    }
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

struct State {
    by_route: HashMap<u64, RouteState>,
    cache: VoteCacheConfig,
}

struct RouteState {
    attestors: Vec<Address>,
    threshold: usize,
    by_message: HashMap<B256, MessageSlot>,
    /// Insertion order, used together with [`MessageSlot::inserted_at`] for TTL/LRU eviction.
    order: VecDeque<B256>,
    cache_max: usize,
    /// Verified votes whose message the Outbox watcher has not indexed yet, keyed by message hash
    /// and then by *recovered* signer.
    ///
    /// Attestors gossip a vote as soon as they observe a message, which is routinely before this
    /// relayer has read the same message out of the Creditcoin logs. Those votes used to be
    /// dropped, so every message waited for its stall-detector timeout and a reobservation round
    /// before its votes were accepted — measured on usc-devnet as 233 deliveries against 236
    /// reobservation requests, a ~41s median time-to-threshold against the few seconds the
    /// pipeline is actually capable of, and a hard dependency on the reobservation path for
    /// 100% of traffic.
    ///
    /// Bounded two ways. Within a hash, the key is the recovered signer and every signer must
    /// already be in `attestors`, so an entry cannot exceed the attestor set. Across hashes,
    /// `cache_max` applies with oldest-first eviction, and [`Self::prune_expired`] ages entries
    /// out — a hash that is never indexed must not pin memory forever.
    early_votes: HashMap<B256, EarlyVotes>,
}

/// Buffered votes for one not-yet-indexed message. Keyed by recovered signer for the same reason
/// [`MessageSlot::signers`] is: a forged signature must not be able to occupy a real attestor's
/// slot and displace their genuine vote.
struct EarlyVotes {
    signers: BTreeMap<Address, [u8; 65]>,
    first_seen: Instant,
}

struct MessageSlot {
    indexed: IndexedMessage,
    signers: BTreeMap<Address, [u8; 65]>,
    delivered: bool,
    terminal: bool,
    in_flight: bool,
    delivery_attempts: u32,
    next_delivery_attempt_at: Option<Instant>,
    inserted_at: Instant,
    /// When we last gossiped a reobservation request for this message (`None` = never). Rate-limits
    /// re-requests so a persistently stalled message doesn't spam the mesh.
    last_reobs_request: Option<Instant>,
}

impl State {
    fn new(routes: Vec<RouteAttestors>, cache: VoteCacheConfig) -> Self {
        let cap = cache.max_messages;
        Self {
            by_route: routes
                .into_iter()
                .map(|r| {
                    (
                        r.chain_key,
                        RouteState {
                            attestors: r.attestors,
                            threshold: r.threshold,
                            by_message: HashMap::new(),
                            early_votes: HashMap::new(),
                            order: VecDeque::new(),
                            cache_max: cap,
                        },
                    )
                })
                .collect(),
            cache,
        }
    }

    /// Returns a [`DeliveryJob`] when buffered votes already put this message at quorum, so the
    /// caller dispatches immediately instead of waiting for the next `collect_ready_deliveries`
    /// tick — otherwise the buffer would trade a stall-detector round trip for a tick delay.
    fn note_indexed(
        &mut self,
        indexed: IndexedMessage,
        metrics: &dyn crate::prom::MetricsTrait,
    ) -> Option<DeliveryJob> {
        let chain_key = indexed.chain_key;
        let Some(route) = self.by_route.get_mut(&chain_key) else {
            warn!(
                chain_key,
                "indexed message for unconfigured chain_key — dropping"
            );
            return None;
        };
        let hash = indexed.message_hash;
        if route.by_message.contains_key(&hash) {
            // Re-org or duplicate finalized event; safe to ignore — keep the original slot.
            debug!(chain_key, %hash, "re-indexing existing message; keeping original slot");
            return None;
        }
        route.by_message.insert(
            hash,
            MessageSlot {
                indexed,
                signers: BTreeMap::new(),
                delivered: false,
                terminal: false,
                in_flight: false,
                delivery_attempts: 0,
                next_delivery_attempt_at: None,
                inserted_at: Instant::now(),
                last_reobs_request: None,
            },
        );
        route.order.push_back(hash);
        route.evict_overflow();

        // Adopt any votes that arrived before this message was indexed. Doing it here rather than
        // waiting for re-gossip is the whole point of the buffer: it is what removes the
        // stall-detector round trip from the common path.
        let job = 'adopt: {
            let Some(early) = route.early_votes.remove(&hash) else {
                break 'adopt None;
            };
            let adopted = early.signers.len();
            let slot = route
                .by_message
                .get_mut(&hash)
                .expect("slot inserted immediately above");
            // Re-check membership per signer: the attestor set can have rotated between the vote
            // arriving and the message being indexed, and a vote from an attestor who is no longer
            // in the set must not count toward the new threshold.
            let mut dropped_by_rotation = 0usize;
            for (signer, signature) in early.signers {
                if route.attestors.contains(&signer) {
                    slot.signers.insert(signer, signature);
                    metrics.inc_vote(chain_key, VoteOutcome::Accept);
                } else {
                    dropped_by_rotation += 1;
                    metrics.inc_vote(chain_key, VoteOutcome::Reject);
                }
            }
            let signer_count = slot.signers.len();
            debug!(
                chain_key, %hash, adopted, dropped_by_rotation, signer_count,
                "adopted buffered votes for newly indexed message"
            );
            if signer_count >= route.threshold {
                info!(
                    chain_key,
                    %hash,
                    signer_count,
                    "✅ threshold reached from buffered votes — dispatching without waiting for \
                     reobservation"
                );
            }
            // `observe_threshold` is true, so this records `time_to_threshold` measured from the
            // slot's `inserted_at` — a moment ago. That is not a broken metric: it has always
            // meant "how long after *we* index a message do we reach quorum", and a buffered
            // quorum legitimately reaches it instantly. Expect that histogram to collapse toward
            // zero once this ships, and read attestation latency off the attestor side instead.
            Self::dispatch_if_ready(chain_key, hash, route, metrics, true, Instant::now())
        };

        metrics.set_pool_messages_pending(self.total_pending() as i64);
        job
    }

    fn note_vote(
        &mut self,
        vote: MessageVote,
        metrics: &dyn crate::prom::MetricsTrait,
    ) -> Option<DeliveryJob> {
        let chain_key = vote.chain_key;
        let route = self.by_route.get_mut(&chain_key)?;

        let hash = B256::from(vote.message_hash);
        if !route.by_message.contains_key(&hash) {
            // Not indexed yet. Hold the vote rather than discarding it: it is almost always a
            // legitimate attestor gossiping ahead of our own Outbox watcher, and dropping it cost
            // every message a stall-detector timeout before the re-gossip was accepted. Verified
            // before buffering — see `buffer_early_vote`. Nothing can be dispatched here:
            // without an indexed message there is no payload or emitter to deliver, so quorum is
            // evaluated in `note_indexed`.
            route.buffer_early_vote(chain_key, hash, &vote, metrics);
            return None;
        }
        let Some(slot) = route.by_message.get_mut(&hash) else {
            unreachable!("presence checked immediately above")
        };
        if slot.delivered || slot.terminal {
            debug!(chain_key, %hash, delivered = slot.delivered, terminal = slot.terminal,
                "vote for already-resolved message ignored");
            metrics.inc_vote(chain_key, VoteOutcome::Ignore);
            return None;
        }

        let claimed_signer = Address::from(vote.signer);

        // Allowlist check — cheap, do before `ecrecover`.
        if !route.attestors.contains(&claimed_signer) {
            // warn, not debug: a claimed signer outside the current allowlist is either a stale
            // attestor set (rotation not yet applied here) or a misbehaving/unauthorized voter —
            // unlike the routine drops above, this does not self-heal and is worth a human seeing.
            warn!(chain_key, %hash, %claimed_signer, "vote rejected: signer not in attestor allowlist");
            metrics.inc_vote(chain_key, VoteOutcome::Reject);
            return None;
        }

        // Recover the actual signer and ensure it agrees with the claimed signer.
        let recovered = match recover_signer(&hash, &vote.signature) {
            Ok(addr) => addr,
            Err(err) => {
                warn!(chain_key, %hash, %err, %claimed_signer, "vote rejected: signature did not recover");
                metrics.inc_vote(chain_key, VoteOutcome::Reject);
                return None;
            }
        };
        if recovered != claimed_signer {
            warn!(chain_key, %hash, %claimed_signer, %recovered,
                "vote rejected: recovered signer does not match claimed signer");
            metrics.inc_vote(chain_key, VoteOutcome::Reject);
            return None;
        }

        // Dedup.
        if slot.signers.contains_key(&recovered) {
            debug!(chain_key, %hash, %recovered, "duplicate vote from signer ignored");
            metrics.inc_vote(chain_key, VoteOutcome::Ignore);
            return None;
        }
        slot.signers.insert(recovered, vote.signature);
        metrics.inc_vote(chain_key, VoteOutcome::Accept);

        if slot.signers.len() < route.threshold || slot.in_flight {
            return None;
        }

        let signer_count = slot.signers.len();
        let elapsed = slot.inserted_at.elapsed();
        metrics.observe_votes_per_message(signer_count as u64);
        metrics.observe_time_to_threshold(elapsed);

        info!(
            chain_key,
            %hash,
            signer_count,
            elapsed_ms = elapsed.as_millis() as u64,
            "✅ threshold reached — dispatching delivery"
        );

        Self::dispatch_if_ready(chain_key, hash, route, metrics, true, Instant::now())
    }

    fn prune_expired(&mut self) {
        let ttl = Duration::from_secs(self.cache.ttl_seconds);
        let now = Instant::now();
        for route in self.by_route.values_mut() {
            route.prune_expired(now, ttl);
        }
    }

    fn note_delivery_result(
        &mut self,
        result: DeliveryResult,
        metrics: &dyn crate::prom::MetricsTrait,
    ) -> Option<DeliveryJob> {
        let route = self.by_route.get_mut(&result.chain_key)?;
        let slot = route.by_message.get_mut(&result.message_hash)?;
        slot.in_flight = false;
        match result.outcome {
            DeliveryResultKind::Delivered => {
                slot.delivered = true;
                metrics.set_pool_messages_pending(self.total_pending() as i64);
                return None;
            }
            DeliveryResultKind::Terminal => {
                slot.terminal = true;
                metrics.set_pool_messages_pending(self.total_pending() as i64);
                return None;
            }
            DeliveryResultKind::Retryable => {
                // Do NOT give up after a fixed budget. The message has reached quorum and is
                // validated-ready; the old `terminal = true` after DELIVERY_MAX_DISPATCH_ATTEMPTS
                // meant permanent non-delivery once the outbox checkpoint advanced past it — a
                // ~15-20min destination-RPC outage (or a dead WS delivery provider, which fails every
                // job instantly) silently stranded the message, unrecoverable even across restarts
                // because the budget outlives the scan lookback (C1r). Keep retrying at the capped
                // backoff instead (delivery_retry_delay tops out at DELIVERY_RETRY_MAX); re-attempts
                // are safe via on-chain idempotency (AlreadyValidated), and the slot is still bounded
                // by the count-based LRU (evict_overflow). Genuine permanent failures (reverts) are
                // classified `Terminal`, not `Retryable`, so they are unaffected.
                let delay = delivery_retry_delay(slot.delivery_attempts);
                slot.next_delivery_attempt_at = Some(Instant::now() + delay);
                if slot.delivery_attempts >= DELIVERY_MAX_DISPATCH_ATTEMPTS {
                    // Past the old give-up point: escalate so a persistently failing destination is
                    // alertable, but keep trying rather than dropping.
                    warn!(
                        chain_key = result.chain_key,
                        message_hash = %result.message_hash,
                        attempts = slot.delivery_attempts,
                        retry_after_ms = delay.as_millis() as u64,
                        "delivery still failing after {DELIVERY_MAX_DISPATCH_ATTEMPTS}+ attempts; continuing to retry at capped backoff (check the destination RPC/signer)"
                    );
                } else {
                    debug!(
                        chain_key = result.chain_key,
                        message_hash = %result.message_hash,
                        attempts = slot.delivery_attempts,
                        retry_after_ms = delay.as_millis() as u64,
                        "delivery failed transiently; scheduled bounded retry"
                    );
                }
            }
        }
        None
    }

    fn collect_ready_deliveries(
        &mut self,
        metrics: &dyn crate::prom::MetricsTrait,
    ) -> Vec<DeliveryJob> {
        let now = Instant::now();
        let mut jobs = Vec::new();
        for (chain_key, route) in &mut self.by_route {
            let hashes: Vec<B256> = route.by_message.keys().copied().collect();
            for hash in hashes {
                if let Some(job) =
                    Self::dispatch_if_ready(*chain_key, hash, route, metrics, false, now)
                {
                    jobs.push(job);
                }
            }
        }
        jobs
    }

    fn total_pending(&self) -> usize {
        self.by_route.values().map(|r| r.by_message.len()).sum()
    }

    /// Oldest unfinished (undelivered, non-terminal) message block per route — the outbox-cursor
    /// holdback anchors. Delivered and terminal slots don't hold the cursor back: delivered work is
    /// done, and terminal (genuine revert) messages will never deliver no matter how often they are
    /// re-indexed.
    fn oldest_unfinished_blocks(&self) -> Vec<(u64, Option<u64>)> {
        self.by_route
            .iter()
            .map(|(chain_key, route)| {
                let oldest = route
                    .by_message
                    .values()
                    .filter(|slot| !slot.delivered && !slot.terminal)
                    .map(|slot| slot.indexed.block_height)
                    .min();
                (*chain_key, oldest)
            })
            .collect()
    }

    /// Return a job to its slot after a full delivery channel (backpressure, not a delivery
    /// failure): clear `in_flight` and schedule a near-term retry so a slow/wedged destination on
    /// one route can't strand the message (S3r). Undoes the attempt increment `dispatch_if_ready`
    /// applied, since no delivery was actually attempted.
    fn requeue_delivery(&mut self, chain_key: u64, message_hash: B256, now: Instant) {
        let Some(route) = self.by_route.get_mut(&chain_key) else {
            return;
        };
        let Some(slot) = route.by_message.get_mut(&message_hash) else {
            return;
        };
        slot.in_flight = false;
        slot.delivery_attempts = slot.delivery_attempts.saturating_sub(1);
        slot.next_delivery_attempt_at = Some(now + DELIVERY_CHANNEL_FULL_REQUEUE_DELAY);
        debug!(
            chain_key,
            %message_hash,
            "delivery channel full; requeued for near-term retry (destination busy)"
        );
    }

    /// Publish the current allowlist size of every route (called at startup and after a reload).
    fn report_set_sizes(&self, metrics: &dyn crate::prom::MetricsTrait) {
        for (chain_key, route) in &self.by_route {
            metrics.set_attestor_set_size(*chain_key, route.attestors.len() as i64);
        }
    }

    /// Apply a hot-reloaded attestor set + threshold for one route. Re-evaluates that route's
    /// not-yet-delivered messages against the **new** set/threshold: signatures from signers no
    /// longer in the set stop counting, and a lowered threshold (or a now-sufficient set) can push
    /// an already-collected message over quorum — those are returned as [`DeliveryJob`]s to dispatch.
    fn apply_attestor_set(
        &mut self,
        update: RouteAttestors,
        metrics: &dyn crate::prom::MetricsTrait,
    ) -> Vec<DeliveryJob> {
        let chain_key = update.chain_key;
        let Some(route) = self.by_route.get_mut(&chain_key) else {
            warn!(
                chain_key,
                "attestor-set update for unconfigured chain_key — ignoring"
            );
            return Vec::new();
        };

        let changed = route.attestors != update.attestors || route.threshold != update.threshold;
        route.attestors = update.attestors;
        route.threshold = update.threshold;
        metrics.set_attestor_set_size(chain_key, route.attestors.len() as i64);

        if !changed {
            return Vec::new();
        }
        metrics.inc_attestor_set_reload(chain_key);
        info!(
            chain_key,
            attestors = route.attestors.len(),
            threshold = route.threshold,
            "🔄 attestor set hot-reloaded"
        );

        // Clone the (small) allowlist so we can iterate `by_message` mutably alongside it.
        let attestors = route.attestors.clone();
        let threshold = route.threshold;
        let mut ready = Vec::new();
        for (hash, slot) in route.by_message.iter_mut() {
            if slot.delivered || slot.terminal || slot.in_flight {
                continue;
            }
            slot.signers.retain(|addr, _| attestors.contains(addr));
            if slot.signers.len() < threshold {
                continue;
            }
            let signer_count = slot.signers.len();
            ready.push((*hash, signer_count));
        }

        let mut jobs = Vec::new();
        for (hash, signer_count) in ready {
            info!(
                chain_key,
                %hash,
                signer_count,
                "✅ threshold reached after set reload — dispatching delivery"
            );
            if let Some(job) =
                Self::dispatch_if_ready(chain_key, hash, route, metrics, true, Instant::now())
            {
                jobs.push(job);
            }
        }
        jobs
    }

    /// Find messages stalled below quorum and build a [`ReobservationRequest`] for each, recording
    /// the send time so we don't re-request more than once per [`REOBS_REPEAT_EVERY`]. A message
    /// qualifies once it has been pending [`REOBS_STALL_AFTER`] without reaching threshold.
    fn collect_stalled_reobservations(&mut self, now: Instant) -> Vec<ReobservationRequest> {
        let mut requests = Vec::new();
        for (chain_key, route) in &mut self.by_route {
            let threshold = route.threshold;
            for slot in route.by_message.values_mut() {
                if slot.delivered
                    || slot.terminal
                    || slot.in_flight
                    || slot.signers.len() >= threshold
                {
                    continue;
                }
                if now.duration_since(slot.inserted_at) < REOBS_STALL_AFTER {
                    continue;
                }
                if slot
                    .last_reobs_request
                    .is_some_and(|t| now.duration_since(t) < REOBS_REPEAT_EVERY)
                {
                    continue;
                }
                slot.last_reobs_request = Some(now);
                // info, not debug: a stalled message asking the attestor set to re-sign is a notable
                // liveness event an operator should see, and it is rate-limited so it can't be noisy.
                info!(
                    chain_key,
                    message_id = %slot.indexed.message_id,
                    have = slot.signers.len(),
                    threshold,
                    "📣 requesting reobservation for stalled message"
                );
                requests.push(ReobservationRequest {
                    chain_key: *chain_key,
                    message_id: slot.indexed.message_id.0,
                    tx_hash: slot.indexed.tx_hash.0,
                    block_height: slot.indexed.block_height,
                });
            }
        }
        requests
    }

    /// Build the read-only [`VoteBundle`] for `message_hash`, or `None` if we have not indexed it.
    fn query_bundle(&self, message_hash: &B256) -> Option<VoteBundle> {
        for (chain_key, route) in &self.by_route {
            if let Some(slot) = route.by_message.get(message_hash) {
                return Some(VoteBundle {
                    chain_key: *chain_key,
                    message_id: slot.indexed.message_id,
                    message_hash: *message_hash,
                    threshold: route.threshold,
                    signer_count: slot.signers.len(),
                    delivered: slot.delivered,
                    signers: slot.signers.keys().copied().collect(),
                });
            }
        }
        None
    }
}

impl State {
    fn dispatch_if_ready(
        chain_key: u64,
        hash: B256,
        route: &mut RouteState,
        metrics: &dyn crate::prom::MetricsTrait,
        observe_threshold: bool,
        now: Instant,
    ) -> Option<DeliveryJob> {
        let slot = route.by_message.get_mut(&hash)?;
        if slot.delivered || slot.terminal || slot.in_flight || slot.signers.len() < route.threshold
        {
            return None;
        }
        if slot.next_delivery_attempt_at.is_some_and(|next| now < next) {
            return None;
        }
        slot.in_flight = true;
        slot.delivery_attempts = slot.delivery_attempts.saturating_add(1);
        slot.next_delivery_attempt_at = None;
        let signatures: Vec<[u8; 65]> = slot.signers.values().copied().collect();
        let signer_count = signatures.len();
        let votes_calldata = encode_votes(&signatures);
        if observe_threshold {
            let elapsed = slot.inserted_at.elapsed();
            metrics.observe_votes_per_message(signer_count as u64);
            metrics.observe_time_to_threshold(elapsed);
        }
        Some(DeliveryJob {
            chain_key,
            message_id: slot.indexed.message_id,
            emitter: slot.indexed.emitter,
            outbox: slot.indexed.outbox,
            message_hash: hash,
            payload: slot.indexed.payload.clone(),
            votes_calldata,
            signer_count,
            indexed_at: slot.inserted_at,
        })
    }
}

fn delivery_retry_delay(attempts: u32) -> Duration {
    let shift = attempts.saturating_sub(1).min(4);
    let secs = DELIVERY_RETRY_BASE
        .as_secs()
        .saturating_mul(1u64 << shift)
        .min(DELIVERY_RETRY_MAX.as_secs());
    Duration::from_secs(secs)
}

impl RouteState {
    /// Verify a vote for a not-yet-indexed message and hold it until the message arrives.
    ///
    /// Verification happens *before* buffering, and the entry is keyed on the **recovered**
    /// signer rather than the claimed one. Both matter: buffering unverified votes keyed by a
    /// caller-supplied address would let a forged signature occupy a real attestor's slot and
    /// displace their genuine vote — the same poisoning the indexed path already guards against.
    fn buffer_early_vote(
        &mut self,
        chain_key: u64,
        hash: B256,
        vote: &MessageVote,
        metrics: &dyn crate::prom::MetricsTrait,
    ) {
        let claimed_signer = Address::from(vote.signer);
        if !self.attestors.contains(&claimed_signer) {
            warn!(chain_key, %hash, %claimed_signer,
                "early vote rejected: signer not in attestor allowlist");
            metrics.inc_vote(chain_key, VoteOutcome::Reject);
            return;
        }
        let recovered = match recover_signer(&hash, &vote.signature) {
            Ok(addr) => addr,
            Err(err) => {
                warn!(chain_key, %hash, %err, %claimed_signer,
                    "early vote rejected: signature did not recover");
                metrics.inc_vote(chain_key, VoteOutcome::Reject);
                return;
            }
        };
        if recovered != claimed_signer {
            warn!(chain_key, %hash, %claimed_signer, %recovered,
                "early vote rejected: recovered signer does not match claimed signer");
            metrics.inc_vote(chain_key, VoteOutcome::Reject);
            return;
        }

        let entry = self.early_votes.entry(hash).or_insert_with(|| EarlyVotes {
            signers: BTreeMap::new(),
            first_seen: Instant::now(),
        });
        entry.signers.insert(recovered, vote.signature);
        let held = entry.signers.len();
        self.evict_early_overflow();
        debug!(chain_key, %hash, %recovered, held,
            "buffered early vote for unindexed message");
        metrics.inc_vote(chain_key, VoteOutcome::Buffered);
    }

    /// Bound the number of distinct not-yet-indexed hashes held, oldest first. Per-hash size is
    /// already bounded by the attestor set, since every key is an allowlisted recovered signer.
    ///
    /// Reaching this cap requires an allowlisted attestor's key, because `buffer_early_vote`
    /// applies the allowlist before inserting. So evicting a legitimate buffered vote by flooding
    /// distinct hashes is not open to an arbitrary peer — it costs a compromised attestor, who has
    /// strictly better attacks available. Oldest-first is still the right eviction order: the
    /// oldest unindexed hash is the one least likely to ever be indexed.
    fn evict_early_overflow(&mut self) {
        while self.early_votes.len() > self.cache_max {
            let Some(oldest) = self
                .early_votes
                .iter()
                .min_by_key(|(_, v)| v.first_seen)
                .map(|(k, _)| *k)
            else {
                break;
            };
            self.early_votes.remove(&oldest);
        }
    }

    fn evict_overflow(&mut self) {
        while self.by_message.len() > self.cache_max {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.by_message.remove(&oldest);
        }
    }

    fn prune_expired(&mut self, now: Instant, ttl: Duration) {
        // Evict delivered slots eagerly, and `terminal` slots (genuine reverts) once past the TTL.
        // Undelivered, non-terminal slots are deliberately NOT evicted by age (C1r/C3): a message
        // that reached quorum but has not been delivered — or is still gathering votes — must not
        // silently vanish just because it is slow (the old 30-min TTL evicted exactly the messages a
        // network isolation had starved, ending reobservation for them). They are bounded instead by
        // the count-based LRU (`evict_overflow`), and reobservation keeps driving them toward
        // quorum. Full scan rather than a front-prefix walk, because a retained undelivered slot can
        // sit ahead of reapable ones in insertion order.
        let expired_removable: Vec<B256> = self
            .by_message
            .iter()
            .filter(|(_, slot)| {
                slot.delivered || (slot.terminal && now.duration_since(slot.inserted_at) > ttl)
            })
            .map(|(&hash, _)| hash)
            .collect();
        for hash in expired_removable {
            self.by_message.remove(&hash);
        }
        self.order.retain(|h| self.by_message.contains_key(h));

        // Early votes DO expire by age, unlike indexed slots above. A buffered hash that never
        // gets indexed is not a slow message we owe delivery to — it is a message this route will
        // never see (wrong chain, a rotated-out attestor's stale gossip, or an emitter we do not
        // watch). Holding it forever would be an unbounded sink keyed on attacker-influenced data.
        self.early_votes
            .retain(|_, votes| now.duration_since(votes.first_seen) <= ttl);
    }
}

/// secp256k1 half-order (n/2), big-endian. EOAValidator enforces EIP-2 low-`s` on-chain and
/// rejects any signature whose `s` exceeds this. A high-`s` vote recovers to a valid attestor
/// off-chain but reverts `validateVotes`, so we must apply the same bound before counting a vote.
const SECP256K1_HALF_ORDER_BE: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

pub(crate) fn recover_signer(hash: &B256, raw: &[u8; 65]) -> Result<Address> {
    // Enforce the same canonical-encoding rules EOAValidator applies on-chain (EIP-2) *before*
    // ecrecover. Alloy's parser is more permissive than the contract (it accepts `v` of 0/1 and
    // normalizes high-`s`), so a non-canonical vote can recover to a valid attestor here yet later
    // revert the whole delivery bundle at `validateVotes`. Rejecting here — before `note_vote`'s
    // dedup insert — stops a non-canonical vote from occupying the signer's slot and blocking the
    // canonical vote that would follow (USC-WRITE-ABILITY-004).
    //
    // `v` must be exactly 27 or 28.
    let v = raw[64];
    if v != 27 && v != 28 {
        anyhow::bail!("non-canonical signature: v={v} (only 27/28 accepted)");
    }
    // `s` must be <= the secp256k1 half-order.
    let s = U256::from_be_slice(&raw[32..64]);
    if s > U256::from_be_slice(&SECP256K1_HALF_ORDER_BE) {
        anyhow::bail!("non-canonical signature: high-s value rejected (EIP-2)");
    }

    let sig: Signature = raw[..]
        .try_into()
        .map_err(|e| anyhow::anyhow!("malformed signature bytes: {e}"))?;
    sig.recover_address_from_prehash(hash)
        .map_err(|e| anyhow::anyhow!("ecrecover failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prom::NoopMetrics;
    use alloy::primitives::address;

    fn route_for(chain_key: u64, attestors: Vec<Address>) -> RouteAttestors {
        let threshold = calculate_threshold(attestors.len());
        RouteAttestors {
            chain_key,
            attestors,
            threshold,
        }
    }

    fn indexed_for(chain_key: u64, hash: B256) -> IndexedMessage {
        IndexedMessage {
            chain_key,
            message_id: B256::from([7u8; 32]),
            emitter: address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            outbox: address!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            destination_chain_key: B256::from([0u8; 32]),
            creditcoin_chain_id: 1,
            payload: vec![1, 2, 3],
            message_hash: hash,
            tx_hash: B256::from([0xab; 32]),
            block_height: 99,
        }
    }

    #[test]
    fn threshold_two_thirds_plus_one() {
        assert_eq!(calculate_threshold(1), 1);
        assert_eq!(calculate_threshold(3), 3);
        assert_eq!(calculate_threshold(4), 3);
        assert_eq!(calculate_threshold(7), 5);
        assert_eq!(calculate_threshold(10), 7);
    }

    /// An unverifiable vote for an unindexed message must not even reach the buffer: `[0u8; 65]`
    /// has `v = 0`, which `recover_signer` rejects. Buffering unverified votes would be the
    /// poisoning vector `buffer_early_vote` exists to avoid.
    #[test]
    fn unknown_message_with_unverifiable_vote_is_not_buffered() {
        let route = route_for(
            2,
            vec![address!("000000000000000000000000000000000000000a")],
        );
        let mut state = State::new(vec![route], VoteCacheConfig::default());
        let metrics = NoopMetrics::new();
        let vote = MessageVote {
            chain_key: 2,
            message_id: [7u8; 32],
            message_hash: [1u8; 32],
            signer: [0x0a; 20],
            signature: [0u8; 65],
        };
        assert!(state.note_vote(vote, metrics.as_ref()).is_none());
        assert_eq!(state.total_pending(), 0);
        assert!(
            state.by_route[&2].early_votes.is_empty(),
            "an unverifiable vote must be rejected outright, not buffered"
        );
    }

    // secp256k1 group order N, big-endian — used to build the malleable high-`s` equivalent
    // (`s' = N - s`) of a canonical signature.
    const SECP256K1_N_BE: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    fn test_signer(seed: u8) -> alloy::signers::local::PrivateKeySigner {
        alloy::signers::local::PrivateKeySigner::from_slice(&[seed; 32]).expect("valid key")
    }

    fn canonical_sig(signer: &alloy::signers::local::PrivateKeySigner, hash: &B256) -> [u8; 65] {
        use alloy::signers::SignerSync as _;
        // alloy's k256 signer normalizes `s` to low and encodes `v` as 27/28 — i.e. canonical.
        signer.sign_hash_sync(hash).expect("sign").as_bytes()
    }

    /// The malleable high-`s` equivalent of a canonical signature: `s' = N - s` with the recovery
    /// parity flipped. Recovers to the same signer under a permissive parser, but violates EIP-2.
    fn to_high_s(mut raw: [u8; 65]) -> [u8; 65] {
        let high = U256::from_be_slice(&SECP256K1_N_BE) - U256::from_be_slice(&raw[32..64]);
        raw[32..64].copy_from_slice(&high.to_be_bytes::<32>());
        raw[64] = if raw[64] == 27 { 28 } else { 27 };
        raw
    }

    #[test]
    fn recover_signer_rejects_non_canonical_encodings() {
        let signer = test_signer(0x11);
        let hash = B256::from([0x42u8; 32]);
        let canonical = canonical_sig(&signer, &hash);

        // Sanity: the canonical signature recovers to the signer.
        assert_eq!(recover_signer(&hash, &canonical).unwrap(), signer.address());

        // High-`s` malleable equivalent — recovers to the same signer on a permissive parser but
        // must be rejected here (EOAValidator would revert on it).
        assert!(recover_signer(&hash, &to_high_s(canonical)).is_err());

        // `v` encoded as 0/1 instead of 27/28.
        let mut bad_v = canonical;
        bad_v[64] -= 27;
        assert!(recover_signer(&hash, &bad_v).is_err());
    }

    #[test]
    fn non_canonical_vote_does_not_poison_dedup_slot() {
        let signer = test_signer(0x22);
        let addr = signer.address();
        let mut state = State::new(vec![route_for(2, vec![addr])], VoteCacheConfig::default());
        let metrics = NoopMetrics::new();
        let hash = B256::from([0x07u8; 32]);
        state.note_indexed(indexed_for(2, hash), metrics.as_ref());

        let canonical = canonical_sig(&signer, &hash);
        let high_s = to_high_s(canonical);
        let mk = |sig: [u8; 65]| MessageVote {
            chain_key: 2,
            message_id: [7u8; 32],
            message_hash: hash.0,
            signer: addr.into_array(),
            signature: sig,
        };

        // The non-canonical vote arrives first: rejected, not counted, dedup slot untouched, and
        // the message is not driven terminal.
        assert!(state.note_vote(mk(high_s), metrics.as_ref()).is_none());

        // The canonical vote from the *same* attestor is still accepted and reaches threshold (1),
        // proving the poison did not consume the signer's slot.
        assert!(
            state.note_vote(mk(canonical), metrics.as_ref()).is_some(),
            "canonical vote must be accepted after a non-canonical one from the same signer"
        );
    }

    // ---------------------------------------------------------------------------------------
    // Early-vote buffer. Attestors routinely gossip a vote before our own Outbox watcher has
    // indexed the message (they sign at import; we index at finality). Dropping those votes cost
    // every message a stall-detector round trip: measured on usc-devnet as 233 deliveries against
    // 236 reobservation requests, median time-to-delivery 41s. Buffering removes that round trip
    // from the common path.
    // ---------------------------------------------------------------------------------------

    /// Build a vote as `signer` for `hash`, optionally claiming a different address.
    fn vote_for(
        chain_key: u64,
        hash: B256,
        signer: &alloy::signers::local::PrivateKeySigner,
        claimed: Option<Address>,
    ) -> MessageVote {
        MessageVote {
            chain_key,
            message_id: [7u8; 32],
            message_hash: hash.0,
            signer: claimed.unwrap_or_else(|| signer.address()).into_array(),
            signature: canonical_sig(signer, &hash),
        }
    }

    #[test]
    fn early_votes_are_buffered_then_adopted_when_the_message_is_indexed() {
        let signers: Vec<_> = (0x31u8..=0x33).map(test_signer).collect();
        let addrs: Vec<Address> = signers.iter().map(|s| s.address()).collect();
        let mut state = State::new(vec![route_for(2, addrs)], VoteCacheConfig::default());
        let metrics = NoopMetrics::new();
        let hash = B256::from([0x51u8; 32]);

        // All three votes land before the watcher indexes the message. None can dispatch yet —
        // without an indexed message there is no payload or emitter to deliver.
        for s in &signers {
            assert!(
                state
                    .note_vote(vote_for(2, hash, s, None), metrics.as_ref())
                    .is_none(),
                "a buffered vote cannot dispatch: the message is not indexed yet"
            );
        }
        assert_eq!(state.by_route[&2].early_votes[&hash].signers.len(), 3);
        assert_eq!(state.total_pending(), 0);

        // Indexing adopts them and dispatches immediately, with no reobservation round trip.
        let job = state
            .note_indexed(indexed_for(2, hash), metrics.as_ref())
            .expect("buffered quorum must dispatch on index");
        assert_eq!(job.chain_key, 2);
        assert_eq!(job.message_hash, hash);
        assert!(
            state.by_route[&2].early_votes.is_empty(),
            "adopted votes must be drained out of the buffer"
        );
        assert_eq!(state.by_route[&2].by_message[&hash].signers.len(), 3);
    }

    #[test]
    fn repeated_early_votes_from_one_signer_occupy_one_slot() {
        let signer = test_signer(0x34);
        let mut state = State::new(
            vec![route_for(
                2,
                vec![signer.address(), test_signer(0x35).address()],
            )],
            VoteCacheConfig::default(),
        );
        let metrics = NoopMetrics::new();
        let hash = B256::from([0x52u8; 32]);

        for _ in 0..5 {
            state.note_vote(vote_for(2, hash, &signer, None), metrics.as_ref());
        }
        assert_eq!(state.by_route[&2].early_votes[&hash].signers.len(), 1);

        // One of two attestors is below the threshold of 2, so indexing must not dispatch.
        assert!(state
            .note_indexed(indexed_for(2, hash), metrics.as_ref())
            .is_none());
        assert_eq!(state.by_route[&2].by_message[&hash].signers.len(), 1);
    }

    #[test]
    fn early_vote_from_a_non_attestor_is_not_buffered() {
        let attestor = test_signer(0x36);
        let outsider = test_signer(0x99);
        let mut state = State::new(
            vec![route_for(2, vec![attestor.address()])],
            VoteCacheConfig::default(),
        );
        let metrics = NoopMetrics::new();
        let hash = B256::from([0x53u8; 32]);

        assert!(state
            .note_vote(vote_for(2, hash, &outsider, None), metrics.as_ref())
            .is_none());
        assert!(
            state.by_route[&2].early_votes.is_empty(),
            "the allowlist must be applied before buffering, not after"
        );
    }

    /// The buffered analogue of `non_canonical_vote_does_not_poison_dedup_slot`: a forged vote
    /// claiming an attestor's address must not occupy that attestor's buffered slot, or an attacker
    /// could displace real votes for a message we have not indexed yet — precisely the window the
    /// buffer opens.
    #[test]
    fn forged_early_vote_cannot_occupy_a_real_attestors_buffered_slot() {
        let attestor = test_signer(0x37);
        let attacker = test_signer(0x9a);
        let mut state = State::new(
            vec![route_for(2, vec![attestor.address()])],
            VoteCacheConfig::default(),
        );
        let metrics = NoopMetrics::new();
        let hash = B256::from([0x54u8; 32]);

        // Attacker signs with its own key but claims the attestor's address.
        assert!(state
            .note_vote(
                vote_for(2, hash, &attacker, Some(attestor.address())),
                metrics.as_ref()
            )
            .is_none());
        assert!(
            state.by_route[&2].early_votes.is_empty(),
            "a claimed-signer mismatch must be rejected before it reaches the buffer"
        );

        // The attestor's genuine vote is still accepted and still reaches threshold (1).
        state.note_vote(vote_for(2, hash, &attestor, None), metrics.as_ref());
        assert!(
            state
                .note_indexed(indexed_for(2, hash), metrics.as_ref())
                .is_some(),
            "the genuine vote must survive the forgery attempt"
        );
    }

    #[test]
    fn buffered_vote_from_an_attestor_rotated_out_before_indexing_is_dropped() {
        let old_attestor = test_signer(0x38);
        let new_attestor = test_signer(0x39);
        let mut state = State::new(
            vec![route_for(2, vec![old_attestor.address()])],
            VoteCacheConfig::default(),
        );
        let metrics = NoopMetrics::new();
        let hash = B256::from([0x55u8; 32]);

        state.note_vote(vote_for(2, hash, &old_attestor, None), metrics.as_ref());
        assert_eq!(state.by_route[&2].early_votes[&hash].signers.len(), 1);

        // Rotation lands while the vote is still buffered.
        state.apply_attestor_set(route_for(2, vec![new_attestor.address()]), metrics.as_ref());

        assert!(
            state
                .note_indexed(indexed_for(2, hash), metrics.as_ref())
                .is_none(),
            "a rotated-out attestor's buffered vote must not count toward the new threshold"
        );
        assert!(state.by_route[&2].by_message[&hash].signers.is_empty());
    }

    #[test]
    fn early_vote_buffer_is_bounded_by_the_cache_cap() {
        let signer = test_signer(0x3a);
        let mut state = State::new(
            vec![route_for(2, vec![signer.address()])],
            VoteCacheConfig {
                ttl_seconds: 600,
                max_messages: 2,
            },
        );
        let metrics = NoopMetrics::new();
        for byte in 1u8..=4 {
            let mut h = [0u8; 32];
            h[0] = byte;
            state.note_vote(vote_for(2, B256::from(h), &signer, None), metrics.as_ref());
        }
        assert_eq!(
            state.by_route[&2].early_votes.len(),
            2,
            "distinct unindexed hashes are attacker-influenced, so the buffer must be capped"
        );
    }

    #[test]
    fn early_votes_expire_by_ttl() {
        let signer = test_signer(0x3b);
        let mut state = State::new(
            vec![route_for(2, vec![signer.address()])],
            VoteCacheConfig {
                ttl_seconds: 0,
                max_messages: 128,
            },
        );
        let metrics = NoopMetrics::new();
        let hash = B256::from([0x56u8; 32]);
        state.note_vote(vote_for(2, hash, &signer, None), metrics.as_ref());
        assert_eq!(state.by_route[&2].early_votes.len(), 1);

        state.prune_expired();
        assert!(
            state.by_route[&2].early_votes.is_empty(),
            "a hash that is never indexed must not be held forever"
        );
    }

    #[test]
    fn evicts_when_cap_reached() {
        let route = route_for(
            2,
            vec![address!("000000000000000000000000000000000000000a")],
        );
        let cache = VoteCacheConfig {
            ttl_seconds: 600,
            max_messages: 2,
        };
        let mut state = State::new(vec![route], cache);
        let metrics = NoopMetrics::new();
        for byte in 1u8..=4 {
            let mut h = [0u8; 32];
            h[0] = byte;
            state.note_indexed(indexed_for(2, B256::from(h)), metrics.as_ref());
        }
        assert_eq!(state.total_pending(), 2);
    }

    #[test]
    fn duplicate_indexed_is_idempotent() {
        let route = route_for(
            2,
            vec![address!("000000000000000000000000000000000000000a")],
        );
        let mut state = State::new(vec![route], VoteCacheConfig::default());
        let metrics = NoopMetrics::new();
        let hash = B256::from([1u8; 32]);
        state.note_indexed(indexed_for(2, hash), metrics.as_ref());
        state.note_indexed(indexed_for(2, hash), metrics.as_ref());
        assert_eq!(state.total_pending(), 1);
    }

    /// Seed a slot with `signers` already accepted (bypassing ecrecover) so we can exercise
    /// `apply_attestor_set`'s re-evaluation directly.
    #[test]
    fn oldest_unfinished_blocks_skips_delivered_and_terminal() {
        let metrics = NoopMetrics::new();
        let mut state = State::new(
            vec![route_for(2, vec![])],
            VoteCacheConfig {
                ttl_seconds: 600,
                max_messages: 100,
            },
        );
        // No messages: no holdback.
        assert_eq!(state.oldest_unfinished_blocks(), vec![(2, None)]);

        let mk = |b: u8, height: u64| {
            let mut m = indexed_for(2, B256::from([b; 32]));
            m.block_height = height;
            m
        };
        state.note_indexed(mk(1, 500), metrics.as_ref());
        state.note_indexed(mk(2, 300), metrics.as_ref());
        state.note_indexed(mk(3, 400), metrics.as_ref());
        assert_eq!(state.oldest_unfinished_blocks(), vec![(2, Some(300))]);

        // Delivered and terminal slots release their holdback.
        let route = state.by_route.get_mut(&2).unwrap();
        route
            .by_message
            .get_mut(&B256::from([2u8; 32]))
            .unwrap()
            .delivered = true;
        route
            .by_message
            .get_mut(&B256::from([3u8; 32]))
            .unwrap()
            .terminal = true;
        assert_eq!(state.oldest_unfinished_blocks(), vec![(2, Some(500))]);
    }

    fn seed_slot(state: &mut State, chain_key: u64, hash: B256, signers: &[Address]) {
        let metrics = NoopMetrics::new();
        state.note_indexed(indexed_for(chain_key, hash), metrics.as_ref());
        let slot = state
            .by_route
            .get_mut(&chain_key)
            .unwrap()
            .by_message
            .get_mut(&hash)
            .unwrap();
        for (i, a) in signers.iter().enumerate() {
            slot.signers.insert(*a, [i as u8 + 1; 65]);
        }
    }

    #[test]
    fn set_reload_lower_threshold_dispatches_pending() {
        let (a, b, c) = (
            Address::from([0xa; 20]),
            Address::from([0xb; 20]),
            Address::from([0xc; 20]),
        );
        let mut state = State::new(
            vec![RouteAttestors {
                chain_key: 2,
                attestors: vec![a, b, c],
                threshold: 3,
            }],
            VoteCacheConfig::default(),
        );
        let hash = B256::from([1u8; 32]);
        seed_slot(&mut state, 2, hash, &[a, b]); // 2 signers, below threshold 3 → not delivered

        // Threshold drops to 2: the already-collected slot now clears quorum and must dispatch.
        let jobs = state.apply_attestor_set(
            RouteAttestors {
                chain_key: 2,
                attestors: vec![a, b, c],
                threshold: 2,
            },
            NoopMetrics::new().as_ref(),
        );
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].signer_count, 2);
    }

    #[test]
    fn set_reload_removing_signer_revokes_its_vote() {
        let (a, b, c) = (
            Address::from([0xa; 20]),
            Address::from([0xb; 20]),
            Address::from([0xc; 20]),
        );
        let mut state = State::new(
            vec![RouteAttestors {
                chain_key: 2,
                attestors: vec![a, b, c],
                threshold: 3,
            }],
            VoteCacheConfig::default(),
        );
        let hash = B256::from([1u8; 32]);
        seed_slot(&mut state, 2, hash, &[a, b]);

        // Remove `b` and require 2: only `a` still counts (1 < 2), so nothing dispatches and the
        // slot stays open.
        let jobs = state.apply_attestor_set(
            RouteAttestors {
                chain_key: 2,
                attestors: vec![a, c],
                threshold: 2,
            },
            NoopMetrics::new().as_ref(),
        );
        assert!(jobs.is_empty());
        let slot = state
            .by_route
            .get(&2)
            .unwrap()
            .by_message
            .get(&hash)
            .unwrap();
        assert!(!slot.delivered);
    }

    #[test]
    fn stalled_message_yields_one_request_then_respects_cooldown() {
        let a = address!("000000000000000000000000000000000000000a");
        let mut state = State::new(
            vec![route_for(2, vec![a, a, a])],
            VoteCacheConfig::default(),
        );
        // route_for sets threshold = calculate_threshold(3) = 3.
        let hash = B256::from([1u8; 32]);
        seed_slot(&mut state, 2, hash, &[a]); // 1 signer, below threshold 3

        let t0 = Instant::now();
        // Before the stall window: nothing.
        assert!(state.collect_stalled_reobservations(t0).is_empty());

        // Past the stall window: exactly one request, carrying the indexed tx pointer.
        let after = t0 + REOBS_STALL_AFTER + Duration::from_secs(1);
        let reqs = state.collect_stalled_reobservations(after);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].chain_key, 2);
        assert_eq!(reqs[0].block_height, 99);

        // Immediately again: cooldown suppresses it.
        assert!(state.collect_stalled_reobservations(after).is_empty());
        // After the repeat interval: requested again.
        let later = after + REOBS_REPEAT_EVERY + Duration::from_secs(1);
        assert_eq!(state.collect_stalled_reobservations(later).len(), 1);
    }

    #[test]
    fn delivered_or_quorum_message_is_not_reobserved() {
        let a = address!("000000000000000000000000000000000000000a");
        let mut state = State::new(vec![route_for(2, vec![a])], VoteCacheConfig::default());
        // Single attestor → threshold 1, so one seeded signer already meets quorum.
        let hash = B256::from([2u8; 32]);
        seed_slot(&mut state, 2, hash, &[a]);
        let after = Instant::now() + REOBS_STALL_AFTER + Duration::from_secs(1);
        assert!(
            state.collect_stalled_reobservations(after).is_empty(),
            "a message at/above quorum must not be reobserved"
        );
    }

    #[test]
    fn query_bundle_reports_accumulated_signers() {
        let (a, b) = (
            address!("000000000000000000000000000000000000000a"),
            address!("000000000000000000000000000000000000000b"),
        );
        let mut state = State::new(vec![route_for(2, vec![a, b])], VoteCacheConfig::default());
        let hash = B256::from([3u8; 32]);
        seed_slot(&mut state, 2, hash, &[a]);

        let bundle = state.query_bundle(&hash).expect("indexed message present");
        assert_eq!(bundle.chain_key, 2);
        assert_eq!(bundle.signer_count, 1);
        assert!(!bundle.delivered);
        assert_eq!(bundle.signers, vec![a]);

        assert!(
            state.query_bundle(&B256::from([0xff; 32])).is_none(),
            "unknown hash returns None"
        );
    }

    #[test]
    fn set_reload_no_change_is_noop() {
        let a = Address::from([0xa; 20]);
        let mut state = State::new(
            vec![RouteAttestors {
                chain_key: 2,
                attestors: vec![a],
                threshold: 1,
            }],
            VoteCacheConfig::default(),
        );
        let jobs = state.apply_attestor_set(
            RouteAttestors {
                chain_key: 2,
                attestors: vec![a],
                threshold: 1,
            },
            NoopMetrics::new().as_ref(),
        );
        assert!(jobs.is_empty());
    }
}
