//! Bounded pending-transaction tracking shared by the proof submitters (ack, claim).
//!
//! Each submitter discovers source/destination transactions it must eventually prove and submit,
//! and drives them through retry states: due now, deferred (proof not attested yet), or backing
//! off after transient failures. The queue is bounded so a prolonged proof-gen outage cannot grow
//! memory without limit — on overflow the oldest entry is evicted (and logged by the caller).

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use alloy::primitives::B256;

/// Exponential backoff for *transient* submit failures (RPC down, timeout, nonce). Doubles from
/// the base per failed attempt, capped. Callers layer their own give-up budget on top so a
/// permanently failing submit (e.g. unfunded signer) does not hammer the RPC forever.
pub const TRANSIENT_BACKOFF_BASE: Duration = Duration::from_secs(30);
pub const TRANSIENT_BACKOFF_MAX: Duration = Duration::from_secs(10 * 60);

/// Retry schedule for a proof that proof-gen cannot serve *yet* (`ProofFetch::NotReady`: the
/// destination block is not attested, or proof-gen's view of the destination chain has not caught
/// up with the tx). This is the normal early state of every ack, not a failure, so it must not
/// take the transient backoff: on usc-devnet (2026-09-08) four 404s on one delivery, each backed
/// off as an error (30 s doubling), landed the ack 17 minutes after delivery — four of them pure
/// backoff after the proof had already become available.
///
/// The schedule is a pure function of how long the tx has been waiting since it was first seen:
/// a fixed short `poll_interval` for the first `poll_window`, then the same 30 s → 10 min
/// exponential shape as the transient backoff (derived from the time past the window, so no
/// attempt counter is needed) so a proof that never appears — a tx hash that does not exist, a
/// block that is never attested — does not hot-loop until the caller's age give-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotReadyPolicy {
    /// Re-poll cadence while the tx has been waiting less than `poll_window`. Must be non-zero
    /// (the config layer rejects 0).
    pub poll_interval: Duration,
    /// How long, since the tx was first seen, to keep the fixed cadence before sliding into the
    /// slow backoff.
    pub poll_window: Duration,
}

impl NotReadyPolicy {
    /// Delay until the next attempt for a tx that has been waiting `waited` (since first seen)
    /// and was just answered "not ready".
    pub fn next_delay(&self, waited: Duration) -> Duration {
        if waited < self.poll_window {
            return self.poll_interval;
        }
        // Past the window: 30 s, 60 s, 120 s, … capped at 10 min, chosen from how far past the
        // window we are. Consecutive polls at these delays reproduce the doubling sequence
        // exactly (cumulative excess 0, 30, 90, 210, 450, 930 s), without a per-tx counter.
        let excess = waited.saturating_sub(self.poll_window);
        let steps = excess.as_secs() / TRANSIENT_BACKOFF_BASE.as_secs().max(1) + 1;
        let exp = steps.ilog2().min(31);
        TRANSIENT_BACKOFF_BASE
            .saturating_mul(2u32.saturating_pow(exp))
            .min(TRANSIENT_BACKOFF_MAX)
    }
}

/// One tracked tx awaiting proof + submission.
struct PendingTx {
    /// When the tx was first observed — drives cap eviction and the caller's max-age cutoff.
    first_seen: Instant,
    /// Block the tx was discovered in. Anchors the checkpoint holdback: the persisted discovery
    /// cursor is clamped to `oldest_pending_block - 1` so a restart always rescans (and therefore
    /// re-discovers) every tx that was still pending when the process died — no matter how long it
    /// had been pending. Without this, the cursor advanced at enqueue and the memory-only pending
    /// set was protected only by the fixed lookback window; anything pending longer than that
    /// window at the moment of a restart was silently lost forever.
    block: u64,
    /// Earliest next attempt (not-ready deferral or transient backoff).
    next_attempt_at: Instant,
    /// Transient submit failures so far (not-ready deferrals do not count).
    transient_attempts: u32,
    /// Submitter-specific 32-byte metadata decoded from the tx's logs at discovery time
    /// (ack: delivered messageIds; claim: `claimed`-mapping keys). Drives cheap pre-checks
    /// before any proof is fetched.
    meta: Vec<B256>,
}

/// Tx hashes awaiting submission, bounded by `cap`. Retried oldest-first; on overflow the oldest
/// entry is evicted (a tx we give up on) so the queue cannot grow without limit.
pub struct PendingTxs {
    seen: HashMap<B256, PendingTx>,
    cap: usize,
}

impl PendingTxs {
    pub fn new(cap: usize) -> Self {
        Self {
            seen: HashMap::new(),
            cap,
        }
    }

    pub fn contains(&self, tx: &B256) -> bool {
        self.seen.contains_key(tx)
    }

    /// How many txs are currently tracked, whether or not their retry time has come.
    ///
    /// Exported so the caller can publish it as a gauge: a settlement queue that never drains is
    /// the exact shape of a silent settlement outage, and it is invisible in the per-outcome
    /// counters because a tx whose proof fetch keeps failing is re-deferred rather than resolved.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    pub fn remove(&mut self, tx: &B256) {
        self.seen.remove(tx);
    }

    /// How long `tx` has been tracked, or `None` if unknown.
    pub fn age(&self, tx: &B256, now: Instant) -> Option<Duration> {
        self.seen
            .get(tx)
            .map(|e| now.saturating_duration_since(e.first_seen))
    }

    /// The lowest discovery block among still-pending txs, or `None` when nothing is pending.
    /// The caller clamps its *persisted* checkpoint to `min(cursor, this - 1)` so restart-recovery
    /// (checkpoint rescan) covers every unfinished tx; the in-memory cursor keeps advancing so the
    /// live scan never re-reads. Completed / given-up txs are removed from `seen` and release the
    /// holdback automatically.
    pub fn oldest_pending_block(&self) -> Option<u64> {
        self.seen.values().map(|e| e.block).min()
    }

    /// Track a newly-observed tx (no-op if already tracked). `block` is the chain height the tx was
    /// discovered at (see [`Self::oldest_pending_block`]). Returns the tx hash evicted to honour
    /// the cap, if any — the caller logs it as a tracked tx being abandoned.
    pub fn insert(&mut self, tx: B256, now: Instant, block: u64, meta: Vec<B256>) -> Option<B256> {
        if self.seen.contains_key(&tx) {
            return None;
        }
        self.seen.insert(
            tx,
            PendingTx {
                first_seen: now,
                block,
                next_attempt_at: now,
                transient_attempts: 0,
                meta,
            },
        );
        if self.seen.len() > self.cap {
            if let Some((&oldest, _)) = self.seen.iter().min_by_key(|(_, e)| e.first_seen) {
                self.seen.remove(&oldest);
                return Some(oldest);
            }
        }
        None
    }

    /// Append another metadata entry to an already-tracked tx (a tx may emit several relevant
    /// logs, discovered across scans).
    pub fn note_meta(&mut self, tx: &B256, item: B256) {
        if let Some(entry) = self.seen.get_mut(tx) {
            if !entry.meta.contains(&item) {
                entry.meta.push(item);
            }
        }
    }

    /// The oldest `n` tx hashes whose next attempt is due, oldest-first, with their metadata.
    pub fn ready(&self, n: usize, now: Instant) -> Vec<(B256, Vec<B256>)> {
        let mut entries: Vec<(B256, Instant, Vec<B256>)> = self
            .seen
            .iter()
            .filter(|(_, e)| e.next_attempt_at <= now)
            .map(|(&h, e)| (h, e.first_seen, e.meta.clone()))
            .collect();
        entries.sort_by_key(|&(_, first_seen, _)| first_seen);
        entries
            .into_iter()
            .take(n)
            .map(|(h, _, meta)| (h, meta))
            .collect()
    }

    /// Defer the next attempt for `tx` (proof not ready — not a failure).
    pub fn defer(&mut self, tx: &B256, until: Instant) {
        if let Some(entry) = self.seen.get_mut(tx) {
            entry.next_attempt_at = until;
        }
    }

    /// Record a transient submit failure: bump the attempt counter and schedule the next try with
    /// exponential backoff. Returns the attempts so far so the caller can enforce its budget.
    pub fn record_transient_failure(&mut self, tx: &B256, now: Instant) -> u32 {
        let Some(entry) = self.seen.get_mut(tx) else {
            return 0;
        };
        entry.transient_attempts += 1;
        let exp = entry.transient_attempts.saturating_sub(1).min(31);
        let backoff = TRANSIENT_BACKOFF_BASE
            .saturating_mul(2u32.saturating_pow(exp))
            .min(TRANSIENT_BACKOFF_MAX);
        entry.next_attempt_at = now + backoff;
        entry.transient_attempts
    }
}

/// A FIFO set of fixed capacity: insertion past `cap` evicts the oldest entry. Used to remember
/// recently-finished tx hashes for in-session dedup without leaking memory over long uptimes.
pub struct BoundedSeen {
    set: HashSet<B256>,
    order: VecDeque<B256>,
    cap: usize,
}

impl BoundedSeen {
    pub fn new(cap: usize) -> Self {
        Self {
            set: HashSet::new(),
            order: VecDeque::new(),
            cap,
        }
    }

    pub fn contains(&self, tx: &B256) -> bool {
        self.set.contains(tx)
    }

    pub fn insert(&mut self, tx: B256) {
        if self.set.insert(tx) {
            self.order.push_back(tx);
            if self.set.len() > self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(n: u8) -> B256 {
        B256::from([n; 32])
    }

    /// `ready(..)` tx hashes only, for FIFO assertions.
    fn ready_txs(p: &PendingTxs, n: usize, now: Instant) -> Vec<B256> {
        p.ready(n, now).into_iter().map(|(h, _)| h).collect()
    }

    #[test]
    fn pending_dedupes_and_reports_no_eviction_under_cap() {
        let mut p = PendingTxs::new(4);
        let now = Instant::now();
        assert!(p.insert(tx(1), now, 10, vec![tx(9)]).is_none());
        assert!(p.contains(&tx(1)));
        // Re-inserting the same tx is a no-op (no eviction, still tracked once).
        assert!(p.insert(tx(1), now, 10, vec![tx(9)]).is_none());
        assert_eq!(ready_txs(&p, 10, now), vec![tx(1)]);
        // The metadata rides along for the pre-checks.
        assert_eq!(p.ready(10, now)[0].1, vec![tx(9)]);
        // note_meta appends without duplicating.
        p.note_meta(&tx(1), tx(9));
        p.note_meta(&tx(1), tx(8));
        assert_eq!(p.ready(10, now)[0].1, vec![tx(9), tx(8)]);
    }

    #[test]
    fn pending_evicts_oldest_on_overflow() {
        let mut p = PendingTxs::new(2);
        let t0 = Instant::now();
        // Distinct, increasing timestamps so "oldest" is unambiguous.
        assert!(p.insert(tx(1), t0, 10, Vec::new()).is_none());
        assert!(p
            .insert(tx(2), t0 + Duration::from_millis(1), 11, Vec::new())
            .is_none());
        // Third insert exceeds cap → evicts tx(1), the oldest.
        let evicted = p.insert(tx(3), t0 + Duration::from_millis(2), 12, Vec::new());
        assert_eq!(evicted, Some(tx(1)));
        assert!(!p.contains(&tx(1)));
        assert!(p.contains(&tx(2)));
        assert!(p.contains(&tx(3)));
    }

    #[test]
    fn pending_ready_is_fifo_and_bounded_by_n() {
        let mut p = PendingTxs::new(100);
        let t0 = Instant::now();
        for i in 0..5u8 {
            p.insert(
                tx(i),
                t0 + Duration::from_millis(u64::from(i)),
                100 + u64::from(i),
                Vec::new(),
            );
        }
        let now = t0 + Duration::from_secs(1);
        assert_eq!(ready_txs(&p, 3, now), vec![tx(0), tx(1), tx(2)]);
        p.remove(&tx(0));
        assert_eq!(ready_txs(&p, 3, now), vec![tx(1), tx(2), tx(3)]);
    }

    #[test]
    fn pending_defer_and_backoff_gate_readiness() {
        let mut p = PendingTxs::new(10);
        let t0 = Instant::now();
        p.insert(tx(1), t0, 10, Vec::new());
        assert_eq!(ready_txs(&p, 10, t0), vec![tx(1)]);

        // Not-ready deferral: hidden until `until`, no attempt counted.
        let defer_until = t0 + Duration::from_secs(15);
        p.defer(&tx(1), defer_until);
        assert!(ready_txs(&p, 10, t0).is_empty());
        assert_eq!(ready_txs(&p, 10, defer_until), vec![tx(1)]);

        // Transient failures back off exponentially: 30s, 60s, 120s, … capped at 10min.
        assert_eq!(p.record_transient_failure(&tx(1), t0), 1);
        assert!(ready_txs(&p, 10, t0 + TRANSIENT_BACKOFF_BASE - Duration::from_secs(1)).is_empty());
        assert_eq!(ready_txs(&p, 10, t0 + TRANSIENT_BACKOFF_BASE), vec![tx(1)]);
        assert_eq!(p.record_transient_failure(&tx(1), t0), 2);
        assert!(ready_txs(&p, 10, t0 + TRANSIENT_BACKOFF_BASE).is_empty());
        assert_eq!(
            ready_txs(&p, 10, t0 + TRANSIENT_BACKOFF_BASE * 2),
            vec![tx(1)]
        );
        // Deep attempt counts saturate at the cap instead of overflowing.
        for _ in 0..40 {
            p.record_transient_failure(&tx(1), t0);
        }
        assert_eq!(ready_txs(&p, 10, t0 + TRANSIENT_BACKOFF_MAX), vec![tx(1)]);

        // Age is measured from first_seen, unaffected by deferrals.
        assert_eq!(
            p.age(&tx(1), t0 + Duration::from_secs(5)),
            Some(Duration::from_secs(5))
        );
        assert_eq!(p.age(&tx(2), t0), None);
    }

    /// Inside the window the cadence is flat — no growth, no attempt counting — so a proof that
    /// becomes available is picked up within one `poll_interval`, not after a doubled backoff.
    #[test]
    fn not_ready_policy_polls_flat_inside_the_window() {
        let policy = NotReadyPolicy {
            poll_interval: Duration::from_secs(20),
            poll_window: Duration::from_secs(30 * 60),
        };
        for waited_secs in [0u64, 20, 400, 6 * 60 + 38, 29 * 60 + 59] {
            assert_eq!(
                policy.next_delay(Duration::from_secs(waited_secs)),
                Duration::from_secs(20),
                "waited {waited_secs}s must still be on the flat cadence"
            );
        }
        // The observed devnet case: four "not ready" answers over ~6 min, then the proof exists.
        // Flat polling bounds the extra latency after availability to one interval.
        let mut waited = Duration::ZERO;
        let mut polls = 0;
        while waited < Duration::from_secs(13 * 60) {
            waited += policy.next_delay(waited);
            polls += 1;
        }
        assert_eq!(polls, 39, "13 min of not-ready at 20 s is 39 polls");
    }

    /// Past the window the delays reproduce the transient backoff shape, 30 s doubling to a 10 min
    /// cap, so a proof that never appears cannot hot-loop until the caller's age give-up.
    #[test]
    fn not_ready_policy_backs_off_past_the_window() {
        let window = Duration::from_secs(30 * 60);
        let policy = NotReadyPolicy {
            poll_interval: Duration::from_secs(20),
            poll_window: window,
        };
        let mut waited = window;
        let mut delays = Vec::new();
        for _ in 0..8 {
            let d = policy.next_delay(waited);
            delays.push(d.as_secs());
            waited += d;
        }
        assert_eq!(delays, vec![30, 60, 120, 240, 480, 600, 600, 600]);
        // Monotone non-decreasing everywhere past the window, and never below the base.
        let mut last = Duration::ZERO;
        for excess_secs in (0..3600).step_by(7) {
            let d = policy.next_delay(window + Duration::from_secs(excess_secs));
            assert!(d >= TRANSIENT_BACKOFF_BASE && d <= TRANSIENT_BACKOFF_MAX);
            assert!(d >= last, "delay must not shrink as waiting grows");
            last = d;
        }
    }

    /// A zero window disables the fast poll entirely (straight to the slow backoff); a very long
    /// window keeps the flat cadence for as long as the caller's age give-up allows.
    #[test]
    fn not_ready_policy_window_edges() {
        let interval = Duration::from_secs(25);
        let none = NotReadyPolicy {
            poll_interval: interval,
            poll_window: Duration::ZERO,
        };
        assert_eq!(none.next_delay(Duration::ZERO), TRANSIENT_BACKOFF_BASE);
        let forever = NotReadyPolicy {
            poll_interval: interval,
            poll_window: Duration::MAX,
        };
        assert_eq!(forever.next_delay(Duration::from_secs(48 * 3600)), interval);
    }

    #[test]
    fn oldest_pending_block_tracks_min_and_releases() {
        let mut p = PendingTxs::new(10);
        let t0 = Instant::now();
        assert_eq!(p.oldest_pending_block(), None);
        p.insert(tx(1), t0, 500, Vec::new());
        p.insert(tx(2), t0, 300, Vec::new());
        p.insert(tx(3), t0, 400, Vec::new());
        assert_eq!(p.oldest_pending_block(), Some(300));
        // Completing the oldest releases the holdback to the next-oldest.
        p.remove(&tx(2));
        assert_eq!(p.oldest_pending_block(), Some(400));
        p.remove(&tx(3));
        p.remove(&tx(1));
        assert_eq!(p.oldest_pending_block(), None);
    }

    #[test]
    fn bounded_seen_is_fifo_capped() {
        let mut s = BoundedSeen::new(2);
        s.insert(tx(1));
        s.insert(tx(1)); // idempotent
        s.insert(tx(2));
        s.insert(tx(3)); // evicts tx(1)
        assert!(!s.contains(&tx(1)));
        assert!(s.contains(&tx(2)));
        assert!(s.contains(&tx(3)));
    }
}
