//! Attestor-set-update aggregator + submitter (write-ability P2-8, relayer half).
//!
//! Attestors gossip [`SetUpdateVote`]s on `{chain_key}/attestor-set-update/v1` when the elected set
//! diverges from the destination `EOAValidator`'s current set. This task snoops those votes (fed in
//! over `vote_rx` by the p2p task), aggregates a threshold of valid signatures over a given
//! `(newAttestors, nonce)`, and submits `submitAttestorSetUpdate(newAttestors, signatures)` on the
//! validator — reusing the same signer/provider/encoding as message delivery.
//!
//! Mirrors the message-vote pool's validation exactly: the same `recover_signer` (EIP-2 canonical
//! checks matching `EOAValidator._recoverChecked`), the same allowlist-then-recover-then-dedup
//! order, the same `encode_votes` calldata. The only structural difference is that votes are keyed
//! by the **update digest** (which uniquely binds `(newAttestors, nonce)`), and there is no
//! source-chain pre-indexing — the relayer recomputes the digest itself from the envelope and only
//! aggregates votes whose nonce matches the validator's current `attestorSetUpdateNonce`.
//!
//! Runs only for routes whose attestor set is sourced on-chain (`AttestorSet::OnChain { Evm }`) and
//! that have a `signer_key` (to pay gas — submission is permissionless, authority is in the sigs).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use write_ability::abi::IVoteValidator;
use write_ability::envelope::SetUpdateVote;
use write_ability::hash::{attestor_set_update_digest, canonical_attestor_order};

use crate::config::{AttestorSet, AttestorSource, ChainRoute};
use crate::delivery::encode::encode_votes;
use crate::pool::recover_signer;

/// How often to refresh each route's on-chain view (current attestor set, threshold, nonce, and
/// chain id). Set changes are rare, so a slow poll keeps RPC load negligible.
const REFRESH_SECS: u64 = 60;

/// Upper bound on a single `submitAttestorSetUpdate` broadcast. Alloy's HTTP transport sets no
/// timeout, so a black-holed destination RPC would otherwise park this task's vote branch — and with
/// it the aggregator's refresh tick and cancel branch — indefinitely. Also bounds how long one
/// submission can hold the signer's broadcast slot, which the route's delivery worker shares.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// The validator's current state a set-update vote is validated against.
#[derive(Clone)]
struct OnChain {
    attestors: HashSet<Address>,
    threshold: usize,
    nonce: U256,
    chain_id: U256,
}

/// Per-route aggregation state.
struct RouteState {
    validator: Address,
    signer_key: String,
    dest_rpc_url: String,
    /// `None` until the first successful on-chain refresh.
    current: Option<OnChain>,
    /// digest → recovered signer → signature. One slot per distinct `(newAttestors, nonce)`.
    votes: HashMap<B256, BTreeMap<Address, [u8; 65]>>,
    /// Digests for which a `submitAttestorSetUpdate` tx has been broadcast at the current nonce and
    /// not yet confirmed mined. Guards against a duplicate submit if the slot rebuilds to threshold
    /// again in the send→mine window (review #3): we skip re-submitting an in-flight digest. Cleared
    /// on the next `refresh` when the on-chain nonce advances (the update mined) — a fresh nonce
    /// yields fresh digests anyway, so this can never wedge a genuine later update.
    in_flight: HashSet<B256>,
}

/// Validate a vote against the validator's current state, returning the canonical attestor order,
/// the update digest, and the recovered signer if (and only if) the vote is aggregatable: nonce
/// matches, the signature is canonical + recovers over the digest, and the signer is a current
/// attestor. Pure (no I/O) so the aggregation rules are unit-testable.
///
/// `validator` comes from local route config, never from the vote: the contract binds its own
/// address into the preimage, and trusting a peer-supplied address would let anyone redirect
/// aggregation at an arbitrary contract.
fn verify_vote(
    vote: &SetUpdateVote,
    validator: Address,
    current: &OnChain,
) -> Option<(Vec<Address>, B256, Address)> {
    let nonce = U256::from_be_bytes(vote.nonce);
    if nonce != current.nonce {
        // Stale (an update already landed) or ahead of what we've observed — not aggregatable now.
        return None;
    }
    let proposed: Vec<Address> = vote
        .new_attestors
        .iter()
        .map(|a| Address::from(*a))
        .collect();
    // Recompute the digest over the CANONICAL order — the exact bytes the attestor signed. A vote
    // whose array isn't canonical simply won't recover to a current attestor and is dropped.
    let canonical = canonical_attestor_order(&proposed);
    let digest = attestor_set_update_digest(validator, &canonical, current.chain_id, nonce);
    let signer = recover_signer(&digest, &vote.signature).ok()?;
    if !current.attestors.contains(&signer) {
        return None;
    }
    Some((canonical, digest, signer))
}

/// Health component key for one route's aggregator progress. Keyed per route — matching
/// `delivery:{chain_key}` and `attestor-set:{chain_key}` — so a healthy route's beat cannot mask a
/// route whose refresh always fails.
fn health_key(chain_key: u64) -> String {
    format!("attestor-set-update:{chain_key}")
}

/// Refresh a route's on-chain view. Best-effort; a failure leaves the previous view in place.
async fn refresh(state: &mut RouteState) -> Result<()> {
    let provider = ProviderBuilder::new()
        .connect(&state.dest_rpc_url)
        .await
        .with_context(|| format!("connect destination RPC {}", state.dest_rpc_url))?;
    let contract = IVoteValidator::new(state.validator, &provider);

    let attestors: HashSet<Address> = contract.attestors().call().await?.into_iter().collect();
    let threshold = contract.threshold().call().await?.saturating_to::<usize>();
    let nonce = contract.attestorSetUpdateNonce().call().await?;
    let chain_id = U256::from(provider.get_chain_id().await?);

    // If the nonce advanced, any accumulated votes are for a spent update — drop them, and clear the
    // in-flight guard (a mined update bumps the nonce; the old digests are now permanently invalid).
    if state.current.as_ref().is_some_and(|c| c.nonce != nonce) {
        state.votes.clear();
        state.in_flight.clear();
    }
    state.current = Some(OnChain {
        attestors,
        threshold,
        nonce,
        chain_id,
    });
    Ok(())
}

/// Submit `submitAttestorSetUpdate` with the aggregated signatures. Reuses the delivery signer +
/// `encode_votes` calldata format (identical `abi.encode(bytes[])`).
async fn submit(
    state: &RouteState,
    broadcast_locks: &Arc<crate::broadcast::BroadcastLocks>,
    new_attestors: &[Address],
    signatures: &[[u8; 65]],
) -> Result<()> {
    let signer: PrivateKeySigner = state
        .signer_key
        .trim()
        .parse()
        .context("invalid signer_key for set-update submission")?;
    let submitter_address = signer.address();
    // A fresh provider per submission would read the nonce from the chain anyway (an empty cached
    // counter has nothing to go stale), but that is incidental — build it explicitly chain-read so
    // this does not silently depend on staying short-lived. What actually matters here is the
    // broadcast lock: this signer is `route.signer_key`, the *same* key the route's delivery worker
    // signs with, and the two providers have no shared nonce state at all. Without serializing on the
    // address, a submission and a delivery can read the same pending nonce and one of them is lost.
    let provider = crate::broadcast::chain_nonce_builder()
        .wallet(EthereumWallet::from(signer))
        .connect(&state.dest_rpc_url)
        .await
        .with_context(|| format!("connect destination RPC {}", state.dest_rpc_url))?;
    let contract = IVoteValidator::new(state.validator, &provider);
    let calldata = Bytes::from(encode_votes(signatures));

    // Simulate first (mirrors delivery) so a guaranteed revert doesn't burn gas.
    contract
        .submitAttestorSetUpdate(new_attestors.to_vec(), calldata.clone())
        .call()
        .await
        .context("simulate(submitAttestorSetUpdate) reverted")?;

    let pending = broadcast_locks
        .broadcast(
            submitter_address,
            SEND_TIMEOUT,
            contract
                .submitAttestorSetUpdate(new_attestors.to_vec(), calldata)
                .send(),
        )
        .await
        .map_err(|stalled| anyhow::anyhow!("submit(submitAttestorSetUpdate) {stalled}"))?
        .context("submit(submitAttestorSetUpdate) failed")?;
    info!(tx = %pending.tx_hash(), attestors = new_attestors.len(), "🗳️ submitted attestor-set update");
    Ok(())
}

/// Handle one incoming vote: validate, dedup, and submit on threshold.
async fn handle_vote(
    states: &mut HashMap<u64, RouteState>,
    broadcast_locks: &Arc<crate::broadcast::BroadcastLocks>,
    vote: SetUpdateVote,
) {
    let Some(state) = states.get_mut(&vote.chain_key) else {
        return;
    };
    let Some(current) = state.current.clone() else {
        debug!(
            chain_key = vote.chain_key,
            "set-update vote before on-chain view is ready — dropping"
        );
        return;
    };
    let Some((canonical, digest, signer)) = verify_vote(&vote, state.validator, &current) else {
        debug!(
            chain_key = vote.chain_key,
            "set-update vote failed validation — dropping"
        );
        return;
    };

    // Already broadcast a tx for this exact (newAttestors, nonce) — don't send a duplicate while it
    // is still mining (review #3). Cleared when the nonce advances (refresh) — i.e. once it mined.
    if state.in_flight.contains(&digest) {
        return;
    }

    let slot = state.votes.entry(digest).or_default();
    if slot.insert(signer, vote.signature).is_some() {
        return; // duplicate signer
    }
    if slot.len() < current.threshold {
        return;
    }

    // Threshold reached — submit. Snapshot the signatures, clear the slot, and mark the digest
    // in-flight so a rebuild-to-threshold in the send→mine window doesn't double-submit. On failure,
    // drop the in-flight mark so the next votes can retry.
    let signatures: Vec<[u8; 65]> = slot.values().copied().collect();
    state.votes.remove(&digest);
    state.in_flight.insert(digest);
    match submit(state, broadcast_locks, &canonical, &signatures).await {
        Ok(()) => {}
        Err(err) => {
            state.in_flight.remove(&digest);
            warn!(chain_key = vote.chain_key, %err, "attestor-set update submission failed — will retry as more votes arrive");
        }
    }
}

/// Run the aggregator+submitter for all eligible routes until `cancel` fires.
pub async fn run(
    routes: Vec<ChainRoute>,
    mut vote_rx: mpsc::Receiver<SetUpdateVote>,
    health: Arc<crate::health::Health>,
    broadcast_locks: Arc<crate::broadcast::BroadcastLocks>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut states: HashMap<u64, RouteState> = HashMap::new();
    for route in &routes {
        // Only on-chain-sourced sets have a validator to update; only routes with a signer can pay
        // for submission.
        if let AttestorSet::OnChain {
            source: AttestorSource::Evm { address },
        } = &route.attestor_set
        {
            let Some(signer_key) = route.signer_key.clone() else {
                warn!(
                    chain_key = route.chain_key,
                    "attestor-set-update: on-chain set but no signer_key — skipping route"
                );
                continue;
            };
            states.insert(
                route.chain_key,
                RouteState {
                    validator: *address,
                    signer_key,
                    dest_rpc_url: route.destination_rpc_url.clone(),
                    current: None,
                    votes: HashMap::new(),
                    in_flight: HashSet::new(),
                },
            );
        }
    }

    if states.is_empty() {
        info!("attestor-set-update: no eligible routes — task idle");
        cancel.cancelled().await;
        return Ok(());
    }
    info!(
        routes = states.len(),
        "🗳️ attestor-set-update aggregator online"
    );

    // Register with the health watchdog, one component per route. This worker previously registered
    // nothing at all, and `Health::status` only inspects components that have registered — so a wedged
    // aggregator (the RPC awaits in `refresh`/`submit` are unbounded) was invisible and `/health`
    // reported 200 while on-chain attestor-set rotations silently stopped applying. Registered *after*
    // the `states.is_empty()` return above, since that path deliberately parks forever with no work to
    // report on. `REFRESH_SECS` (60s) is the beat cadence and is well inside `PROGRESS_DEADLINE`.
    for chain_key in states.keys() {
        health.heartbeat(&health_key(*chain_key));
    }

    let mut refresh_tick = tokio::time::interval(Duration::from_secs(REFRESH_SECS));
    let mut pacer = crate::pacing::RateLimitPacer::default();
    refresh_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // Cancel first. On shutdown the p2p/spy vote source drops its sender at the same
            // instant the token fires; without `biased` the closed-channel arm below could win the
            // race and log an ERROR for an orderly exit. It did, at 05:19:39 UTC on 2026-09-17,
            // and the network report read that line as the reason the relayer exited.
            biased;
            () = cancel.cancelled() => {
                info!("🛑 attestor-set-update aggregator exiting on cancel");
                return Ok(());
            }
            _ = refresh_tick.tick() => {
                // Rate-limit pacing: skip the refresh while a deferral window is active. The
                // vote_rx arm below is untouched — votes keep aggregating during a deferral
                // (bugbot: an in-arm sleep stalled vote intake for the whole cooldown).
                if let Some(remaining) = pacer.deferring() {
                    tracing::debug!(remaining_ms = remaining.as_millis() as u64,
                        "⏸️ pacing set-update refresh — skipping tick");
                    continue;
                }
                let mut rate_limited = false;
                for (chain_key, state) in states.iter_mut() {
                    match refresh(state).await {
                        // Beat per route on a *successful* refresh, matching the outbox/ack/claim
                        // convention of reporting progress on a successful poll rather than on a loop
                        // turn. Deliberately not also beating on a successful `submit`: `verify_vote`
                        // requires a vote's nonce to equal the last-seen on-chain nonce, so a route
                        // whose refresh is dead holds a frozen view and rejects every vote as soon as
                        // one update mines. Submissions can only keep succeeding in the window before
                        // that, so treating them as liveness would report a wedged route healthy —
                        // the exact failure class this watchdog exists to catch.
                        Ok(()) => health.heartbeat(&health_key(*chain_key)),
                        Err(err) => {
                            rate_limited = rate_limited
                                || crate::pacing::error_looks_rate_limited(&format!("{err:#}"));
                            // Still ticking: degraded rather than stale (see `crate::health`).
                            // `refresh` dials a fresh provider every time, so there is nothing
                            // further to rebuild here.
                            health.error(&health_key(*chain_key));
                            warn!(%chain_key, %err, "attestor-set-update: on-chain refresh failed; keeping last-known view");
                        }
                    }
                }

                // Rate-limit pacing — see `crate::pacing`: a rate-limited refresh arms a
                // deferral window (checked at tick start); clean refreshes decay and never slow
                // the loop. Vote intake is independent of the window entirely.
                pacer.after(rate_limited);
                if rate_limited {
                    if let Some(window) = pacer.deferring() {
                        warn!(defer_ms = window.as_millis() as u64,
                            "🧯 provider is rate limiting — deferring set-update refresh");
                    }
                }
            }
            maybe = vote_rx.recv() => {
                match maybe {
                    Some(vote) => handle_vote(&mut states, &broadcast_locks, vote).await,
                    None => {
                        // All senders dropped. During shutdown that is the vote source draining
                        // ahead of us (the `biased` cancel arm normally wins, this is the backstop);
                        // outside shutdown the p2p/spy source is gone and the supervisor should
                        // hear about it as a failure, not a clean exit.
                        if cancel.is_cancelled() {
                            info!("🛑 attestor-set-update aggregator exiting on cancel");
                            return Ok(());
                        }
                        error!("attestor-set-update vote channel closed outside shutdown — the p2p/spy vote source is gone; exiting");
                        anyhow::bail!("attestor-set-update vote channel closed outside shutdown");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use alloy::signers::SignerSync;

    fn onchain(attestors: &[Address], threshold: usize, nonce: u64, chain_id: u64) -> OnChain {
        OnChain {
            attestors: attestors.iter().copied().collect(),
            threshold,
            nonce: U256::from(nonce),
            chain_id: U256::from(chain_id),
        }
    }

    /// Validator every test signs for; `verify_vote` must be given the same one to aggregate.
    const TEST_VALIDATOR: Address = address!("00000000000000000000000000000000000000e1");

    /// Build a valid set-update vote signed by `signer` over the canonical digest.
    fn signed_vote(
        signer: &PrivateKeySigner,
        chain_key: u64,
        new_attestors: &[Address],
        nonce: u64,
        chain_id: u64,
    ) -> SetUpdateVote {
        let canonical = canonical_attestor_order(new_attestors);
        let digest = attestor_set_update_digest(
            TEST_VALIDATOR,
            &canonical,
            U256::from(chain_id),
            U256::from(nonce),
        );
        let sig = signer.sign_hash_sync(&digest).unwrap();
        SetUpdateVote {
            chain_key,
            new_attestors: canonical.iter().map(|a| a.into_array()).collect(),
            nonce: U256::from(nonce).to_be_bytes(),
            signer: signer.address().into_array(),
            signature: sig.as_bytes(),
        }
    }

    fn key(n: u8) -> PrivateKeySigner {
        PrivateKeySigner::from_slice(&[n; 32]).unwrap()
    }
    fn addr(n: u8) -> Address {
        Address::from([n; 20])
    }

    #[test]
    fn verify_accepts_current_attestor_and_binds_digest() {
        let s = key(7);
        let new_set = [addr(0xaa), addr(0xbb)];
        let current = onchain(&[s.address()], 1, 5, 11_155_111);
        let vote = signed_vote(&s, 2, &new_set, 5, 11_155_111);

        let (canonical, digest, signer) =
            verify_vote(&vote, TEST_VALIDATOR, &current).expect("valid vote");
        assert_eq!(signer, s.address());
        assert_eq!(canonical, canonical_attestor_order(&new_set));
        assert_eq!(
            digest,
            attestor_set_update_digest(
                TEST_VALIDATOR,
                &canonical,
                U256::from(11_155_111u64),
                U256::from(5u64)
            )
        );
    }

    #[test]
    fn verify_rejects_non_attestor() {
        let s = key(7);
        let current = onchain(&[addr(0x01)], 1, 5, 1); // s is NOT in the set
        let vote = signed_vote(&s, 2, &[addr(0xaa)], 5, 1);
        assert!(verify_vote(&vote, TEST_VALIDATOR, &current).is_none());
    }

    #[test]
    fn verify_rejects_stale_nonce() {
        let s = key(7);
        let current = onchain(&[s.address()], 1, 6, 1); // on-chain nonce advanced to 6
        let vote = signed_vote(&s, 2, &[addr(0xaa)], 5, 1); // signed against 5
        assert!(verify_vote(&vote, TEST_VALIDATOR, &current).is_none());
    }

    #[test]
    fn verify_rejects_wrong_chain_id() {
        let s = key(7);
        let current = onchain(&[s.address()], 1, 5, 999); // on-chain chain id differs
        let vote = signed_vote(&s, 2, &[addr(0xaa)], 5, 1);
        assert!(verify_vote(&vote, TEST_VALIDATOR, &current).is_none());
    }
}
