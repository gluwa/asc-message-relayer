//! The spy's libp2p task: join the attestor mesh, observe, annotate, fan out.
//!
//! Reuses the relayer's [`RelayerBehavior`] (gossipsub Strict + `validate_messages`, kad,
//! identify, ping, mdns toggle, connection limits) and the shared `write-ability` topic ids, so
//! the spy is wire-identical to the relayer's observer half — one mesh, one stack.
//!
//! Gossipsub citizenship for a non-validator (spec §3): a decodable vote whose envelope
//! `chain_key` matches its topic is **Accept**ed and streamed — including votes whose signature
//! does *not* recover to the advertised signer. Signature validity is an **annotation**
//! (`signature_valid`), not a gate: the spy has no active-set view, the mesh's real validators
//! (attestors, relayer pool) enforce membership and reject forgeries themselves, and an observer
//! that Rejected on local crypto judgment would P4-penalize peers for traffic the validators may
//! accept. Only provably malformed frames (undecodable, topic/envelope mismatch) are Rejected.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Context, Result};
use futures::StreamExt;
use libp2p::gossipsub::{IdentTopic, MessageAcceptance, TopicHash};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use message_relayer::health::Health;
use message_relayer::p2p::behavior::{RelayerBehavior, RelayerBehaviorEvent};
use message_relayer::p2p::{derive_keypair, protocols};
use write_ability::envelope::{MessageVote, ReobservationRequest, SetUpdateVote};

use crate::config::P2pConfig;
use crate::events::SpyEvent;
use crate::hub::Hub;
use crate::metrics::{EventLabelKind, EventOutcome, SpyMetrics};

/// Backoff between listen retries (transient port conflicts from a restarting predecessor).
const LISTEN_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);
/// Listen attempts before proceeding dial-only (loudly).
const LISTEN_RETRY_ATTEMPTS: u32 = 12;
/// Cadence of the swarm loop's liveness pulse into [`Health`]. A wedged loop stops pulsing and
/// `/health` flips 503 so orchestration restarts the spy.
const HEALTH_PULSE: std::time::Duration = std::time::Duration::from_secs(30);

/// A reobservation request a WS client asked the spy to gossip (spec §5, `allow_publish` only).
#[derive(Debug)]
pub struct PublishRequest {
    pub request: ReobservationRequest,
}

pub async fn run(
    p2p: P2pConfig,
    chain_keys: Vec<u64>,
    hub: Hub,
    mut publish_rx: mpsc::Receiver<PublishRequest>,
    metrics: Arc<SpyMetrics>,
    health: Arc<Health>,
    cancel: CancellationToken,
) -> Result<()> {
    let keypair =
        derive_keypair(p2p.identity.as_deref()).context("failed to derive libp2p identity")?;
    let local_peer_id = keypair.public().to_peer_id();
    info!(%local_peer_id, "🕵️ spy libp2p identity ready");

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_quic()
        .with_dns()?
        .with_behaviour(|key| RelayerBehavior::new(key, !p2p.no_mdns))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(std::time::Duration::from_secs(60)))
        .build();

    // Subscribe to the message-vote and reobservation topics per configured chain.
    let mut vote_topic_to_chain: HashMap<TopicHash, u64> = HashMap::new();
    let mut reobs_topic_to_chain: HashMap<TopicHash, u64> = HashMap::new();
    let mut setupdate_topic_to_chain: HashMap<TopicHash, u64> = HashMap::new();
    let mut chain_to_reobs_topic: HashMap<u64, IdentTopic> = HashMap::new();
    for ck in &chain_keys {
        let votes = IdentTopic::new(protocols::message_votes_topic(*ck));
        info!(chain_key = ck, topic = %votes, "📥 observing message votes");
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&votes)
            .with_context(|| format!("subscribe to {votes} failed"))?;
        vote_topic_to_chain.insert(votes.hash(), *ck);

        let reobs = IdentTopic::new(protocols::reobservation_topic(*ck));
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&reobs)
            .with_context(|| format!("subscribe to {reobs} failed"))?;
        reobs_topic_to_chain.insert(reobs.hash(), *ck);
        chain_to_reobs_topic.insert(*ck, reobs);

        let setupdate = IdentTopic::new(protocols::attestor_set_update_topic(*ck));
        info!(chain_key = ck, topic = %setupdate, "📥 observing attestor-set-update votes");
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&setupdate)
            .with_context(|| format!("subscribe to {setupdate} failed"))?;
        setupdate_topic_to_chain.insert(setupdate.hash(), *ck);
    }

    for boot in &p2p.boot_nodes {
        match boot.parse::<libp2p::Multiaddr>() {
            Ok(addr) => {
                if let Some(peer_id) = addr.iter().find_map(|p| match p {
                    libp2p::multiaddr::Protocol::P2p(peer_id) => Some(peer_id),
                    _ => None,
                }) {
                    info!(%addr, %peer_id, "👥 registering boot node");
                    swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                } else {
                    warn!(%addr, "boot node address has no /p2p/ component; skipping");
                }
            }
            Err(err) => warn!(%boot, %err, "could not parse boot node multiaddr; skipping"),
        }
    }

    if let Some(public) = &p2p.public_addr {
        match format!("/dns4/{public}/tcp/{}", p2p.port).parse::<libp2p::Multiaddr>() {
            Ok(addr) => {
                info!(%addr, "📰 broadcasting external address");
                swarm.add_external_address(addr);
            }
            Err(err) => warn!(public, port = p2p.port, %err, "invalid public_addr"),
        }
    }

    // Only listen when a `public_addr` is configured. A listening spy leaks its discovered
    // listen addrs (loopback + cluster-local pod IP) to peers via identify, and the bootnode's
    // kad table then propagates that record mesh-wide: every attestor — including ones in other
    // clusters with no route to a pod IP — burns dial attempts on it until their unreachable-peer
    // eviction kicks in, and a restart (new pod IP, new ephemeral PeerId) leaves the stale record
    // behind to re-poison the mesh. A dial-only observer needs no inbound reachability at all:
    // gossipsub delivers over its outbound connections, and with no listen addrs identify has
    // nothing dialable to advertise.
    if p2p.public_addr.is_some() {
        // Retry the listen; after the budget proceed dial-only, loudly (mirrors the relayer).
        let listen: libp2p::Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", p2p.port).parse()?;
        for attempt in 1..=LISTEN_RETRY_ATTEMPTS {
            match swarm.listen_on(listen.clone()) {
                Ok(_) => break,
                Err(err) if attempt == LISTEN_RETRY_ATTEMPTS => {
                    tracing::error!(
                        %listen, %err, attempts = attempt,
                        "swarm listen failed after retries — continuing DIAL-ONLY (inbound peers cannot reach this spy)"
                    );
                }
                Err(err) => {
                    warn!(%listen, %err, attempt, "swarm listen failed; retrying after backoff");
                    tokio::select! {
                        () = cancel.cancelled() => return Ok(()),
                        () = tokio::time::sleep(LISTEN_RETRY_BACKOFF) => {}
                    }
                }
            }
        }
    } else {
        info!("🕶️ no public_addr configured — dial-only observer; not listening, nothing dialable advertised");
    }

    info!(chains = chain_keys.len(), "✅ spy swarm online");

    let mut subscribed_peers: SubscribedPeers = HashMap::new();
    let mut health_tick = tokio::time::interval(HEALTH_PULSE);
    health_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    health.heartbeat("swarm");

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!("🛑 spy swarm exiting on cancel");
                return Ok(());
            }
            _ = health_tick.tick() => {
                health.heartbeat("swarm");
            }
            maybe = publish_rx.recv() => {
                let Some(PublishRequest { request }) = maybe else {
                    // WS layer holds the sender for the process lifetime; closure means shutdown.
                    debug!("publish channel closed");
                    continue;
                };
                let Some(topic) = chain_to_reobs_topic.get(&request.chain_key) else {
                    warn!(chain_key = request.chain_key, "publish for unobserved chain_key; dropping");
                    continue;
                };
                match swarm.behaviour_mut().gossipsub.publish(topic.hash(), request.encode_bytes()) {
                    Ok(_) => {
                        metrics.inc_reobservation_published();
                        debug!(chain_key = request.chain_key, "📣 gossiped reobservation request");
                    }
                    // No mesh peers is the common transient; the client retries on its own cadence.
                    Err(err) => debug!(chain_key = request.chain_key, %err, "reobservation publish failed"),
                }
            }
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    event,
                    &mut swarm,
                    &vote_topic_to_chain,
                    &reobs_topic_to_chain,
                    &setupdate_topic_to_chain,
                    &hub,
                    metrics.as_ref(),
                    &mut subscribed_peers,
                );
            }
        }
    }
}

/// Distinct peers seen subscribed to each chain's vote topic.
///
/// A set, not a counter. The previous counter incremented on every gossipsub `Subscribed` and
/// decremented on every `Unsubscribed`, which over-counts badly in practice: gossipsub emits no
/// `Unsubscribed` when a peer simply disconnects, so each reconnect added one more and nothing ever
/// took it away. On usc-devnet that read **52 subscribed peers against a verified 10-attestor
/// fleet** — useless for fleet health, and actively misleading to anyone treating it as a peer
/// count. Keying on `PeerId` makes the gauge idempotent under repeated `Subscribed` events and lets
/// `ConnectionClosed` remove a peer that left without unsubscribing.
type SubscribedPeers = HashMap<u64, HashSet<libp2p::PeerId>>;

/// Record `peer_id` as subscribed to `chain_key`. Returns the new distinct count, or `None` if the
/// peer was already known — a duplicate `Subscribed` must not move the gauge.
fn note_subscribed(
    peers: &mut SubscribedPeers,
    chain_key: u64,
    peer_id: libp2p::PeerId,
) -> Option<usize> {
    let entry = peers.entry(chain_key).or_default();
    entry.insert(peer_id).then_some(entry.len())
}

/// Drop `peer_id` from `chain_key`. Returns the new distinct count, or `None` if it was not there.
fn note_unsubscribed(
    peers: &mut SubscribedPeers,
    chain_key: u64,
    peer_id: &libp2p::PeerId,
) -> Option<usize> {
    let entry = peers.get_mut(&chain_key)?;
    entry.remove(peer_id).then_some(entry.len())
}

/// Drop `peer_id` from every chain it was subscribed to. Returns `(chain_key, new_count)` for each
/// chain that actually changed, so a disconnect corrects every gauge the peer was counted in.
fn note_disconnected(peers: &mut SubscribedPeers, peer_id: &libp2p::PeerId) -> Vec<(u64, usize)> {
    peers
        .iter_mut()
        .filter_map(|(&chain_key, set)| set.remove(peer_id).then_some((chain_key, set.len())))
        .collect()
}

fn report_peer_count(chain_key: u64, count: usize, hub: &Hub, metrics: &SpyMetrics) {
    metrics.set_subscribed_peers(chain_key, i64::try_from(count).unwrap_or(i64::MAX));
    hub.publish(SpyEvent::peer_status(chain_key, count));
}

#[allow(clippy::too_many_arguments)]
fn handle_swarm_event(
    event: libp2p::swarm::SwarmEvent<RelayerBehaviorEvent>,
    swarm: &mut libp2p::Swarm<RelayerBehavior>,
    vote_topic_to_chain: &HashMap<TopicHash, u64>,
    reobs_topic_to_chain: &HashMap<TopicHash, u64>,
    setupdate_topic_to_chain: &HashMap<TopicHash, u64>,
    hub: &Hub,
    metrics: &SpyMetrics,
    subscribed_peers: &mut SubscribedPeers,
) {
    match event {
        libp2p::swarm::SwarmEvent::Behaviour(RelayerBehaviorEvent::Identify(
            libp2p::identify::Event::Received {
                peer_id,
                info: libp2p::identify::Info { listen_addrs, .. },
                ..
            },
        )) => {
            for addr in listen_addrs {
                swarm.behaviour_mut().kad.add_address(&peer_id, addr);
            }
        }
        libp2p::swarm::SwarmEvent::Behaviour(RelayerBehaviorEvent::Mdns(
            libp2p::mdns::Event::Discovered(peers),
        )) => {
            for (peer_id, addr) in peers {
                debug!(%peer_id, %addr, "🛰️ mDNS discovered");
                swarm.behaviour_mut().kad.add_address(&peer_id, addr);
            }
        }
        libp2p::swarm::SwarmEvent::Behaviour(RelayerBehaviorEvent::Gossipsub(
            libp2p::gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            },
        )) => {
            let acceptance = if let Some(&chain_key) = vote_topic_to_chain.get(&message.topic) {
                observe_vote(chain_key, &message.data, &propagation_source, hub, metrics)
            } else if let Some(&chain_key) = reobs_topic_to_chain.get(&message.topic) {
                observe_reobservation(chain_key, &message.data, &propagation_source, hub, metrics)
            } else if let Some(&chain_key) = setupdate_topic_to_chain.get(&message.topic) {
                observe_set_update(chain_key, &message.data, &propagation_source, hub, metrics)
            } else {
                trace!(topic = %message.topic, "message on unsubscribed topic");
                return;
            };
            swarm
                .behaviour_mut()
                .gossipsub
                .report_message_validation_result(&message_id, &propagation_source, acceptance);
        }
        libp2p::swarm::SwarmEvent::Behaviour(RelayerBehaviorEvent::Gossipsub(
            libp2p::gossipsub::Event::Subscribed { peer_id, topic },
        )) => {
            if let Some(&chain_key) = vote_topic_to_chain.get(&topic) {
                if let Some(count) = note_subscribed(subscribed_peers, chain_key, peer_id) {
                    report_peer_count(chain_key, count, hub, metrics);
                }
            }
            trace!(%peer_id, %topic, "peer subscribed");
        }
        libp2p::swarm::SwarmEvent::Behaviour(RelayerBehaviorEvent::Gossipsub(
            libp2p::gossipsub::Event::Unsubscribed { peer_id, topic },
        )) => {
            if let Some(&chain_key) = vote_topic_to_chain.get(&topic) {
                if let Some(count) = note_unsubscribed(subscribed_peers, chain_key, &peer_id) {
                    report_peer_count(chain_key, count, hub, metrics);
                }
            }
            trace!(%peer_id, %topic, "peer unsubscribed");
        }
        libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
            info!(%address, "🔍 new listen address");
        }
        libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            debug!(%peer_id, "🔗 connection established");
        }
        libp2p::swarm::SwarmEvent::ConnectionClosed {
            peer_id,
            num_established,
            ..
        } => {
            debug!(%peer_id, num_established, "⛓️‍💥 connection closed");
            // gossipsub does NOT emit `Unsubscribed` when a peer disconnects — it drops the peer
            // from its topic meshes silently. Without this, a peer that reconnects raises the
            // gauge again on its fresh `Subscribed` and never lowers it, so the number climbs with
            // churn instead of tracking the fleet. Only act once the *last* connection to the peer
            // is gone; libp2p may hold several at a time.
            if num_established == 0 {
                for (chain_key, count) in note_disconnected(subscribed_peers, &peer_id) {
                    report_peer_count(chain_key, count, hub, metrics);
                }
            }
        }
        libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            debug!(?peer_id, %error, "outgoing connection error");
        }
        _ => {}
    }
}

/// Decode + annotate one message-vote frame. Returns the gossipsub acceptance (module docs).
fn observe_vote(
    chain_key: u64,
    data: &[u8],
    source: &libp2p::PeerId,
    hub: &Hub,
    metrics: &SpyMetrics,
) -> MessageAcceptance {
    let vote = match MessageVote::decode_bytes(data) {
        Ok(vote) if vote.chain_key == chain_key => vote,
        Ok(vote) => {
            warn!(
                %source,
                envelope_chain_key = vote.chain_key,
                topic_chain_key = chain_key,
                "vote envelope chain_key disagrees with topic — rejecting"
            );
            metrics.inc_event(EventLabelKind::MessageVote, EventOutcome::Rejected);
            return MessageAcceptance::Reject;
        }
        Err(err) => {
            warn!(%source, %err, "could not decode MessageVote — rejecting");
            metrics.inc_event(EventLabelKind::MessageVote, EventOutcome::Rejected);
            return MessageAcceptance::Reject;
        }
    };

    // Annotate, don't gate: recovery failure streams as `signature_valid: false` (module docs).
    let advertised = alloy::primitives::Address::from(vote.signer);
    let (signer, signature_valid) = match recover_signer(
        &alloy::primitives::B256::from(vote.message_id),
        &vote.signature,
    ) {
        Ok(recovered) => (recovered, recovered == advertised),
        Err(_) => (advertised, false),
    };

    hub.publish(SpyEvent::message_vote(
        chain_key,
        vote.message_id,
        signer,
        signature_valid,
        &vote.signature,
        source,
    ));
    metrics.inc_event(EventLabelKind::MessageVote, EventOutcome::Accepted);
    MessageAcceptance::Accept
}

/// Decode one reobservation-request frame. Requests are unauthenticated by design (attestors
/// re-verify against their own RPC), so any decodable request is Accepted and streamed.
fn observe_reobservation(
    chain_key: u64,
    data: &[u8],
    source: &libp2p::PeerId,
    hub: &Hub,
    metrics: &SpyMetrics,
) -> MessageAcceptance {
    match ReobservationRequest::decode_bytes(data) {
        Ok(req) if req.chain_key == chain_key => {
            hub.publish(SpyEvent::reobservation_request(
                chain_key,
                req.message_id,
                req.tx_hash,
                req.block_height,
                source,
            ));
            metrics.inc_event(EventLabelKind::ReobservationRequest, EventOutcome::Accepted);
            MessageAcceptance::Accept
        }
        Ok(req) => {
            warn!(
                %source,
                envelope_chain_key = req.chain_key,
                topic_chain_key = chain_key,
                "reobservation envelope chain_key disagrees with topic — rejecting"
            );
            metrics.inc_event(EventLabelKind::ReobservationRequest, EventOutcome::Rejected);
            MessageAcceptance::Reject
        }
        Err(err) => {
            warn!(%source, %err, "could not decode ReobservationRequest — rejecting");
            metrics.inc_event(EventLabelKind::ReobservationRequest, EventOutcome::Rejected);
            MessageAcceptance::Reject
        }
    }
}

/// Decode one attestor-set-update-vote frame and stream it raw. Unlike [`observe_vote`], the spy
/// does **not** attempt signature recovery: the signature covers the update digest, which is
/// derived from destination-chain state (`chain_id`, `attestorSetUpdateNonce`) the spy has no
/// connection to. The relayer's set-update aggregator recomputes the digest and recovers the
/// signer itself, so the spy just re-emits the wire fields. Any decodable vote whose envelope
/// `chain_key` matches its topic is Accepted; malformed / mismatched frames are Rejected.
fn observe_set_update(
    chain_key: u64,
    data: &[u8],
    source: &libp2p::PeerId,
    hub: &Hub,
    metrics: &SpyMetrics,
) -> MessageAcceptance {
    match SetUpdateVote::decode_bytes(data) {
        Ok(vote) if vote.chain_key == chain_key => {
            hub.publish(SpyEvent::set_update_vote(
                chain_key,
                &vote.new_attestors,
                vote.nonce,
                vote.signer,
                &vote.signature,
                source,
            ));
            metrics.inc_event(EventLabelKind::SetUpdateVote, EventOutcome::Accepted);
            MessageAcceptance::Accept
        }
        Ok(vote) => {
            warn!(
                %source,
                envelope_chain_key = vote.chain_key,
                topic_chain_key = chain_key,
                "set-update vote envelope chain_key disagrees with topic — rejecting"
            );
            metrics.inc_event(EventLabelKind::SetUpdateVote, EventOutcome::Rejected);
            MessageAcceptance::Reject
        }
        Err(err) => {
            warn!(%source, %err, "could not decode SetUpdateVote — rejecting");
            metrics.inc_event(EventLabelKind::SetUpdateVote, EventOutcome::Rejected);
            MessageAcceptance::Reject
        }
    }
}

fn recover_signer(
    hash: &alloy::primitives::B256,
    raw: &[u8; 65],
) -> Result<alloy::primitives::Address> {
    let sig: alloy::primitives::Signature = raw[..]
        .try_into()
        .map_err(|e| anyhow::anyhow!("malformed signature bytes: {e}"))?;
    sig.recover_address_from_prehash(hash)
        .map_err(|e| anyhow::anyhow!("ecrecover failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------------------
    // Subscribed-peer accounting. The gauge this feeds read 52 against a verified 10-attestor
    // fleet, because it was a counter that only ever went up on reconnect. These cover the three
    // ways the set has to stay honest.
    // ---------------------------------------------------------------------------------------

    fn peer(seed: u8) -> libp2p::PeerId {
        libp2p::identity::Keypair::ed25519_from_bytes([seed; 32])
            .expect("valid key")
            .public()
            .to_peer_id()
    }

    #[test]
    fn repeated_subscribed_from_one_peer_counts_once() {
        let mut peers: SubscribedPeers = HashMap::new();
        let p = peer(1);
        assert_eq!(note_subscribed(&mut peers, 8, p), Some(1));
        // A reconnect re-emits `Subscribed` with no intervening `Unsubscribed`. This is the exact
        // event sequence that inflated the gauge to 52.
        assert_eq!(note_subscribed(&mut peers, 8, p), None);
        assert_eq!(note_subscribed(&mut peers, 8, p), None);
        assert_eq!(peers[&8].len(), 1);
    }

    #[test]
    fn unsubscribe_removes_only_that_peer_and_never_underflows() {
        let mut peers: SubscribedPeers = HashMap::new();
        note_subscribed(&mut peers, 8, peer(1));
        note_subscribed(&mut peers, 8, peer(2));
        assert_eq!(note_unsubscribed(&mut peers, 8, &peer(1)), Some(1));
        // Unsubscribe from a peer we never counted, and from a chain we have no set for: both must
        // be no-ops rather than driving a count negative, which the old saturating_sub masked.
        assert_eq!(note_unsubscribed(&mut peers, 8, &peer(1)), None);
        assert_eq!(note_unsubscribed(&mut peers, 99, &peer(2)), None);
        assert_eq!(peers[&8].len(), 1);
    }

    #[test]
    fn disconnect_clears_the_peer_from_every_chain_it_was_counted_in() {
        let mut peers: SubscribedPeers = HashMap::new();
        let leaving = peer(1);
        note_subscribed(&mut peers, 8, leaving);
        note_subscribed(&mut peers, 7, leaving);
        note_subscribed(&mut peers, 8, peer(2));

        let mut changed = note_disconnected(&mut peers, &leaving);
        changed.sort_unstable();
        assert_eq!(changed, vec![(7, 0), (8, 1)]);

        // Nothing left to correct on a second disconnect for the same peer.
        assert!(note_disconnected(&mut peers, &leaving).is_empty());
    }

    /// Sign a vote with a real key and run it through `observe_vote`: it must Accept, stream one
    /// event, and annotate `signature_valid: true` with the recovered signer.
    #[tokio::test]
    async fn observe_vote_streams_annotated_event() {
        use alloy::signers::local::PrivateKeySigner;
        use alloy::signers::SignerSync;

        let signer = PrivateKeySigner::random();
        let hash = alloy::primitives::B256::repeat_byte(0xAB);
        let sig = signer.sign_hash_sync(&hash).unwrap();
        let mut raw = [0u8; 65];
        raw.copy_from_slice(&sig.as_bytes());

        let vote = MessageVote {
            chain_key: 102,
            message_id: hash.0,
            signer: signer.address().into_array(),
            signature: raw,
        };

        let hub = Hub::new();
        let mut rx = hub.subscribe();
        let metrics = SpyMetrics::new();
        let acceptance = observe_vote(
            102,
            &vote.encode_bytes(),
            &libp2p::PeerId::random(),
            &hub,
            &metrics,
        );
        assert!(matches!(acceptance, MessageAcceptance::Accept));

        let event = rx.recv().await.unwrap();
        let json = serde_json::to_value(&*event).unwrap();
        assert_eq!(json["type"], "message_vote");
        assert_eq!(json["signature_valid"], true);
        assert_eq!(
            json["signer"].as_str().unwrap().to_lowercase(),
            format!("{:?}", signer.address()).to_lowercase()
        );
    }

    /// A forged signer field must still stream (Accept) but be annotated invalid — the spy
    /// observes, the mesh's validators judge.
    #[tokio::test]
    async fn forged_signer_streams_with_signature_valid_false() {
        use alloy::signers::local::PrivateKeySigner;
        use alloy::signers::SignerSync;

        let real = PrivateKeySigner::random();
        let hash = alloy::primitives::B256::repeat_byte(0xCD);
        let sig = real.sign_hash_sync(&hash).unwrap();
        let mut raw = [0u8; 65];
        raw.copy_from_slice(&sig.as_bytes());

        let impostor = alloy::primitives::Address::repeat_byte(0x66);
        let vote = MessageVote {
            chain_key: 102,
            message_id: hash.0,
            signer: impostor.into_array(),
            signature: raw,
        };

        let hub = Hub::new();
        let mut rx = hub.subscribe();
        let metrics = SpyMetrics::new();
        let acceptance = observe_vote(
            102,
            &vote.encode_bytes(),
            &libp2p::PeerId::random(),
            &hub,
            &metrics,
        );
        assert!(matches!(acceptance, MessageAcceptance::Accept));

        let json = serde_json::to_value(&*rx.recv().await.unwrap()).unwrap();
        assert_eq!(json["signature_valid"], false);
    }

    #[test]
    fn garbage_and_chain_mismatch_are_rejected() {
        let hub = Hub::new();
        let metrics = SpyMetrics::new();
        assert!(matches!(
            observe_vote(102, b"garbage", &libp2p::PeerId::random(), &hub, &metrics),
            MessageAcceptance::Reject
        ));

        let vote = MessageVote {
            chain_key: 7, // disagrees with topic chain 102
            message_id: [1u8; 32],
            signer: [3u8; 20],
            signature: [0u8; 65],
        };
        assert!(matches!(
            observe_vote(
                102,
                &vote.encode_bytes(),
                &libp2p::PeerId::random(),
                &hub,
                &metrics
            ),
            MessageAcceptance::Reject
        ));
    }

    /// A decodable set-update vote streams raw (no signature recovery, no `signature_valid`) and
    /// Accepts; the relayer's aggregator re-derives the digest and validates.
    #[tokio::test]
    async fn observe_set_update_streams_raw_event() {
        let vote = SetUpdateVote {
            chain_key: 102,
            new_attestors: vec![[0x0A; 20], [0x0B; 20]],
            nonce: [0xCD; 32],
            signer: [0xEE; 20],
            signature: [0x03; 65],
        };

        let hub = Hub::new();
        let mut rx = hub.subscribe();
        let metrics = SpyMetrics::new();
        let acceptance = observe_set_update(
            102,
            &vote.encode_bytes(),
            &libp2p::PeerId::random(),
            &hub,
            &metrics,
        );
        assert!(matches!(acceptance, MessageAcceptance::Accept));

        let json = serde_json::to_value(&*rx.recv().await.unwrap()).unwrap();
        assert_eq!(json["type"], "attestor_set_update");
        assert_eq!(json["chain_key"], 102);
        assert_eq!(json["new_attestors"][0], format!("0x{}", "0a".repeat(20)));
        assert_eq!(json["signer"], format!("0x{}", "ee".repeat(20)));
        assert!(json.get("signature_valid").is_none());
    }

    #[test]
    fn set_update_garbage_and_chain_mismatch_are_rejected() {
        let hub = Hub::new();
        let metrics = SpyMetrics::new();
        assert!(matches!(
            observe_set_update(102, b"garbage", &libp2p::PeerId::random(), &hub, &metrics),
            MessageAcceptance::Reject
        ));

        let vote = SetUpdateVote {
            chain_key: 7, // disagrees with topic chain 102
            new_attestors: vec![[0x0A; 20]],
            nonce: [0xCD; 32],
            signer: [0xEE; 20],
            signature: [0x03; 65],
        };
        assert!(matches!(
            observe_set_update(
                102,
                &vote.encode_bytes(),
                &libp2p::PeerId::random(),
                &hub,
                &metrics
            ),
            MessageAcceptance::Reject
        ));
    }
}
