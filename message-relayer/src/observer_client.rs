//! Observer-node WebSocket client — the relayer's vote source when it fronts its gossip through a
//! observer instead of embedding a libp2p swarm (observer spec §1; decided 2026-07-13).
//!
//! Replaces [`crate::p2p::run`] when `observer.ws_url` is configured: message votes arrive as JSON
//! events from the observer's `/ws` subscription, and the pool's reobservation requests go out as
//! `publish_reobservation` frames (the observer must run with `allow_publish: true`).
//!
//! **Trust model:** the observer is untrusted infrastructure. Its `signature_valid` annotation is
//! deliberately ignored — every vote is reconstructed into the wire [`MessageVote`] envelope and
//! flows through the pool's own ecrecover + allowlist validation, exactly as gossip-delivered
//! votes do. A lying observer can withhold votes (a liveness problem, mitigated by running your own)
//! but cannot forge one.
//!
//! **Liveness:** heartbeats into [`Health`] fire only on *successful* activity (connect, inbound
//! frames, pongs) — never on reconnect attempts. A dead/unreachable observer therefore trips `/health`
//! after the progress deadline and the relayer restarts until the observer returns: visible and
//! alertable, unlike a silent vote drought (the C4 wedge class). Votes gossiped while
//! disconnected are recovered by the pool's reobservation cadence once the connection returns.

use std::time::Duration;

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use write_ability::envelope::{ReobservationRequest, SetUpdateVote};

use crate::health::Health;
use crate::p2p::MessageVote;
use crate::prom::Metrics;

/// Reconnect backoff bounds (exponential between them).
const RECONNECT_BASE: Duration = Duration::from_secs(2);
const RECONNECT_MAX: Duration = Duration::from_secs(60);
/// WS protocol ping cadence — the pong doubles as the liveness pulse on a quiet mesh (no votes
/// flowing is normal between publishes; a dead connection is not).
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Health registry key for this worker.
const HEALTH_KEY: &str = "observer-client";

#[derive(Debug, Clone, Deserialize)]
pub struct ObserverClientConfig {
    /// The observer's subscription endpoint, e.g. `ws://cc3-usc-dev-observer-node:9190/ws`.
    pub ws_url: String,
}

/// Run the observer client until cancelled: subscribe for the routes' chain keys, forward votes into
/// `vote_tx`, publish the pool's reobservation requests through the observer.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    config: ObserverClientConfig,
    chain_keys: Vec<u64>,
    vote_tx: mpsc::Sender<MessageVote>,
    setupdate_vote_tx: mpsc::Sender<SetUpdateVote>,
    mut reobs_rx: mpsc::Receiver<ReobservationRequest>,
    metrics: Metrics,
    health: std::sync::Arc<Health>,
    cancel: CancellationToken,
) -> Result<()> {
    info!(url = %config.ws_url, ?chain_keys, "🕵️ vote source: observer node (no embedded swarm)");
    // Register at startup so an observer that is unreachable from the first attempt still goes stale
    // and trips /health (heartbeats only fire on successful activity — see module docs).
    health.heartbeat(HEALTH_KEY);

    let mut backoff = RECONNECT_BASE;
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        match session(
            &config,
            &chain_keys,
            &vote_tx,
            &setupdate_vote_tx,
            &mut reobs_rx,
            &metrics,
            &health,
            &cancel,
        )
        .await
        {
            Ok(()) => return Ok(()), // cancelled
            Err(err) => {
                warn!(%err, retry_in = ?backoff, "observer connection lost; reconnecting");
            }
        }
        tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            () = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

/// One connected session: subscribe, then pump events/publishes until the socket dies (Err) or
/// we are cancelled (Ok).
#[allow(clippy::too_many_arguments)]
async fn session(
    config: &ObserverClientConfig,
    chain_keys: &[u64],
    vote_tx: &mpsc::Sender<MessageVote>,
    setupdate_vote_tx: &mpsc::Sender<SetUpdateVote>,
    reobs_rx: &mut mpsc::Receiver<ReobservationRequest>,
    metrics: &Metrics,
    health: &Health,
    cancel: &CancellationToken,
) -> Result<()> {
    let (mut ws, _) = tokio::select! {
        () = cancel.cancelled() => return Ok(()),
        conn = tokio_tungstenite::connect_async(&config.ws_url) => {
            conn.with_context(|| format!("connecting to observer at {}", config.ws_url))?
        }
    };
    info!(url = %config.ws_url, "🔗 connected to observer");
    health.heartbeat(HEALTH_KEY);

    // Subscribe to message votes + peer status for our chains. (Reobservation-request events are
    // not needed — the relayer *originates* requests, it does not act on others'.)
    let subscribe = serde_json::json!({
        "subscribe": {
            "chain_keys": chain_keys,
            "events": ["message_vote", "attestor_set_update", "peer_status"]
        }
    });
    ws.send(WsMessage::Text(subscribe.to_string().into()))
        .await
        .context("sending subscribe frame")?;

    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            _ = ping.tick() => {
                ws.send(WsMessage::Ping(Vec::new().into())).await.context("ws ping failed")?;
            }
            maybe = reobs_rx.recv() => {
                let Some(req) = maybe else {
                    debug!("reobservation request channel closed");
                    continue;
                };
                let frame = serde_json::json!({
                    "publish_reobservation": {
                        "chain_key": req.chain_key,
                        "message_id": format!("0x{}", hex::encode(req.message_id)),
                        "tx_hash": format!("0x{}", hex::encode(req.tx_hash)),
                        "block_height": req.block_height,
                    }
                });
                ws.send(WsMessage::Text(frame.to_string().into()))
                    .await
                    .context("sending publish_reobservation frame")?;
            }
            inbound = ws.next() => {
                let msg = inbound
                    .ok_or_else(|| anyhow::anyhow!("observer closed the connection"))?
                    .context("ws receive failed")?;
                match msg {
                    WsMessage::Text(text) => {
                        health.heartbeat(HEALTH_KEY);
                        handle_event(text.as_str(), vote_tx, setupdate_vote_tx, metrics);
                    }
                    WsMessage::Pong(_) => {
                        // The liveness pulse on a quiet mesh: the connection demonstrably works.
                        health.heartbeat(HEALTH_KEY);
                    }
                    WsMessage::Close(frame) => {
                        anyhow::bail!("observer closed the connection: {frame:?}");
                    }
                    _ => {}
                }
            }
        }
    }
}

/// One observer event frame. Unknown `type`s (and ack/error frames, which have no `type`) are ignored
/// so the observer can add event kinds without breaking older relayers.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ObserverEvent {
    MessageVote(ObserverVote),
    #[serde(rename = "attestor_set_update")]
    SetUpdateVote(ObserverSetUpdate),
    PeerStatus {
        chain_key: u64,
        subscribed_peers: usize,
    },
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
struct ObserverVote {
    chain_key: u64,
    message_id: String,
    signer: String,
    signature: String,
    // `message_hash` (equal to `message_id` since asc-contracts #54 — see the observer's event docs)
    // and `signature_valid` are deliberately not read — the pool re-validates (module docs).
}

#[derive(Debug, Deserialize)]
struct ObserverSetUpdate {
    chain_key: u64,
    new_attestors: Vec<String>,
    nonce: String,
    signer: String,
    signature: String,
    // `source_peer` / `received_at_ms` are carried by the observer but unused here; extra fields are
    // ignored by serde. The set-update aggregator re-derives the digest and re-recovers the signer.
}

fn handle_event(
    text: &str,
    vote_tx: &mpsc::Sender<MessageVote>,
    setupdate_vote_tx: &mpsc::Sender<SetUpdateVote>,
    metrics: &Metrics,
) {
    let event: ObserverEvent = match serde_json::from_str(text) {
        Ok(event) => event,
        Err(_) => {
            // Ack / error frames ({"ack":…}, {"error":…}) land here — debug, not warn.
            debug!(frame = %text, "non-event frame from observer");
            return;
        }
    };
    match event {
        ObserverEvent::MessageVote(vote) => {
            let chain_key = vote.chain_key;
            match convert_vote(vote) {
                Ok(vote) => {
                    // Mirror the swarm path's shed-don't-block hand-off (votes are idempotent and
                    // recoverable via reobservation).
                    match vote_tx.try_send(vote) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            metrics.inc_vote(chain_key, crate::prom::VoteOutcome::Dropped);
                            warn!(
                                chain_key,
                                "vote pool saturated; dropping observer-delivered vote"
                            );
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            warn!("vote pool channel closed; observer client draining");
                        }
                    }
                }
                Err(err) => {
                    metrics.inc_vote(chain_key, crate::prom::VoteOutcome::Reject);
                    warn!(%err, "malformed vote event from observer — dropping");
                }
            }
        }
        ObserverEvent::SetUpdateVote(vote) => {
            let chain_key = vote.chain_key;
            match convert_set_update(vote) {
                Ok(vote) => {
                    // Mirror the swarm path's shed-don't-block hand-off (the proposer re-emits each
                    // cycle, so a dropped vote is recovered on the next round).
                    match setupdate_vote_tx.try_send(vote) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            warn!(
                                chain_key,
                                "set-update aggregator saturated; dropping observer-delivered vote"
                            );
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            warn!("set-update aggregator channel closed; observer client draining");
                        }
                    }
                }
                Err(err) => {
                    warn!(%err, "malformed set-update vote event from observer — dropping");
                }
            }
        }
        ObserverEvent::PeerStatus {
            chain_key,
            subscribed_peers,
        } => {
            // The observer's mesh visibility stands in for the removed swarm's own peer gauge.
            metrics.set_p2p_peer_count(chain_key, i64::try_from(subscribed_peers).unwrap_or(0));
        }
        ObserverEvent::Other => {}
    }
}

/// Reconstruct the wire envelope from an observer event. The pool re-validates from these raw fields
/// (ecrecover over `message_id`, signer allowlist), so nothing here trusts the observer.
fn convert_vote(vote: ObserverVote) -> Result<MessageVote> {
    Ok(MessageVote {
        chain_key: vote.chain_key,
        message_id: parse_hex::<32>(&vote.message_id).context("message_id")?,
        signer: parse_hex::<20>(&vote.signer).context("signer")?,
        signature: parse_hex::<65>(&vote.signature).context("signature")?,
    })
}

/// Reconstruct the wire [`SetUpdateVote`] envelope from an observer event. The set-update aggregator
/// re-derives the update digest from chain state and re-recovers the signer, so nothing here
/// trusts the observer (which cannot compute the digest and so does not annotate validity).
fn convert_set_update(vote: ObserverSetUpdate) -> Result<SetUpdateVote> {
    let new_attestors = vote
        .new_attestors
        .iter()
        .enumerate()
        .map(|(i, a)| parse_hex::<20>(a).with_context(|| format!("new_attestors[{i}]")))
        .collect::<Result<Vec<_>>>()?;
    Ok(SetUpdateVote {
        chain_key: vote.chain_key,
        new_attestors,
        nonce: parse_hex::<32>(&vote.nonce).context("nonce")?,
        signer: parse_hex::<20>(&vote.signer).context("signer")?,
        signature: parse_hex::<65>(&vote.signature).context("signature")?,
    })
}

fn parse_hex<const N: usize>(s: &str) -> Result<[u8; N]> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    anyhow::ensure!(
        hex_str.len() == N * 2,
        "expected {N}-byte hex string, got {} chars",
        hex_str.len()
    );
    let mut out = [0u8; N];
    hex::decode_to_slice(hex_str, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An observer `message_vote` frame (as `observer-node` serializes it) reconstructs the exact wire
    /// envelope. Field formats pinned by the observer's own event tests.
    #[test]
    fn converts_observer_vote_event_to_wire_envelope() {
        let json = format!(
            r#"{{"type":"message_vote","chain_key":7,"message_id":"0x{}","message_hash":"0x{}",
                "signer":"0x{}","signature_valid":true,"signature":"0x{}",
                "source_peer":"12D3KooWExample","received_at_ms":1}}"#,
            "01".repeat(32),
            "02".repeat(32),
            "0a".repeat(20),
            "03".repeat(65),
        );
        let event: ObserverEvent = serde_json::from_str(&json).unwrap();
        let ObserverEvent::MessageVote(vote) = event else {
            panic!("expected message_vote")
        };
        let wire = convert_vote(vote).unwrap();
        assert_eq!(wire.chain_key, 7);
        assert_eq!(wire.message_id, [0x01; 32]);
        assert_eq!(wire.signer, [0x0A; 20]);
        assert_eq!(wire.signature, [0x03; 65]);
    }

    #[test]
    fn peer_status_and_unknown_types_parse() {
        let ps: ObserverEvent = serde_json::from_str(
            r#"{"type":"peer_status","chain_key":7,"subscribed_peers":8,"received_at_ms":1}"#,
        )
        .unwrap();
        assert!(matches!(
            ps,
            ObserverEvent::PeerStatus {
                chain_key: 7,
                subscribed_peers: 8
            }
        ));
        // Forward compatibility: unknown event kinds must not error.
        let other: ObserverEvent =
            serde_json::from_str(r#"{"type":"brand_new_event","whatever":true}"#).unwrap();
        assert!(matches!(other, ObserverEvent::Other));
        // Ack frames (no `type` tag) fail to parse as ObserverEvent — handle_event ignores them.
        assert!(serde_json::from_str::<ObserverEvent>(r#"{"ack":{"subscribe":true}}"#).is_err());
    }

    /// An observer `attestor_set_update` frame reconstructs the exact wire envelope (raw fields, no
    /// signature annotation — the aggregator re-derives the digest and re-recovers).
    #[test]
    fn converts_observer_set_update_event_to_wire_envelope() {
        let json = format!(
            r#"{{"type":"attestor_set_update","chain_key":7,
                "new_attestors":["0x{}","0x{}"],"nonce":"0x{}","signer":"0x{}",
                "signature":"0x{}","source_peer":"12D3KooWExample","received_at_ms":1}}"#,
            "0a".repeat(20),
            "0b".repeat(20),
            "cd".repeat(32),
            "ee".repeat(20),
            "03".repeat(65),
        );
        let event: ObserverEvent = serde_json::from_str(&json).unwrap();
        let ObserverEvent::SetUpdateVote(vote) = event else {
            panic!("expected attestor_set_update")
        };
        let wire = convert_set_update(vote).unwrap();
        assert_eq!(wire.chain_key, 7);
        assert_eq!(wire.new_attestors, vec![[0x0A; 20], [0x0B; 20]]);
        assert_eq!(wire.nonce, [0xCD; 32]);
        assert_eq!(wire.signer, [0xEE; 20]);
        assert_eq!(wire.signature, [0x03; 65]);
    }

    #[test]
    fn malformed_set_update_hex_is_rejected() {
        let vote = ObserverSetUpdate {
            chain_key: 7,
            new_attestors: vec!["0x1234".into()], // wrong length
            nonce: format!("0x{}", "cd".repeat(32)),
            signer: format!("0x{}", "ee".repeat(20)),
            signature: format!("0x{}", "03".repeat(65)),
        };
        assert!(convert_set_update(vote).is_err());
    }

    #[test]
    fn malformed_hex_is_rejected() {
        let vote = ObserverVote {
            chain_key: 7,
            message_id: "0x1234".into(), // wrong length
            signer: format!("0x{}", "0a".repeat(20)),
            signature: format!("0x{}", "03".repeat(65)),
        };
        assert!(convert_vote(vote).is_err());
    }
}
