//! The spy's outward-facing event schema (JSON over WebSocket) and subscription filters.
//!
//! Deliberately dumb, like Wormhole's Spy: events are *verified observations* (decoded envelope
//! plus ECDSA recovery), never aggregation or quorum judgment. Consumers count signers themselves.
//! `signature_valid` asserts only that the signature recovers to `signer` over `message_id` (also
//! the vote's `message_hash` field, kept for wire compatibility — see that field's doc);
//! active-set membership is the consumer's problem (checking it would give the spy a chain-RPC
//! dependency, and the mesh's real validators enforce it anyway).

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// One observed p2p event, serialized as `{"type": "...", ...}`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SpyEvent {
    /// An attestor's ECDSA vote for a published message, seen on `{chain_key}/message-votes/v1`.
    MessageVote {
        chain_key: u64,
        /// `0x`-prefixed 32-byte hex — also the digest the signature covers (raw, no EIP-191)
        /// since asc-contracts #54.
        message_id: String,
        /// Equal to `message_id` — kept as a separate field for wire compatibility with existing
        /// consumers of this API; asc-contracts #54 removed the distinct six-field hash this used
        /// to carry (`Inbox.validateVotes` now takes `messageId` itself as the signed digest).
        message_hash: String,
        /// Recovered signer when recovery succeeds; the envelope's advertised signer (with
        /// `signature_valid: false`) when it does not.
        signer: String,
        /// Whether the 65-byte signature recovers to `signer` over `message_id`.
        signature_valid: bool,
        /// `0x`-prefixed 65-byte hex — carried so consumers can re-verify independently.
        signature: String,
        /// The gossipsub peer we received the frame from (propagation source, not necessarily
        /// the original publisher).
        source_peer: String,
        received_at_ms: u64,
    },
    /// A relayer's liveness-recovery request for a stalled message, seen on
    /// `{chain_key}/reobservation/v1`.
    ReobservationRequest {
        chain_key: u64,
        message_id: String,
        tx_hash: String,
        block_height: u64,
        source_peer: String,
        received_at_ms: u64,
    },
    /// An attestor's ECDSA vote proposing a new destination attestor set, seen on
    /// `{chain_key}/attestor-set-update/v1`. Streamed raw: the spy has no destination-chain
    /// connection and cannot recompute the update digest, so (unlike `MessageVote`) it does not
    /// annotate `signature_valid` — the relayer's set-update aggregator re-derives the digest from
    /// chain state and recovers the signer itself.
    #[serde(rename = "attestor_set_update")]
    SetUpdateVote {
        chain_key: u64,
        /// Proposed attestor set, each `0x`-prefixed 20-byte hex, in canonical (ascending) order.
        new_attestors: Vec<String>,
        /// `0x`-prefixed 32-byte hex — the `attestorSetUpdateNonce` this vote was signed against.
        nonce: String,
        /// `0x`-prefixed 20-byte hex — the envelope's advertised signer.
        signer: String,
        /// `0x`-prefixed 65-byte hex — carried so the relayer can recover + re-verify independently.
        signature: String,
        /// The gossipsub peer we received the frame from (propagation source).
        source_peer: String,
        received_at_ms: u64,
    },
    /// Per-chain mesh visibility: how many peers this spy currently sees subscribed to the
    /// message-vote topic. Emitted on every change.
    PeerStatus {
        chain_key: u64,
        subscribed_peers: usize,
        received_at_ms: u64,
    },
}

impl SpyEvent {
    pub fn message_vote(
        chain_key: u64,
        message_id: [u8; 32],
        signer: alloy::primitives::Address,
        signature_valid: bool,
        signature: &[u8; 65],
        source_peer: &libp2p::PeerId,
    ) -> Self {
        Self::MessageVote {
            chain_key,
            message_id: format!("0x{}", hex::encode(message_id)),
            // Equal to `message_id` (see that field's doc) — asc-contracts #54 removed the
            // distinct hash this used to carry.
            message_hash: format!("0x{}", hex::encode(message_id)),
            signer: format!("{signer:?}"),
            signature_valid,
            signature: format!("0x{}", hex::encode(signature)),
            source_peer: source_peer.to_string(),
            received_at_ms: now_ms(),
        }
    }

    pub fn reobservation_request(
        chain_key: u64,
        message_id: [u8; 32],
        tx_hash: [u8; 32],
        block_height: u64,
        source_peer: &libp2p::PeerId,
    ) -> Self {
        Self::ReobservationRequest {
            chain_key,
            message_id: format!("0x{}", hex::encode(message_id)),
            tx_hash: format!("0x{}", hex::encode(tx_hash)),
            block_height,
            source_peer: source_peer.to_string(),
            received_at_ms: now_ms(),
        }
    }

    pub fn set_update_vote(
        chain_key: u64,
        new_attestors: &[[u8; 20]],
        nonce: [u8; 32],
        signer: [u8; 20],
        signature: &[u8; 65],
        source_peer: &libp2p::PeerId,
    ) -> Self {
        Self::SetUpdateVote {
            chain_key,
            new_attestors: new_attestors
                .iter()
                .map(|a| format!("0x{}", hex::encode(a)))
                .collect(),
            nonce: format!("0x{}", hex::encode(nonce)),
            signer: format!("0x{}", hex::encode(signer)),
            signature: format!("0x{}", hex::encode(signature)),
            source_peer: source_peer.to_string(),
            received_at_ms: now_ms(),
        }
    }

    pub fn peer_status(chain_key: u64, subscribed_peers: usize) -> Self {
        Self::PeerStatus {
            chain_key,
            subscribed_peers,
            received_at_ms: now_ms(),
        }
    }

    /// The chain this event concerns (every variant is chain-scoped).
    pub fn chain_key(&self) -> u64 {
        match self {
            Self::MessageVote { chain_key, .. }
            | Self::ReobservationRequest { chain_key, .. }
            | Self::SetUpdateVote { chain_key, .. }
            | Self::PeerStatus { chain_key, .. } => *chain_key,
        }
    }

    /// The `message_id` this event concerns, when it is message-scoped.
    pub fn message_id(&self) -> Option<&str> {
        match self {
            Self::MessageVote { message_id, .. }
            | Self::ReobservationRequest { message_id, .. } => Some(message_id),
            Self::SetUpdateVote { .. } | Self::PeerStatus { .. } => None,
        }
    }

    /// The filterable event-kind tag (matches the serialized `type` field).
    pub fn kind(&self) -> EventKind {
        match self {
            Self::MessageVote { .. } => EventKind::MessageVote,
            Self::ReobservationRequest { .. } => EventKind::ReobservationRequest,
            Self::SetUpdateVote { .. } => EventKind::SetUpdateVote,
            Self::PeerStatus { .. } => EventKind::PeerStatus,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    MessageVote,
    ReobservationRequest,
    #[serde(rename = "attestor_set_update")]
    SetUpdateVote,
    PeerStatus,
}

/// A client's subscribe frame: `{"subscribe": {...}}`. Empty/omitted fields mean "everything".
/// Re-sending replaces the connection's active filter.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    #[serde(default)]
    pub chain_keys: Vec<u64>,
    #[serde(default)]
    pub events: Vec<EventKind>,
    /// Single-message firehose (explorer detail views): only events for this `0x…` message id.
    /// `PeerStatus` events are not message-scoped and are filtered out when this is set.
    #[serde(default)]
    pub message_id: Option<String>,
}

impl Filter {
    pub fn matches(&self, event: &SpyEvent) -> bool {
        if !self.chain_keys.is_empty() && !self.chain_keys.contains(&event.chain_key()) {
            return false;
        }
        if !self.events.is_empty() && !self.events.contains(&event.kind()) {
            return false;
        }
        if let Some(want) = &self.message_id {
            return event
                .message_id()
                .is_some_and(|id| id.eq_ignore_ascii_case(want));
        }
        true
    }
}

/// Frames a client may send: a subscription filter, or (when the spy allows publishing) a
/// reobservation request to gossip on behalf of the client.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ClientFrame {
    Subscribe(Filter),
    PublishReobservation(PublishReobservation),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishReobservation {
    pub chain_key: u64,
    /// `0x`-prefixed 32-byte hex.
    pub message_id: String,
    /// `0x`-prefixed 32-byte hex.
    pub tx_hash: String,
    pub block_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vote(chain_key: u64, id_byte: u8) -> SpyEvent {
        SpyEvent::message_vote(
            chain_key,
            [id_byte; 32],
            alloy::primitives::Address::repeat_byte(0x11),
            true,
            &[0u8; 65],
            &libp2p::PeerId::random(),
        )
    }

    #[test]
    fn event_serializes_with_type_tag_and_hex_fields() {
        let json = serde_json::to_value(vote(102, 0x01)).unwrap();
        assert_eq!(json["type"], "message_vote");
        assert_eq!(json["chain_key"], 102);
        assert_eq!(json["message_id"], format!("0x{}", "01".repeat(32)));
        assert_eq!(json["signature_valid"], true);
        assert!(json["signature"].as_str().unwrap().starts_with("0x000000"));
    }

    #[test]
    fn set_update_vote_serializes_with_type_tag_and_hex_fields() {
        let event = SpyEvent::set_update_vote(
            7,
            &[[0x0A; 20], [0x0B; 20]],
            [0xCD; 32],
            [0xEE; 20],
            &[0x03; 65],
            &libp2p::PeerId::random(),
        );
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "attestor_set_update");
        assert_eq!(json["chain_key"], 7);
        assert_eq!(json["new_attestors"][0], format!("0x{}", "0a".repeat(20)));
        assert_eq!(json["new_attestors"][1], format!("0x{}", "0b".repeat(20)));
        assert_eq!(json["nonce"], format!("0x{}", "cd".repeat(32)));
        assert_eq!(json["signer"], format!("0x{}", "ee".repeat(20)));
        assert!(json["signature"].as_str().unwrap().starts_with("0x0303"));
        // Not message-scoped: excluded by a message_id filter, like peer_status.
        assert_eq!(event.kind(), EventKind::SetUpdateVote);
        assert_eq!(event.chain_key(), 7);
        assert!(event.message_id().is_none());
    }

    #[test]
    fn empty_filter_matches_everything() {
        let f = Filter::default();
        assert!(f.matches(&vote(102, 1)));
        assert!(f.matches(&SpyEvent::peer_status(7, 3)));
    }

    #[test]
    fn chain_key_and_kind_filters_apply() {
        let f = Filter {
            chain_keys: vec![102],
            events: vec![EventKind::MessageVote],
            message_id: None,
        };
        assert!(f.matches(&vote(102, 1)));
        assert!(!f.matches(&vote(7, 1)), "wrong chain");
        assert!(
            !f.matches(&SpyEvent::peer_status(102, 3)),
            "wrong event kind"
        );
    }

    #[test]
    fn message_id_filter_is_case_insensitive_and_excludes_unscoped_events() {
        let want = format!("0x{}", "01".repeat(32)).to_uppercase();
        let f = Filter {
            chain_keys: vec![],
            events: vec![],
            message_id: Some(want),
        };
        assert!(f.matches(&vote(102, 0x01)));
        assert!(!f.matches(&vote(102, 0x02)));
        assert!(
            !f.matches(&SpyEvent::peer_status(102, 3)),
            "peer_status is not message-scoped"
        );
    }

    #[test]
    fn client_frames_parse() {
        let sub: ClientFrame =
            serde_json::from_str(r#"{"subscribe":{"chain_keys":[102],"events":["message_vote"]}}"#)
                .unwrap();
        assert!(matches!(sub, ClientFrame::Subscribe(_)));

        let pubr: ClientFrame = serde_json::from_str(
            r#"{"publish_reobservation":{"chain_key":102,"message_id":"0x01","tx_hash":"0x02","block_height":5}}"#,
        )
        .unwrap();
        assert!(matches!(pubr, ClientFrame::PublishReobservation(_)));
    }
}
