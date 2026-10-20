//! Prometheus metrics for the observer node.

use std::sync::atomic::{AtomicI64, AtomicU64};
use std::sync::Arc;

use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

#[derive(Debug)]
pub struct ObserverMetrics {
    registry: Registry,
    /// Observed gossip frames by kind + outcome. `rate()` of `outcome="accepted"` going flat
    /// while the chain has Outbox activity is the "observer stopped observing" alert.
    events: Family<LabelEvent, Counter<u64, AtomicU64>>,
    /// Currently connected WS subscribers.
    ws_clients: Gauge<i64, AtomicI64>,
    /// Clients disconnected for falling behind the fire-hose (lagged past the hub ring).
    ws_client_lag_drops: Counter<u64, AtomicU64>,
    /// Peers this observer sees subscribed to the message-vote topic, per chain.
    subscribed_peers: Family<LabelChain, Gauge<i64, AtomicI64>>,
    /// Reobservation requests published on behalf of WS clients (only when `allow_publish`).
    reobservations_published: Counter<u64, AtomicU64>,
}

impl ObserverMetrics {
    #[must_use]
    pub fn new() -> Arc<Self> {
        let mut registry = Registry::default();
        let events = Family::default();
        registry.register(
            "observer_events",
            "Observed gossip frames by kind and outcome",
            events.clone(),
        );
        let ws_clients = Gauge::default();
        registry.register(
            "observer_ws_clients",
            "Currently connected WebSocket subscribers",
            ws_clients.clone(),
        );
        let ws_client_lag_drops = Counter::default();
        registry.register(
            "observer_ws_client_lag_drops",
            "Subscribers disconnected for falling behind the event fire-hose",
            ws_client_lag_drops.clone(),
        );
        let subscribed_peers = Family::default();
        registry.register(
            "observer_subscribed_peers",
            "Peers seen subscribed to the message-vote topic per chain_key",
            subscribed_peers.clone(),
        );
        let reobservations_published = Counter::default();
        registry.register(
            "observer_reobservations_published",
            "Reobservation requests gossiped on behalf of WS clients",
            reobservations_published.clone(),
        );

        Arc::new(Self {
            registry,
            events,
            ws_clients,
            ws_client_lag_drops,
            subscribed_peers,
            reobservations_published,
        })
    }

    #[must_use]
    pub fn encode(&self) -> String {
        let mut buffer = String::new();
        prometheus_client::encoding::text::encode(&mut buffer, &self.registry)
            .expect("metrics encoding is infallible for well-formed registries");
        buffer
    }

    pub fn inc_event(&self, kind: EventLabelKind, outcome: EventOutcome) {
        self.events
            .get_or_create(&LabelEvent { kind, outcome })
            .inc();
    }

    pub fn set_ws_clients(&self, count: i64) {
        self.ws_clients.set(count);
    }

    pub fn inc_lag_drop(&self) {
        self.ws_client_lag_drops.inc();
    }

    pub fn set_subscribed_peers(&self, chain_key: u64, count: i64) {
        self.subscribed_peers
            .get_or_create(&LabelChain { chain_key })
            .set(count);
    }

    pub fn inc_reobservation_published(&self) {
        self.reobservations_published.inc();
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum EventLabelKind {
    MessageVote,
    ReobservationRequest,
    SetUpdateVote,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum EventOutcome {
    /// Well-formed frame streamed to subscribers (independent of `signature_valid`).
    Accepted,
    /// Undecodable / topic-mismatched frame, Rejected to gossipsub.
    Rejected,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct LabelChain {
    pub chain_key: u64,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct LabelEvent {
    pub kind: EventLabelKind,
    pub outcome: EventOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_encode_round_trips() {
        let m = ObserverMetrics::new();
        m.inc_event(EventLabelKind::MessageVote, EventOutcome::Accepted);
        m.set_ws_clients(2);
        m.set_subscribed_peers(102, 5);
        let body = m.encode();
        assert!(body.contains("observer_events"));
        assert!(body.contains("observer_ws_clients"));
        assert!(body.contains("observer_subscribed_peers"));
    }
}
