//! Fan-out hub: one broadcast channel from the swarm task to every WebSocket client.
//!
//! `tokio::sync::broadcast` gives fire-hose semantics for free: the swarm loop never blocks on a
//! slow consumer (send is non-blocking), and a subscriber that falls more than the channel
//! capacity behind observes `Lagged` — its connection handler disconnects it rather than serving
//! silently gappy data. Events are `Arc`ed so a burst fanned out to N clients clones pointers,
//! not JSON.

use std::sync::Arc;

use tokio::sync::broadcast;

use crate::events::ObserverEvent;

/// Capacity of the hub's broadcast ring. Sized for bursts (catch-up gossip after a mesh join can
/// deliver a few thousand votes at once); a consumer that can't drain this fast gets disconnected.
const HUB_CAPACITY: usize = 8_192;

#[derive(Clone)]
pub struct Hub {
    tx: broadcast::Sender<Arc<ObserverEvent>>,
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

impl Hub {
    #[must_use]
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(HUB_CAPACITY);
        Self { tx }
    }

    /// Publish an event to all current subscribers. A send with zero subscribers is not an
    /// error — the observer observes the mesh whether or not anyone is listening.
    pub fn publish(&self, event: ObserverEvent) {
        let _ = self.tx.send(Arc::new(event));
    }

    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<ObserverEvent>> {
        self.tx.subscribe()
    }

    /// Current subscriber count (drives the `observer_ws_clients` gauge).
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_reaches_subscribers_and_zero_subscribers_is_fine() {
        let hub = Hub::new();
        // No subscribers: must not error or panic.
        hub.publish(ObserverEvent::peer_status(1, 0));

        let mut rx = hub.subscribe();
        hub.publish(ObserverEvent::peer_status(102, 3));
        let got = rx.recv().await.unwrap();
        assert_eq!(got.chain_key(), 102);
    }
}
