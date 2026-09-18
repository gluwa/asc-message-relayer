//! The spy's HTTP surface: `/ws` subscription API, `/health`, `/metrics`.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use message_relayer::health::Health;

use crate::events::{ClientFrame, Filter, PublishReobservation};
use crate::hub::Hub;
use crate::metrics::SpyMetrics;
use crate::swarm::PublishRequest;

/// Shared state behind the axum router.
#[derive(Clone)]
pub struct WsState {
    pub hub: Hub,
    pub metrics: Arc<SpyMetrics>,
    pub health: Arc<Health>,
    /// `None` when `allow_publish: false` — publish frames are refused.
    pub publish_tx: Option<mpsc::Sender<PublishRequest>>,
    /// The chain keys this spy observes; publish frames for other chains are refused up-front so
    /// the client gets a truthful ack instead of a silent swarm-side drop.
    pub chain_keys: Vec<u64>,
    pub max_clients: usize,
}

pub fn build_router(state: WsState) -> Router {
    Router::new()
        .route("/ws", get(ws_handler))
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

/// `200 ok` when every worker has made progress within the deadline, `200` naming degraded
/// workers (erroring but alive), `503` naming stale (silent) ones — the same two-tier verdict as
/// the relayer's `/health`; see `message_relayer::health`.
async fn health_handler(State(state): State<WsState>) -> axum::response::Response {
    let report = state.health.report();
    if !report.is_alive() {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            format!("stale workers: {}", report.stale.join(", ")),
        )
            .into_response();
    }
    if report.degraded.is_empty() {
        (axum::http::StatusCode::OK, "ok").into_response()
    } else {
        (
            axum::http::StatusCode::OK,
            format!("degraded workers: {}", report.degraded.join(", ")),
        )
            .into_response()
    }
}

async fn metrics_handler(State(state): State<WsState>) -> axum::response::Response {
    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )
        .body(axum::body::Body::from(state.metrics.encode()))
        .expect("static response builder")
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<WsState>,
) -> axum::response::Response {
    // Approximate admission control: the hub's receiver count is the live client count.
    if state.hub.subscriber_count() >= state.max_clients {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "subscriber limit reached",
        )
            .into_response();
    }
    ws.on_upgrade(move |socket| client_loop(socket, state))
}

/// One connected subscriber: forward hub events through the connection's filter; process
/// inbound `subscribe` / `publish_reobservation` frames. Fire-hose semantics — a client that
/// lags past the hub ring is disconnected (it reconnects and resumes from "now").
async fn client_loop(mut socket: WebSocket, state: WsState) {
    let mut rx = state.hub.subscribe();
    let mut filter = Filter::default();
    state
        .metrics
        .set_ws_clients(i64::try_from(state.hub.subscriber_count()).unwrap_or(i64::MAX));
    debug!("ws subscriber connected");

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Ok(event) => {
                        if !filter.matches(&event) {
                            continue;
                        }
                        let json = match serde_json::to_string(&*event) {
                            Ok(json) => json,
                            Err(err) => {
                                warn!(%err, "event serialization failed; skipping");
                                continue;
                            }
                        };
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break; // client went away
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                        state.metrics.inc_lag_drop();
                        warn!(missed, "subscriber lagged past the event ring — disconnecting");
                        let _ = socket
                            .send(Message::Text(
                                format!(r#"{{"error":"lagged","missed":{missed}}}"#).into(),
                            ))
                            .await;
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            inbound = socket.recv() => {
                let Some(Ok(msg)) = inbound else { break };
                match msg {
                    Message::Text(text) => handle_client_frame(&mut socket, &state, &mut filter, text.as_str()).await,
                    Message::Close(_) => break,
                    // Pings/pongs are handled by axum; binary frames are ignored.
                    _ => {}
                }
            }
        }
    }

    state
        .metrics
        .set_ws_clients(i64::try_from(state.hub.subscriber_count().saturating_sub(1)).unwrap_or(0));
    debug!("ws subscriber disconnected");
}

async fn handle_client_frame(
    socket: &mut WebSocket,
    state: &WsState,
    filter: &mut Filter,
    text: &str,
) {
    let frame: ClientFrame = match serde_json::from_str(text) {
        Ok(frame) => frame,
        Err(err) => {
            let _ = socket
                .send(Message::Text(
                    format!(r#"{{"error":"bad frame: {err}"}}"#).into(),
                ))
                .await;
            return;
        }
    };
    match frame {
        ClientFrame::Subscribe(new_filter) => {
            info!(?new_filter, "subscriber filter updated");
            *filter = new_filter;
            let _ = socket
                .send(Message::Text(r#"{"ack":{"subscribe":true}}"#.into()))
                .await;
        }
        ClientFrame::PublishReobservation(publish) => {
            let reply = match publish_reobservation(state, publish) {
                Ok(()) => r#"{"ack":{"publish_reobservation":true,"ok":true}}"#.to_string(),
                Err(err) => format!(
                    r#"{{"ack":{{"publish_reobservation":true,"ok":false,"error":"{err}"}}}}"#
                ),
            };
            let _ = socket.send(Message::Text(reply.into())).await;
        }
    }
}

/// Validate + queue a client's reobservation request for the swarm to gossip. Refused when
/// `allow_publish` is off (public read-only deployments).
fn publish_reobservation(state: &WsState, publish: PublishReobservation) -> anyhow::Result<()> {
    let Some(publish_tx) = &state.publish_tx else {
        anyhow::bail!("publishing is disabled on this spy (allow_publish: false)");
    };
    anyhow::ensure!(
        state.chain_keys.contains(&publish.chain_key),
        "chain_key {} is not observed by this spy",
        publish.chain_key
    );
    let request = write_ability::envelope::ReobservationRequest {
        chain_key: publish.chain_key,
        message_id: parse_hex32(&publish.message_id)
            .map_err(|e| anyhow::anyhow!("message_id: {e}"))?,
        tx_hash: parse_hex32(&publish.tx_hash).map_err(|e| anyhow::anyhow!("tx_hash: {e}"))?,
        block_height: publish.block_height,
    };
    publish_tx
        .try_send(PublishRequest { request })
        .map_err(|_| anyhow::anyhow!("publish queue full or spy shutting down"))?;
    Ok(())
}

fn parse_hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    anyhow::ensure!(hex_str.len() == 64, "expected 32-byte 0x hex string");
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex32_accepts_prefixed_and_rejects_short() {
        let ok = format!("0x{}", "ab".repeat(32));
        assert_eq!(parse_hex32(&ok).unwrap(), [0xAB; 32]);
        assert!(parse_hex32("0x1234").is_err());
        assert!(parse_hex32(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn publish_refused_when_disabled() {
        let state = WsState {
            hub: Hub::new(),
            metrics: SpyMetrics::new(),
            health: Health::new(message_relayer::health::PROGRESS_DEADLINE),
            publish_tx: None,
            chain_keys: vec![102],
            max_clients: 8,
        };
        let err = publish_reobservation(
            &state,
            PublishReobservation {
                chain_key: 102,
                message_id: format!("0x{}", "01".repeat(32)),
                tx_hash: format!("0x{}", "02".repeat(32)),
                block_height: 5,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("disabled"));
    }

    #[tokio::test]
    async fn publish_refused_for_unobserved_chain() {
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        let state = WsState {
            hub: Hub::new(),
            metrics: SpyMetrics::new(),
            health: Health::new(message_relayer::health::PROGRESS_DEADLINE),
            publish_tx: Some(tx),
            chain_keys: vec![102],
            max_clients: 8,
        };
        let err = publish_reobservation(
            &state,
            PublishReobservation {
                chain_key: 999,
                message_id: format!("0x{}", "01".repeat(32)),
                tx_hash: format!("0x{}", "02".repeat(32)),
                block_height: 5,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("not observed"));
    }

    #[tokio::test]
    async fn publish_queues_request_when_enabled() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let state = WsState {
            hub: Hub::new(),
            metrics: SpyMetrics::new(),
            health: Health::new(message_relayer::health::PROGRESS_DEADLINE),
            publish_tx: Some(tx),
            chain_keys: vec![102],
            max_clients: 8,
        };
        publish_reobservation(
            &state,
            PublishReobservation {
                chain_key: 102,
                message_id: format!("0x{}", "01".repeat(32)),
                tx_hash: format!("0x{}", "02".repeat(32)),
                block_height: 5,
            },
        )
        .unwrap();
        let queued = rx.recv().await.unwrap();
        assert_eq!(queued.request.chain_key, 102);
        assert_eq!(queued.request.message_id, [0x01; 32]);
        assert_eq!(queued.request.block_height, 5);
    }
}
