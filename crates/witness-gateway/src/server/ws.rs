use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast;

use super::{AttestationEvent, CoreState};

pub(super) async fn ws_events_handler(
    ws: WebSocketUpgrade,
    State(state): State<CoreState>,
) -> impl IntoResponse {
    let token = state.ws_auth_token.clone();
    ws.on_upgrade(move |socket| handle_ws_connection(socket, state.event_tx.subscribe(), token))
}

// ============================================================================
// WebSocket handler
// ============================================================================

pub(super) async fn handle_ws_connection(
    socket: WebSocket,
    mut event_rx: broadcast::Receiver<AttestationEvent>,
    required_token: Option<Arc<str>>,
) {
    let (mut sender, mut receiver) = socket.split();

    tracing::info!("WebSocket client connected");

    // First-message authentication: if a token is configured, challenge the client before
    // forwarding any events.
    if let Some(ref expected_token) = required_token {
        if sender
            .send(Message::Text(r#"{"type":"auth_required"}"#.to_string()))
            .await
            .is_err()
        {
            return;
        }

        let auth_msg = tokio::time::timeout(Duration::from_secs(5), receiver.next()).await;

        match auth_msg {
            Ok(Some(Ok(Message::Text(text)))) => {
                let provided = serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .and_then(|v| v.get("token").and_then(|t| t.as_str()).map(str::to_owned));

                if !provided
                    .as_deref()
                    .map(|t| witness_core::constant_time_eq(t, expected_token))
                    .unwrap_or(false)
                {
                    tracing::warn!("WebSocket client failed authentication");
                    let _ = sender
                        .send(Message::Close(Some(CloseFrame {
                            code: 4001,
                            reason: "Unauthorized".into(),
                        })))
                        .await;
                    return;
                }
                tracing::info!("WebSocket client authenticated");
            }
            _ => {
                tracing::warn!("WebSocket auth timeout or protocol error");
                return;
            }
        }
    }

    let send_task = tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            match serde_json::to_string(&event) {
                Ok(json) => {
                    if sender.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to serialize event: {}", e);
                }
            }
        }
    });

    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Close(_)) => {
                tracing::info!("WebSocket client sent close frame");
                break;
            }
            Ok(Message::Ping(data)) => {
                tracing::debug!("Received ping: {:?}", data);
            }
            Err(e) => {
                tracing::debug!("WebSocket receive error: {}", e);
                break;
            }
            _ => {}
        }
    }

    send_task.abort();
    tracing::info!("WebSocket client disconnected");
}
