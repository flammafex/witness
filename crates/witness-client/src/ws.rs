//! WebSocket push events (`feature = "ws"`).

use std::time::Duration;

use futures_util::{SinkExt, Stream, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use witness_core::AttestationEvent;

use crate::error::{Error, Result};

/// Connect to `/ws/events` and return a stream of [`AttestationEvent`]s.
///
/// If `token` is supplied, performs the first-message auth handshake: the
/// server may first send `{"type":"auth_required"}`, to which the client
/// replies `{"token": ...}` within the server's 5s window. A close code of
/// 4001 indicates an auth failure.
pub async fn subscribe_events(
    gateway_url: &str,
    token: Option<String>,
) -> Result<impl Stream<Item = Result<AttestationEvent>>> {
    let url = format!("{}/ws/events", gateway_url.trim_end_matches('/'));
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .map_err(|e| Error::WebSocket(e.to_string()))?;

    let (mut sink, mut stream) = ws_stream.split();

    if let Some(token) = token {
        let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .map_err(|_| Error::WebSocket("auth handshake timed out".to_string()))?
            .ok_or_else(|| Error::WebSocket("connection closed during auth handshake".to_string()))?
            .map_err(|e| Error::WebSocket(e.to_string()))?;

        match first {
            Message::Text(text) => {
                let value: serde_json::Value =
                    serde_json::from_str(&text).map_err(Error::Decode)?;
                if value.get("type").and_then(|t| t.as_str()) == Some("auth_required") {
                    let reply = serde_json::json!({ "token": token });
                    sink.send(Message::Text(reply.to_string()))
                        .await
                        .map_err(|e| Error::WebSocket(e.to_string()))?;
                }
            }
            Message::Close(_) => {
                return Err(Error::WebSocket(
                    "server closed during auth handshake".to_string(),
                ));
            }
            _ => {}
        }
    }

    let events = stream.filter_map(|msg| async move {
        match msg {
            Ok(Message::Text(text)) => match serde_json::from_str::<AttestationEvent>(&text) {
                Ok(ev) => Some(Ok(ev)),
                Err(e) => Some(Err(Error::Decode(e))),
            },
            Ok(Message::Close(_)) => None,
            Err(e) => Some(Err(Error::WebSocket(e.to_string()))),
            _ => None,
        }
    });

    Ok(events)
}
