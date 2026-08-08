//! WebSocket push events (`feature = "ws"`).

use futures_util::{stream, SinkExt, Stream, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};
use url::Url;
use witness_core::AttestationEvent;

use crate::error::{Error, Result};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
type SocketSink = futures_util::stream::SplitSink<Socket, Message>;
type SocketStream = futures_util::stream::SplitStream<Socket>;

/// Convert a gateway URL into the events endpoint without concatenating URL
/// strings. In particular, this keeps a gateway mounted below a base path
/// (for example, `https://example.test/witness` →
/// `wss://example.test/witness/ws/events`).
fn websocket_events_url(gateway_url: &str) -> Result<Url> {
    let mut url = Url::parse(gateway_url).map_err(|error| Error::InvalidUrl(error.to_string()))?;

    let websocket_scheme = match url.scheme() {
        "http" => "ws",
        "https" => "wss",
        "ws" => "ws",
        "wss" => "wss",
        scheme => {
            return Err(Error::InvalidUrl(format!(
                "unsupported gateway URL scheme `{scheme}`"
            )))
        }
    };

    if url.host_str().is_none() {
        return Err(Error::InvalidUrl(
            "gateway URL must include a host".to_string(),
        ));
    }

    url.set_scheme(websocket_scheme)
        .map_err(|_| Error::InvalidUrl("failed to set WebSocket URL scheme".to_string()))?;

    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    path.push_str("ws/events");
    url.set_path(&path);

    Ok(url)
}

#[derive(Clone, Copy)]
enum HandshakeState {
    /// The first message is part of the handshake if it is an auth challenge,
    /// but it is also the first event when the gateway does not challenge.
    Pending,
    Complete {
        auth_replied: bool,
    },
}

struct EventStreamState {
    sink: SocketSink,
    stream: SocketStream,
    token: Option<String>,
    handshake: HandshakeState,
    terminated: bool,
}

impl EventStreamState {
    async fn next_item(mut self) -> Option<(Result<AttestationEvent>, Self)> {
        if self.terminated {
            return None;
        }

        loop {
            let message = match self.next_message().await {
                Ok(Some(message)) => message,
                Ok(None) => return None,
                Err(error) => return Some(self.finish_with_error(error)),
            };

            match message {
                Message::Text(text) => {
                    if self.is_auth_challenge(&text) {
                        let should_reply = match self.handshake {
                            HandshakeState::Pending => true,
                            HandshakeState::Complete { auth_replied } => !auth_replied,
                        };
                        let Some(token) = self.token.clone() else {
                            return Some(self.finish_with_error(Error::WebSocketAuth(
                                "gateway requires a WebSocket authentication token".to_string(),
                            )));
                        };
                        if should_reply {
                            let reply = serde_json::json!({ "token": token });
                            if let Err(error) =
                                self.sink.send(Message::Text(reply.to_string())).await
                            {
                                return Some(
                                    self.finish_with_error(Error::WebSocket(error.to_string())),
                                );
                            }
                            self.handshake = HandshakeState::Complete { auth_replied: true };
                        }
                        continue;
                    }

                    // This is deliberately done before decoding the event. If
                    // the gateway does not challenge, the first ordinary event
                    // is consumed and returned here rather than being dropped
                    // while probing for an auth challenge.
                    if matches!(self.handshake, HandshakeState::Pending) {
                        self.handshake = HandshakeState::Complete {
                            auth_replied: false,
                        };
                    }
                    return Some((
                        serde_json::from_str::<AttestationEvent>(&text).map_err(Error::Decode),
                        self,
                    ));
                }
                Message::Close(frame) => {
                    if frame
                        .as_ref()
                        .map(|frame| u16::from(frame.code) == 4001)
                        .unwrap_or(false)
                    {
                        return Some(self.finish_with_error(Error::WebSocketAuth(
                            "gateway rejected WebSocket authentication".to_string(),
                        )));
                    }

                    if matches!(self.handshake, HandshakeState::Pending) {
                        return Some(self.finish_with_error(Error::WebSocket(
                            "connection closed during auth handshake".to_string(),
                        )));
                    }
                    return None;
                }
                // Tungstenite handles protocol control frames while polling
                // the stream. They are not attestation events.
                Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
        }
    }

    async fn next_message(&mut self) -> Result<Option<Message>> {
        self.stream
            .next()
            .await
            .transpose()
            .map_err(|error| Error::WebSocket(error.to_string()))
    }

    fn is_auth_challenge(&self, text: &str) -> bool {
        serde_json::from_str::<serde_json::Value>(text)
            .ok()
            .and_then(|value| {
                value
                    .get("type")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned)
            })
            .as_deref()
            == Some("auth_required")
    }

    fn finish_with_error(mut self, error: Error) -> (Result<AttestationEvent>, Self) {
        self.terminated = true;
        (Err(error), self)
    }
}

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
    let url = websocket_events_url(gateway_url)?;
    let (ws_stream, _) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| Error::WebSocket(e.to_string()))?;

    let (sink, stream) = ws_stream.split();
    let state = EventStreamState {
        sink,
        stream,
        token,
        handshake: HandshakeState::Pending,
        terminated: false,
    };

    Ok(stream::unfold(state, |state| state.next_item()))
}

#[cfg(test)]
mod tests {
    use std::{future::Future, time::Duration};

    use futures_util::{SinkExt, StreamExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;
    use tokio_tungstenite::{
        accept_async,
        tungstenite::{protocol::frame::coding::CloseCode, protocol::CloseFrame, Message},
        WebSocketStream,
    };

    use super::{subscribe_events, websocket_events_url};
    use crate::Error;

    async fn spawn_server<F, Fut>(handler: F) -> (String, JoinHandle<()>)
    where
        F: FnOnce(WebSocketStream<TcpStream>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let socket = accept_async(stream).await.unwrap();
            handler(socket).await;
        });
        (format!("ws://{address}"), task)
    }

    fn event_json() -> String {
        serde_json::json!({
            "type": "attestation_created",
            "hash": "0707070707070707070707070707070707070707070707070707070707070707",
            "timestamp": 42,
        })
        .to_string()
    }

    #[test]
    fn converts_gateway_schemes_and_preserves_base_path() {
        let cases = [
            ("http://example.test", "ws://example.test/ws/events"),
            (
                "https://example.test/tenant/",
                "wss://example.test/tenant/ws/events",
            ),
            ("ws://example.test/base", "ws://example.test/base/ws/events"),
            (
                "wss://example.test/base/",
                "wss://example.test/base/ws/events",
            ),
        ];

        for (gateway, expected) in cases {
            assert_eq!(websocket_events_url(gateway).unwrap().as_str(), expected);
        }
    }

    #[test]
    fn rejects_invalid_and_unsupported_gateway_urls() {
        for gateway in ["ftp://example.test", "not a URL", "http://"] {
            assert!(websocket_events_url(gateway).is_err(), "accepted {gateway}");
        }
    }

    #[tokio::test]
    async fn sends_token_after_auth_challenge() {
        let (url, server) = spawn_server(|mut socket| async move {
            socket
                .send(Message::Text(r#"{"type":"auth_required"}"#.to_string()))
                .await
                .unwrap();
            let reply = socket.next().await.unwrap().unwrap();
            let Message::Text(reply) = reply else {
                panic!("expected token reply");
            };
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&reply)
                    .unwrap()
                    .get("token")
                    .and_then(|token| token.as_str()),
                Some("secret")
            );
            socket.send(Message::Text(event_json())).await.unwrap();
        })
        .await;

        let mut events = Box::pin(
            subscribe_events(&url, Some("secret".to_string()))
                .await
                .unwrap(),
        );
        let event = events.next().await.unwrap().unwrap();
        assert_eq!(event.timestamp, 42);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn preserves_first_event_when_token_is_optional_and_gateway_does_not_challenge() {
        let (url, server) = spawn_server(|mut socket| async move {
            socket.send(Message::Text(event_json())).await.unwrap();
        })
        .await;

        let mut events = Box::pin(
            subscribe_events(&url, Some("unused".to_string()))
                .await
                .unwrap(),
        );
        let event = events.next().await.unwrap().unwrap();
        assert_eq!(event.event_type, "attestation_created");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn optional_token_does_not_expire_idle_non_auth_subscription() {
        let (url, server) = spawn_server(|mut socket| async move {
            tokio::time::sleep(Duration::from_millis(5_100)).await;
            socket.send(Message::Text(event_json())).await.unwrap();
        })
        .await;

        let mut events = Box::pin(
            subscribe_events(&url, Some("unused".to_string()))
                .await
                .unwrap(),
        );
        let event = events.next().await.unwrap().unwrap();
        assert_eq!(event.event_type, "attestation_created");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn unauthenticated_challenge_yields_typed_error_and_terminates() {
        let (url, server) = spawn_server(|mut socket| async move {
            socket
                .send(Message::Text(r#"{"type":"auth_required"}"#.to_string()))
                .await
                .unwrap();
            let _ = tokio::time::timeout(Duration::from_millis(100), socket.next()).await;
        })
        .await;

        let mut events = Box::pin(subscribe_events(&url, None).await.unwrap());
        let item = events.next().await.unwrap();
        assert!(matches!(item, Err(Error::WebSocketAuth(_))));
        drop(events);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn close_code_4001_yields_typed_auth_error() {
        let (url, server) = spawn_server(|mut socket| async move {
            socket
                .send(Message::Close(Some(CloseFrame {
                    code: CloseCode::Library(4001),
                    reason: "Unauthorized".into(),
                })))
                .await
                .unwrap();
        })
        .await;

        let mut events = Box::pin(subscribe_events(&url, None).await.unwrap());
        let item = events.next().await.unwrap();
        assert!(matches!(item, Err(Error::WebSocketAuth(_))));
        server.await.unwrap();
    }
}
