use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use witness_core::{NotificationType, WsNotification, WsSubscription};

pub async fn run(
    gateway_url: &str,
    types: &[String],
    output_format: &str,
    count: Option<usize>,
) -> Result<()> {
    // Convert HTTP URL to WebSocket URL
    let ws_url = if gateway_url.starts_with("https://") {
        gateway_url.replace("https://", "wss://")
    } else if gateway_url.starts_with("http://") {
        gateway_url.replace("http://", "ws://")
    } else {
        format!("ws://{}", gateway_url)
    };

    let ws_url = format!("{}/v1/ws", ws_url.trim_end_matches('/'));

    if output_format == "text" {
        println!("Connecting to {}...", ws_url);
    }

    // Connect to WebSocket
    let (ws_stream, _) = connect_async(&ws_url)
        .await
        .context("Failed to connect to WebSocket")?;

    let (mut write, mut read) = ws_stream.split();

    // Parse subscription types
    let subscribe_types: Vec<NotificationType> = types
        .iter()
        .filter_map(|t| match t.to_lowercase().as_str() {
            "attestation" | "attestations" => Some(NotificationType::Attestation),
            "batch" | "batch_closed" => Some(NotificationType::BatchClosed),
            "anchor" | "anchor_completed" => Some(NotificationType::AnchorCompleted),
            _ => {
                eprintln!("Warning: Unknown notification type '{}', ignoring", t);
                None
            }
        })
        .collect();

    // If specific types were requested, send subscription message
    if !subscribe_types.is_empty() {
        let sub_msg = WsSubscription {
            subscribe: subscribe_types.clone(),
            unsubscribe: vec![],
        };
        let msg = serde_json::to_string(&sub_msg)?;
        write.send(Message::Text(msg)).await?;

        if output_format == "text" {
            println!("Subscribed to: {:?}", subscribe_types);
        }
    }

    if output_format == "text" {
        println!("Listening for notifications... (Ctrl+C to stop)");
        println!();
    }

    let mut received_count = 0;

    // Read notifications
    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Ok(notification) = serde_json::from_str::<WsNotification>(&text) {
                    received_count += 1;
                    display_notification(&notification, output_format)?;

                    // Check if we've received enough
                    if let Some(max) = count {
                        if received_count >= max {
                            if output_format == "text" {
                                println!("\nReceived {} notifications, exiting.", max);
                            }
                            break;
                        }
                    }
                }
            }
            Ok(Message::Close(_)) => {
                if output_format == "text" {
                    println!("Connection closed by server");
                }
                break;
            }
            Ok(Message::Ping(data)) => {
                write.send(Message::Pong(data)).await.ok();
            }
            Err(e) => {
                if output_format == "text" {
                    eprintln!("WebSocket error: {}", e);
                }
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

fn display_notification(notification: &WsNotification, format: &str) -> Result<()> {
    match format {
        "json" => {
            println!("{}", serde_json::to_string(&notification)?);
        }
        "text" => {
            let time = format_timestamp(notification.timestamp);
            match &notification.payload {
                witness_core::WsPayload::Connected(payload) => {
                    println!("[{}] Connected to network: {}", time, payload.network_id);
                    println!("  Version: {}", payload.version);
                    println!(
                        "  Subscriptions: {:?}",
                        payload.subscriptions
                    );
                    println!();
                }
                witness_core::WsPayload::Attestation(payload) => {
                    let anon = if payload.anonymous { " (anonymous)" } else { "" };
                    println!(
                        "[{}] New attestation{}:",
                        time, anon
                    );
                    println!("  Hash:     {}", payload.hash);
                    println!("  Sequence: {}", payload.sequence);
                    println!("  Network:  {}", payload.network_id);
                    println!();
                }
                witness_core::WsPayload::BatchClosed(payload) => {
                    println!("[{}] Batch closed:", time);
                    println!("  Batch ID:     {}", payload.batch_id);
                    println!("  Merkle Root:  {}", payload.merkle_root);
                    println!("  Attestations: {}", payload.attestation_count);
                    println!(
                        "  Period:       {} - {}",
                        format_timestamp(payload.period_start),
                        format_timestamp(payload.period_end)
                    );
                    println!();
                }
                witness_core::WsPayload::AnchorCompleted(payload) => {
                    println!("[{}] External anchor completed:", time);
                    println!("  Batch ID: {}", payload.batch_id);
                    println!("  Provider: {}", payload.provider);
                    println!("  Proof:    {}", payload.proof);
                    println!();
                }
            }
        }
        _ => {
            anyhow::bail!("Invalid output format: {}", format);
        }
    }

    Ok(())
}

fn format_timestamp(timestamp: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};

    let datetime = UNIX_EPOCH + Duration::from_secs(timestamp);

    // Try to format as local time
    match datetime.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs();
            let hours = (secs % 86400) / 3600;
            let mins = (secs % 3600) / 60;
            let s = secs % 60;
            format!("{:02}:{:02}:{:02}", hours, mins, s)
        }
        Err(_) => format!("{}", timestamp),
    }
}
