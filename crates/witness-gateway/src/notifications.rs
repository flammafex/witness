// WebSocket notification broadcast system
//
// This module handles broadcasting real-time notifications to connected WebSocket clients.

use std::collections::HashSet;
use tokio::sync::broadcast;
use witness_core::{
    AnchorCompletedPayload, AttestationBatch, AttestationPayload, BatchClosedPayload,
    ConnectedPayload, NotificationType, WsNotification, WsPayload,
};

/// Capacity for the broadcast channel
const BROADCAST_CHANNEL_CAPACITY: usize = 1024;

/// Notification broadcaster for WebSocket clients
#[derive(Clone)]
pub struct NotificationBroadcaster {
    sender: broadcast::Sender<WsNotification>,
    network_id: String,
}

impl NotificationBroadcaster {
    /// Create a new notification broadcaster
    pub fn new(network_id: String) -> Self {
        let (sender, _) = broadcast::channel(BROADCAST_CHANNEL_CAPACITY);
        Self { sender, network_id }
    }

    /// Subscribe to notifications
    pub fn subscribe(&self) -> broadcast::Receiver<WsNotification> {
        self.sender.subscribe()
    }

    /// Get the number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }

    /// Get the network ID
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Send a notification to all subscribers
    fn send(&self, notification: WsNotification) {
        // Ignore errors (no subscribers is fine)
        let _ = self.sender.send(notification);
    }

    /// Broadcast a new attestation notification
    pub fn notify_attestation(&self, hash: &[u8; 32], sequence: u64, anonymous: bool) {
        let notification = WsNotification {
            notification_type: NotificationType::Attestation,
            timestamp: current_timestamp(),
            payload: WsPayload::Attestation(AttestationPayload {
                hash: hex::encode(hash),
                sequence,
                network_id: self.network_id.clone(),
                anonymous,
            }),
        };
        self.send(notification);
        tracing::debug!(
            "Broadcasted attestation notification: hash={}, sequence={}",
            hex::encode(hash),
            sequence
        );
    }

    /// Broadcast a batch closed notification
    pub fn notify_batch_closed(&self, batch: &AttestationBatch) {
        let notification = WsNotification {
            notification_type: NotificationType::BatchClosed,
            timestamp: current_timestamp(),
            payload: WsPayload::BatchClosed(BatchClosedPayload {
                batch_id: batch.id,
                merkle_root: hex::encode(batch.merkle_root),
                attestation_count: batch.attestation_count,
                period_start: batch.period_start,
                period_end: batch.period_end,
            }),
        };
        self.send(notification);
        tracing::debug!(
            "Broadcasted batch closed notification: batch_id={}, attestations={}",
            batch.id,
            batch.attestation_count
        );
    }

    /// Broadcast an anchor completed notification
    pub fn notify_anchor_completed(
        &self,
        batch_id: u64,
        provider: &str,
        proof: serde_json::Value,
    ) {
        let notification = WsNotification {
            notification_type: NotificationType::AnchorCompleted,
            timestamp: current_timestamp(),
            payload: WsPayload::AnchorCompleted(AnchorCompletedPayload {
                batch_id,
                provider: provider.to_string(),
                proof,
            }),
        };
        self.send(notification);
        tracing::debug!(
            "Broadcasted anchor completed notification: batch_id={}, provider={}",
            batch_id,
            provider
        );
    }

    /// Create a connected notification for a new client
    pub fn create_connected_notification(
        &self,
        subscriptions: Vec<NotificationType>,
    ) -> WsNotification {
        WsNotification {
            notification_type: NotificationType::Connected,
            timestamp: current_timestamp(),
            payload: WsPayload::Connected(ConnectedPayload {
                network_id: self.network_id.clone(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                subscriptions,
            }),
        }
    }
}

/// Client subscription state
pub struct ClientSubscription {
    subscriptions: HashSet<NotificationType>,
}

impl Default for ClientSubscription {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientSubscription {
    /// Create a new subscription with all notification types enabled
    pub fn new() -> Self {
        let mut subscriptions = HashSet::new();
        subscriptions.insert(NotificationType::Attestation);
        subscriptions.insert(NotificationType::BatchClosed);
        subscriptions.insert(NotificationType::AnchorCompleted);
        Self { subscriptions }
    }

    /// Check if a notification type is subscribed
    pub fn is_subscribed(&self, notification_type: &NotificationType) -> bool {
        // Connected is always sent
        if *notification_type == NotificationType::Connected {
            return true;
        }
        self.subscriptions.contains(notification_type)
    }

    /// Subscribe to notification types
    pub fn subscribe(&mut self, types: &[NotificationType]) {
        for t in types {
            if *t != NotificationType::Connected {
                self.subscriptions.insert(t.clone());
            }
        }
    }

    /// Unsubscribe from notification types
    pub fn unsubscribe(&mut self, types: &[NotificationType]) {
        for t in types {
            self.subscriptions.remove(t);
        }
    }

    /// Get list of current subscriptions
    pub fn list(&self) -> Vec<NotificationType> {
        self.subscriptions.iter().cloned().collect()
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadcaster_creation() {
        let broadcaster = NotificationBroadcaster::new("test-network".to_string());
        assert_eq!(broadcaster.network_id(), "test-network");
        assert_eq!(broadcaster.subscriber_count(), 0);
    }

    #[test]
    fn test_subscription_default() {
        let sub = ClientSubscription::new();
        assert!(sub.is_subscribed(&NotificationType::Attestation));
        assert!(sub.is_subscribed(&NotificationType::BatchClosed));
        assert!(sub.is_subscribed(&NotificationType::AnchorCompleted));
        assert!(sub.is_subscribed(&NotificationType::Connected)); // Always true
    }

    #[test]
    fn test_subscription_management() {
        let mut sub = ClientSubscription::new();

        // Unsubscribe from attestations
        sub.unsubscribe(&[NotificationType::Attestation]);
        assert!(!sub.is_subscribed(&NotificationType::Attestation));
        assert!(sub.is_subscribed(&NotificationType::BatchClosed));

        // Resubscribe
        sub.subscribe(&[NotificationType::Attestation]);
        assert!(sub.is_subscribed(&NotificationType::Attestation));
    }
}
