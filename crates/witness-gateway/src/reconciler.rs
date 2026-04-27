use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use crate::storage::Storage;

/// Background task that periodically reconciles Signed Tree Heads (STHs)
/// with federation partners.
pub struct Reconciler {
    storage: Arc<Storage>,
    cancel: CancellationToken,
}

impl Reconciler {
    pub fn new(storage: Arc<Storage>, cancel: CancellationToken) -> Self {
        Self { storage, cancel }
    }

    pub async fn run(self) {
        self.run_internal(Duration::from_secs(300)).await;
    }

    #[cfg(test)]
    async fn run_with_interval(self, interval: Duration) {
        self.run_internal(interval).await;
    }

    async fn run_internal(self, interval_duration: Duration) {
        let mut interval = tokio::time::interval(interval_duration);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    tracing::debug!("Reconciler tick: checking federation partners for newer STHs");

                    match self.reconcile_once().await {
                        Ok(()) => tracing::debug!("Reconciler tick completed"),
                        Err(e) => tracing::warn!("Reconciler tick failed: {}", e),
                    }
                }
                _ = self.cancel.cancelled() => {
                    tracing::info!("Reconciler shutting down gracefully");
                    break;
                }
            }
        }
    }

    async fn reconcile_once(&self) -> anyhow::Result<()> {
        // TODO: Implement federation partner STH reconciliation.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_storage() -> Arc<Storage> {
        let storage = Storage::new("sqlite::memory:").await.unwrap();
        storage.migrate().await.unwrap();
        Arc::new(storage)
    }

    #[tokio::test]
    async fn test_reconciler_starts_and_stops_on_cancellation() {
        let storage = setup_test_storage().await;
        let cancel = CancellationToken::new();
        let reconciler = Reconciler::new(storage, cancel.clone());

        let handle = tokio::spawn(reconciler.run());

        tokio::time::sleep(Duration::from_millis(50)).await;

        cancel.cancel();
        let result = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(
            result.is_ok(),
            "Reconciler should shut down within 5 seconds of cancellation"
        );
    }

    #[tokio::test]
    async fn test_reconciler_interval_fires() {
        let storage = setup_test_storage().await;
        let cancel = CancellationToken::new();
        let reconciler = Reconciler::new(storage, cancel.clone());

        let handle = tokio::spawn(reconciler.run_with_interval(Duration::from_millis(50)));

        tokio::time::sleep(Duration::from_millis(150)).await;

        cancel.cancel();
        let result = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(
            result.is_ok(),
            "Reconciler should complete after interval fires and cancellation"
        );
    }
}
