//! Prometheus metrics for Witness Gateway

use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::time::Instant;

/// Initialize the Prometheus metrics exporter
pub fn init_metrics() -> PrometheusHandle {
    PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus recorder")
}

/// Record a successful attestation
pub fn record_attestation() {
    counter!("witness_attestations_total").increment(1);
}

/// Record signatures collected from witnesses
pub fn record_signatures(witness_id: &str) {
    counter!("witness_signatures_collected", "witness" => witness_id.to_string()).increment(1);
}

/// Record a batch creation
pub fn record_batch() {
    counter!("witness_batches_total").increment(1);
}

/// Record an external anchor
pub fn record_anchor(provider: &str) {
    counter!("witness_external_anchors_total", "provider" => provider.to_string()).increment(1);
}

/// Update the 24h attestation gauge
pub fn set_attestations_24h(count: u64) {
    gauge!("witness_attestations_24h").set(count as f64);
}

/// Update witness health status
pub fn set_witness_health(witness_id: &str, healthy: bool) {
    gauge!("witness_witness_health", "witness" => witness_id.to_string())
        .set(if healthy { 1.0 } else { 0.0 });
}

/// Update uptime gauge
pub fn set_uptime(seconds: u64) {
    gauge!("witness_uptime_seconds").set(seconds as f64);
}

/// Helper for timing request duration
pub struct RequestTimer {
    start: Instant,
    endpoint: &'static str,
}

impl RequestTimer {
    pub fn new(endpoint: &'static str) -> Self {
        Self {
            start: Instant::now(),
            endpoint,
        }
    }
}

impl Drop for RequestTimer {
    fn drop(&mut self) {
        let duration = self.start.elapsed().as_secs_f64();
        histogram!("witness_request_duration_seconds", "endpoint" => self.endpoint)
            .record(duration);
    }
}
