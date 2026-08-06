#![allow(dead_code)]

use anyhow::Result;
use async_trait::async_trait;
use witness_core::{Attestation, SignResponse, WitnessInfo};

/// Abstraction over witness signature collection, primarily for testing.
#[async_trait]
pub trait WitnessClientTrait: Send + Sync {
    async fn request_signature(
        &self,
        witness: &WitnessInfo,
        attestation: &Attestation,
    ) -> Result<SignResponse>;
}

#[async_trait]
impl WitnessClientTrait for crate::node_client::NodeClient {
    async fn request_signature(
        &self,
        witness: &WitnessInfo,
        attestation: &Attestation,
    ) -> Result<SignResponse> {
        crate::node_client::NodeClient::request_signature(self, witness, attestation).await
    }
}
