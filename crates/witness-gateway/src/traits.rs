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
impl WitnessClientTrait for crate::witness_client::WitnessClient {
    async fn request_signature(
        &self,
        witness: &WitnessInfo,
        attestation: &Attestation,
    ) -> Result<SignResponse> {
        crate::witness_client::WitnessClient::request_signature(self, witness, attestation).await
    }
}

/// Abstraction over the persistence layer, primarily for testing.
#[async_trait]
pub trait StorageTrait: Send + Sync {
    async fn check_duplicate(&self, hash: &[u8; 32]) -> Result<bool>;
    async fn get_next_sequence(&self, network_id: &str) -> Result<u64>;
    async fn store_attestation(&self, signed: &witness_core::SignedAttestation) -> Result<()>;
    async fn get_attestation(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<witness_core::SignedAttestation>>;
}
