#![allow(dead_code)]

use anyhow::Result;
use async_trait::async_trait;
use witness_core::{Attestation, SignResponse, WitnessInfo};

use crate::storage::LogState;

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
    async fn store_attestation(
        &self,
        signed: &witness_core::SignedAttestation,
        status: Option<&str>,
    ) -> Result<()>;
    async fn get_attestation(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<witness_core::SignedAttestation>>;
    async fn get_log_state(&self, network_id: &str) -> Result<Option<LogState>>;
    async fn update_log_state(
        &self,
        network_id: &str,
        root: &[u8; 32],
        tree_size: u64,
    ) -> Result<()>;
}

#[async_trait]
impl StorageTrait for crate::storage::Storage {
    async fn check_duplicate(&self, hash: &[u8; 32]) -> Result<bool> {
        self.check_duplicate(hash).await
    }

    async fn get_next_sequence(&self, network_id: &str) -> Result<u64> {
        self.get_next_sequence(network_id).await
    }

    async fn store_attestation(
        &self,
        signed: &witness_core::SignedAttestation,
        status: Option<&str>,
    ) -> Result<()> {
        self.store_attestation(signed, status).await
    }

    async fn get_attestation(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<witness_core::SignedAttestation>> {
        self.get_attestation(hash).await
    }

    async fn get_log_state(&self, network_id: &str) -> Result<Option<LogState>> {
        self.get_log_state(network_id).await
    }

    async fn update_log_state(
        &self,
        network_id: &str,
        root: &[u8; 32],
        tree_size: u64,
    ) -> Result<()> {
        self.update_log_state(network_id, root, tree_size).await
    }
}
