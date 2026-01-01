use anyhow::{Context, Result};
use blst::min_sig::{PublicKey as BlsPublicKey, SecretKey as BlsSecretKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use witness_core::SignatureScheme;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessNodeConfig {
    /// Unique identifier for this witness
    pub id: String,

    /// Signature scheme (ed25519 or bls)
    #[serde(default)]
    pub signature_scheme: SignatureScheme,

    /// Private key (hex encoded) - Ed25519 (32 bytes) or BLS (32 bytes)
    pub private_key: String,

    /// HTTP port to listen on
    #[serde(default = "default_port")]
    pub port: u16,

    /// Network ID this witness belongs to
    pub network_id: String,

    /// Maximum clock skew allowed (seconds)
    #[serde(default = "default_max_clock_skew")]
    pub max_clock_skew: u64,
}

fn default_port() -> u16 {
    3000
}

fn default_max_clock_skew() -> u64 {
    300 // 5 minutes
}

impl WitnessNodeConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;

        let config: WitnessNodeConfig = serde_json::from_str(&content)
            .with_context(|| "Failed to parse config JSON")?;

        // Validate private key
        match config.signature_scheme {
            SignatureScheme::Ed25519 => {
                config.ed25519_signing_key()
                    .with_context(|| "Invalid Ed25519 private key in configuration")?;
            }
            SignatureScheme::BLS => {
                config.bls_secret_key()
                    .with_context(|| "Invalid BLS private key in configuration")?;
            }
        }

        Ok(config)
    }

    // Ed25519 methods
    pub fn ed25519_signing_key(&self) -> Result<SigningKey> {
        let key_bytes = hex::decode(&self.private_key)
            .with_context(|| "Failed to decode private key")?;

        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Private key must be 32 bytes"))?;

        Ok(SigningKey::from_bytes(&key_array))
    }

    pub fn ed25519_verifying_key(&self) -> Result<VerifyingKey> {
        let signing_key = self.ed25519_signing_key()?;
        Ok(signing_key.verifying_key())
    }

    // BLS methods
    pub fn bls_secret_key(&self) -> Result<BlsSecretKey> {
        Ok(witness_core::decode_bls_secret_key(&self.private_key)?)
    }

    pub fn bls_public_key(&self) -> Result<BlsPublicKey> {
        let secret_key = self.bls_secret_key()?;
        Ok(secret_key.sk_to_pk())
    }

    // Generic methods
    pub fn public_key(&self) -> String {
        match self.signature_scheme {
            SignatureScheme::Ed25519 => {
                self.ed25519_verifying_key()
                    .map(|k| witness_core::encode_public_key(&k))
                    .unwrap_or_else(|_| "invalid".to_string())
            }
            SignatureScheme::BLS => {
                self.bls_public_key()
                    .map(|k| witness_core::encode_bls_public_key(&k))
                    .unwrap_or_else(|_| "invalid".to_string())
            }
        }
    }

}
