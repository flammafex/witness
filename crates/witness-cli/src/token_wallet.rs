//! Token wallet for caching Freebird tokens
//!
//! Stores tokens locally so users can pre-fetch tokens for offline or bulk use.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use witness_core::FreebirdToken;

/// Token wallet stored on disk
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenWallet {
    /// Available tokens indexed by issuer_id
    pub tokens: Vec<StoredToken>,
}

/// A token stored in the wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    pub token: FreebirdToken,
    /// When this token was acquired (Unix timestamp)
    pub acquired_at: u64,
    /// Whether this token has been used
    pub used: bool,
}

impl TokenWallet {
    /// Get the wallet file path
    pub fn wallet_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
            .context("Could not determine config directory")?;

        let witness_dir = config_dir.join("witness");
        fs::create_dir_all(&witness_dir).context("Failed to create witness config directory")?;

        Ok(witness_dir.join("token_wallet.json"))
    }

    /// Load the wallet from disk, or create empty wallet if it doesn't exist
    pub fn load() -> Result<Self> {
        let path = Self::wallet_path()?;

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&path).context("Failed to read token wallet")?;

        let wallet: TokenWallet =
            serde_json::from_str(&content).context("Failed to parse token wallet")?;

        Ok(wallet)
    }

    /// Save the wallet to disk
    pub fn save(&self) -> Result<()> {
        let path = Self::wallet_path()?;
        let content = serde_json::to_string_pretty(self)?;
        fs::write(&path, content).context("Failed to write token wallet")?;
        Ok(())
    }

    /// Add a token to the wallet
    pub fn add_token(&mut self, token: FreebirdToken) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.tokens.push(StoredToken {
            token,
            acquired_at: now,
            used: false,
        });
    }

    /// Get an unused, unexpired token for the given issuer (or any issuer if None)
    ///
    /// Marks the token as used and saves the wallet.
    pub fn take_token(&mut self, issuer_id: Option<&str>) -> Result<Option<FreebirdToken>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Find first unused, unexpired token matching issuer
        let token_idx = self.tokens.iter().position(|t| {
            !t.used
                && t.token.exp > now
                && issuer_id.map_or(true, |id| t.token.issuer_id == id)
        });

        if let Some(idx) = token_idx {
            self.tokens[idx].used = true;
            let token = self.tokens[idx].token.clone();
            self.save()?;
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }

    /// Get count of available (unused, unexpired) tokens
    pub fn available_count(&self, issuer_id: Option<&str>) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.tokens
            .iter()
            .filter(|t| {
                !t.used
                    && t.token.exp > now
                    && issuer_id.map_or(true, |id| t.token.issuer_id == id)
            })
            .count()
    }

    /// Remove used and expired tokens
    pub fn cleanup(&mut self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let before = self.tokens.len();
        self.tokens.retain(|t| !t.used && t.token.exp > now);
        before - self.tokens.len()
    }

    /// List all tokens with their status
    pub fn list(&self) -> Vec<TokenInfo> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.tokens
            .iter()
            .map(|t| TokenInfo {
                issuer_id: t.token.issuer_id.clone(),
                exp: t.token.exp,
                acquired_at: t.acquired_at,
                used: t.used,
                expired: t.token.exp <= now,
            })
            .collect()
    }
}

/// Summary info about a token
#[derive(Debug)]
pub struct TokenInfo {
    pub issuer_id: String,
    pub exp: u64,
    pub acquired_at: u64,
    pub used: bool,
    pub expired: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_operations() {
        let mut wallet = TokenWallet::default();

        // Add a token
        let token = FreebirdToken {
            token_b64: "test_token".to_string(),
            issuer_id: "test:issuer:v1".to_string(),
            exp: u64::MAX, // Far future
        };

        wallet.add_token(token.clone());
        assert_eq!(wallet.available_count(None), 1);
        assert_eq!(wallet.available_count(Some("test:issuer:v1")), 1);
        assert_eq!(wallet.available_count(Some("other:issuer")), 0);

        // Take the token
        let taken = wallet.take_token(None).unwrap();
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().issuer_id, "test:issuer:v1");

        // Token should now be marked as used
        assert_eq!(wallet.available_count(None), 0);
    }
}
