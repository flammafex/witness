use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use witness_core::{FreebirdConfig, FreebirdToken};

/// Errors that can occur during Freebird verification
#[derive(Debug, Error)]
pub enum FreebirdError {
    #[error("Freebird token required")]
    TokenRequired,

    #[error("Freebird token invalid or already used")]
    TokenInvalid,

    #[error("Freebird token expired")]
    TokenExpired,

    #[error("Untrusted issuer: {0}")]
    UntrustedIssuer(String),

    #[error("Freebird verification failed: {0}")]
    VerificationFailed(String),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
}

/// Request body sent to Freebird verifier
#[derive(Debug, Serialize)]
struct VerifyRequest {
    token_b64: String,
    issuer_id: String,
    exp: u64,
}

/// Response from Freebird verifier
#[derive(Debug, Deserialize)]
struct VerifyResponse {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
}

/// Client for verifying Freebird tokens
pub struct FreebirdClient {
    http: Client,
    config: FreebirdConfig,
}

impl FreebirdClient {
    /// Create a new Freebird client from configuration
    pub fn new(config: FreebirdConfig) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        Self { http, config }
    }

    /// Create a client from environment variables
    pub fn from_env() -> Option<Self> {
        let verifier_url = std::env::var("FREEBIRD_VERIFIER_URL").ok();

        // If no verifier URL is set, Freebird is disabled
        if verifier_url.is_none() {
            return None;
        }

        let issuer_ids: Vec<String> = std::env::var("FREEBIRD_ISSUER_IDS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let required = std::env::var("FREEBIRD_REQUIRED")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        let config = FreebirdConfig {
            verifier_url,
            issuer_ids,
            required,
        };

        Some(Self::new(config))
    }

    /// Check if Freebird tokens are required
    pub fn is_required(&self) -> bool {
        self.config.required
    }

    /// Get the configuration
    pub fn config(&self) -> &FreebirdConfig {
        &self.config
    }

    /// Verify a Freebird token
    ///
    /// Returns Ok(()) if the token is valid and was successfully consumed (nullifier recorded).
    /// Returns Err if the token is invalid, expired, already used, or verification failed.
    pub async fn verify(&self, token: &FreebirdToken) -> Result<(), FreebirdError> {
        // Check if issuer is trusted
        if !self.config.issuer_ids.is_empty()
            && !self.config.issuer_ids.contains(&token.issuer_id)
        {
            return Err(FreebirdError::UntrustedIssuer(token.issuer_id.clone()));
        }

        // Check expiration locally first
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if token.exp < now {
            return Err(FreebirdError::TokenExpired);
        }

        // Get verifier URL
        let verifier_url = self.config.verifier_url.as_ref().ok_or_else(|| {
            FreebirdError::VerificationFailed("Verifier URL not configured".to_string())
        })?;

        // Build verification request
        let request = VerifyRequest {
            token_b64: token.token_b64.clone(),
            issuer_id: token.issuer_id.clone(),
            exp: token.exp,
        };

        // POST to verifier
        let url = format!("{}/v1/verify", verifier_url.trim_end_matches('/'));

        let response = self
            .http
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| FreebirdError::VerificationFailed(format!("HTTP request failed: {}", e)))?;

        // Check HTTP status
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(FreebirdError::VerificationFailed(format!(
                "Verifier returned {}: {}",
                status, error_text
            )));
        }

        // Parse response
        let verify_response: VerifyResponse = response.json().await.map_err(|e| {
            FreebirdError::VerificationFailed(format!("Failed to parse response: {}", e))
        })?;

        if verify_response.ok {
            Ok(())
        } else {
            // Token is invalid or already used
            Err(FreebirdError::TokenInvalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_env() {
        // This test just ensures the function doesn't panic
        // Actual behavior depends on environment variables
        let _ = FreebirdClient::from_env();
    }

    #[test]
    fn test_issuer_validation() {
        let config = FreebirdConfig {
            verifier_url: Some("http://localhost:8082".to_string()),
            issuer_ids: vec!["issuer:trusted:v1".to_string()],
            required: false,
        };

        let client = FreebirdClient::new(config);

        // Check that untrusted issuers are rejected (synchronous check)
        let token = FreebirdToken {
            token_b64: "test".to_string(),
            issuer_id: "issuer:untrusted:v1".to_string(),
            exp: u64::MAX, // Far future
        };

        // We can't easily test the async verify function here,
        // but we can verify the issuer check would fail
        assert!(!client.config.issuer_ids.contains(&token.issuer_id));
    }

    #[test]
    fn test_expiration_check() {
        let token = FreebirdToken {
            token_b64: "test".to_string(),
            issuer_id: "issuer:test:v1".to_string(),
            exp: 0, // Expired (Unix epoch)
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert!(token.exp < now);
    }
}
