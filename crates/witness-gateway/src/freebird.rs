use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use witness_core::{FreebirdConfig, FreebirdToken};

/// Errors that can occur during Freebird verification
#[derive(Debug, Error)]
pub enum FreebirdError {
    #[error("Freebird token invalid or already used")]
    TokenInvalid,

    #[error("Freebird verification failed: {0}")]
    VerificationFailed(String),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
}

/// Request body sent to Freebird verifier
#[derive(Debug, Serialize)]
struct VerifyRequest {
    token_b64: String,
}

/// Response from Freebird verifier
#[derive(Debug, Deserialize)]
struct VerifyResponse {
    ok: bool,
}

/// Client for verifying Freebird tokens
pub struct FreebirdClient {
    http: Client,
    config: FreebirdConfig,
}

impl FreebirdClient {
    /// Create a new Freebird client from configuration
    pub fn new(config: FreebirdConfig) -> Self {
        Self {
            http: crate::http_client::build_client(config.allow_insecure_local),
            config,
        }
    }

    /// Create a client from environment variables
    pub fn from_env() -> Option<Self> {
        // If no verifier URL is set, Freebird is disabled
        let verifier_url = Some(std::env::var("FREEBIRD_VERIFIER_URL").ok()?);

        let required = std::env::var("FREEBIRD_REQUIRED")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        let consume_tokens = std::env::var("FREEBIRD_CONSUME_TOKENS")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(true);

        let allow_insecure_local = std::env::var("FREEBIRD_ALLOW_INSECURE_LOCAL")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        let config = FreebirdConfig {
            verifier_url,
            required,
            consume_tokens,
            allow_insecure_local,
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
    /// Depending on the `consume_tokens` config:
    /// - If true (default): Uses /v1/verify which records the nullifier, preventing reuse.
    /// - If false: Uses /v1/check to validate without consumption.
    ///
    /// Returns Ok(()) if the token is valid.
    /// Returns Err if the token is invalid, expired, or verification failed.
    pub async fn verify(&self, token: &FreebirdToken) -> Result<(), FreebirdError> {
        // Get verifier URL
        let verifier_url = self.config.verifier_url.as_ref().ok_or_else(|| {
            FreebirdError::VerificationFailed("Verifier URL not configured".to_string())
        })?;

        // Build verification request
        let request = VerifyRequest {
            token_b64: token.token_b64.clone(),
        };

        // Choose endpoint based on consume_tokens config:
        // - /v1/verify: consumes token (records nullifier, prevents reuse)
        // - /v1/check: validates only (no consumption, token can be reused)
        let endpoint = if self.config.consume_tokens {
            "verify"
        } else {
            "check"
        };
        let url = format!("{}/v1/{}", verifier_url.trim_end_matches('/'), endpoint);

        if self.config.allow_insecure_local {
            crate::http_client::validate_local_dev_url(&url).map_err(|e| {
                FreebirdError::VerificationFailed(format!("Freebird verifier URL blocked: {}", e))
            })?;
        } else {
            crate::http_client::validate_outbound_url(&url).map_err(|e| {
                FreebirdError::VerificationFailed(format!("Freebird verifier URL blocked: {}", e))
            })?;
        }

        let response = self
            .http
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                FreebirdError::VerificationFailed(format!("HTTP request failed: {}", e))
            })?;

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
            // Token is invalid
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
    fn test_current_freebird_token_shape_parses() {
        let json = r#"{"token_b64":"current-freebird-token"}"#;
        let token: FreebirdToken = serde_json::from_str(json).unwrap();
        assert_eq!(token.token_b64, "current-freebird-token");
    }

    #[test]
    fn test_dev_local_http_validation_is_explicit() {
        assert!(
            crate::http_client::validate_local_dev_url("http://127.0.0.1:8082/v1/verify").is_ok()
        );
        assert!(
            crate::http_client::validate_local_dev_url("https://127.0.0.1:8082/v1/verify").is_err()
        );
        assert!(
            crate::http_client::validate_local_dev_url("http://192.168.1.5:8082/v1/verify")
                .is_err()
        );
    }
}
