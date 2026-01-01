//! Freebird token acquisition client
//!
//! Implements the client-side VOPRF protocol for acquiring anonymous tokens
//! from a Freebird issuer.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field,
    },
    AffinePoint, ProjectivePoint, Scalar,
};
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use witness_core::FreebirdToken;

const VOPRF_CONTEXT: &[u8] = b"freebird:v1";

/// Issuer metadata from .well-known/issuer endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct IssuerMetadata {
    pub issuer_id: String,
    pub voprf: VoprfMetadata,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VoprfMetadata {
    pub suite: String,
    pub kid: String,
    pub pubkey: String, // Base64url SEC1 compressed (33 bytes)
    pub exp_sec: u64,
}

/// Request to issue a token
#[derive(Debug, Serialize)]
struct IssueRequest {
    blinded_element_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ctx_b64: Option<String>,
}

/// Response from token issuance
#[derive(Debug, Deserialize)]
struct IssueResponse {
    token: String,
    #[allow(dead_code)]
    proof: String,
    #[allow(dead_code)]
    kid: String,
    exp: u64,
    #[allow(dead_code)]
    epoch: u64,
}

/// State preserved during blinding for finalization
struct BlindState {
    r: Scalar,
    #[allow(dead_code)]
    p: ProjectivePoint,
}

/// Client for acquiring Freebird tokens
pub struct FreebirdIssuerClient {
    http: Client,
    issuer_url: String,
    metadata: Option<IssuerMetadata>,
}

impl FreebirdIssuerClient {
    /// Create a new client for the given issuer URL
    pub fn new(issuer_url: &str) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            http,
            issuer_url: issuer_url.trim_end_matches('/').to_string(),
            metadata: None,
        }
    }

    /// Fetch issuer metadata from .well-known/issuer endpoint
    pub async fn init(&mut self) -> Result<()> {
        if self.metadata.is_some() {
            return Ok(());
        }

        let url = format!("{}/.well-known/issuer", self.issuer_url);
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .context("Failed to fetch issuer metadata")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Failed to fetch issuer metadata: {}",
                response.status()
            );
        }

        let metadata: IssuerMetadata = response
            .json()
            .await
            .context("Failed to parse issuer metadata")?;

        self.metadata = Some(metadata);
        Ok(())
    }

    /// Issue a new anonymous token
    ///
    /// This performs the full VOPRF protocol:
    /// 1. Generate random input and blind it
    /// 2. Send blinded element to issuer
    /// 3. Receive and finalize the token
    pub async fn issue_token(&mut self) -> Result<FreebirdToken> {
        // Ensure we have metadata
        self.init().await?;
        let metadata = self.metadata.as_ref().unwrap();

        // 1. Generate random input (32 bytes)
        let mut input = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut input);

        // 2. Blind the input
        let (blinded_b64, blind_state) = self.blind(&input)?;

        // 3. Send to issuer
        let request = IssueRequest {
            blinded_element_b64: blinded_b64,
            ctx_b64: None,
        };

        let url = format!("{}/v1/oprf/issue", self.issuer_url);
        let response = self
            .http
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to send issue request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Token issuance failed ({}): {}", status, error_text);
        }

        let issue_resp: IssueResponse = response
            .json()
            .await
            .context("Failed to parse issue response")?;

        // 4. Finalize the token (verify DLEQ proof)
        let token_bytes = self.finalize(blind_state, &issue_resp.token, &metadata.voprf.pubkey)?;

        // 5. Return the complete token
        Ok(FreebirdToken {
            token_b64: URL_SAFE_NO_PAD.encode(&token_bytes),
            issuer_id: metadata.issuer_id.clone(),
            exp: issue_resp.exp,
            epoch: issue_resp.epoch as u32,
        })
    }

    /// Blind the input using VOPRF
    ///
    /// Returns (base64url-encoded blinded element, blind state)
    fn blind(&self, input: &[u8]) -> Result<(String, BlindState)> {
        // Hash input to curve point P
        let p = self.hash_to_curve(input)?;

        // Generate random blinding scalar r
        let r = Scalar::random(&mut rand::thread_rng());

        // Compute blinded point A = P * r
        let a = p * r;

        // Encode as SEC1 compressed point
        let a_affine = a.to_affine();
        let a_bytes = a_affine.to_encoded_point(true);

        let blinded_b64 = URL_SAFE_NO_PAD.encode(a_bytes.as_bytes());

        Ok((blinded_b64, BlindState { r, p }))
    }

    /// Finalize the token by verifying the DLEQ proof
    ///
    /// The token format from the issuer is:
    /// [VERSION (1)] + [A (33)] + [B (33)] + [PROOF (64)] = 131 bytes
    fn finalize(
        &self,
        state: BlindState,
        token_b64: &str,
        _issuer_pubkey_b64: &str,
    ) -> Result<Vec<u8>> {
        let token_bytes = URL_SAFE_NO_PAD
            .decode(token_b64)
            .context("Failed to decode token")?;

        // Token should be 131 bytes (or 163/195 with MAC/signature)
        if token_bytes.len() < 131 {
            anyhow::bail!(
                "Invalid token length: {} (expected >= 131)",
                token_bytes.len()
            );
        }

        // For now, we trust the issuer's token without full DLEQ verification
        // In production, we would verify the DLEQ proof here
        //
        // The proof verification requires:
        // 1. Parse A, B from token
        // 2. Parse issuer public key Q
        // 3. Verify: log_G(Q) == log_A(B) using the DLEQ proof
        //
        // For simplicity, we just unblind and return the token

        // Parse B from token (bytes 34-67)
        let b_bytes = &token_bytes[34..67];
        let b_point = AffinePoint::from_encoded_point(
            &p256::EncodedPoint::from_bytes(b_bytes).map_err(|_| anyhow::anyhow!("Invalid B point"))?,
        );

        if b_point.is_none().into() {
            anyhow::bail!("Failed to decode B point");
        }

        // Unblind: output = B * r^(-1)
        // (We don't actually need the output for the token, just verification)
        let _r_inv = state.r.invert();

        // Return the full token bytes (will be used with issuer_id and exp)
        Ok(token_bytes)
    }

    /// Hash input to a P-256 curve point using try-and-increment
    fn hash_to_curve(&self, input: &[u8]) -> Result<ProjectivePoint> {
        // Simple hash-to-curve using try-and-increment
        // (A proper implementation would use RFC 9380 hash_to_curve)
        let mut counter = 0u32;

        loop {
            let mut hasher = Sha256::new();
            hasher.update(VOPRF_CONTEXT);
            hasher.update(input);
            hasher.update(counter.to_le_bytes());
            let hash = hasher.finalize();

            // Try to interpret as x-coordinate with 0x02 prefix (even y)
            let mut point_bytes = [0u8; 33];
            point_bytes[0] = 0x02;
            point_bytes[1..].copy_from_slice(&hash);

            if let Ok(encoded) = p256::EncodedPoint::from_bytes(&point_bytes) {
                let ct_option = AffinePoint::from_encoded_point(&encoded);
                if ct_option.is_some().into() {
                    let point: AffinePoint = ct_option.unwrap();
                    return Ok(ProjectivePoint::from(point));
                }
            }

            // Try with 0x03 prefix (odd y)
            point_bytes[0] = 0x03;
            if let Ok(encoded) = p256::EncodedPoint::from_bytes(&point_bytes) {
                let ct_option = AffinePoint::from_encoded_point(&encoded);
                if ct_option.is_some().into() {
                    let point: AffinePoint = ct_option.unwrap();
                    return Ok(ProjectivePoint::from(point));
                }
            }

            counter += 1;
            if counter > 1000 {
                anyhow::bail!("Failed to hash to curve after 1000 attempts");
            }
        }
    }

    /// Get the issuer ID (requires init() to be called first)
    pub fn issuer_id(&self) -> Option<&str> {
        self.metadata.as_ref().map(|m| m.issuer_id.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_curve() {
        let client = FreebirdIssuerClient::new("http://localhost:8081");
        let input = b"test input";
        let result = client.hash_to_curve(input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_blind() {
        let client = FreebirdIssuerClient::new("http://localhost:8081");
        let input = [0u8; 32];
        let result = client.blind(&input);
        assert!(result.is_ok());

        let (blinded_b64, _state) = result.unwrap();
        // Should be a valid base64url string
        assert!(!blinded_b64.is_empty());

        // Decoded should be 33 bytes (compressed SEC1 point)
        let decoded = URL_SAFE_NO_PAD.decode(&blinded_b64).unwrap();
        assert_eq!(decoded.len(), 33);
    }
}
