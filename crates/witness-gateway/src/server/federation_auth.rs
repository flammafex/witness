use dashmap::DashMap;

use crate::epoch::epoch_secs;

// ============================================================================
// Federation auth token store
// ============================================================================

const FEDERATION_TOKEN_LIFETIME_SECS: u64 = 90 * 24 * 60 * 60;

/// Entry for a federation auth token with expiry.
#[derive(Clone)]
struct TokenEntry {
    token: String,
    expires_at: u64,
}

/// In-memory store for federation auth tokens.
///
/// Supports per-partner token generation, automatic expiry of previous
/// tokens when rotated, and periodic cleanup.
#[derive(Clone)]
pub struct FederationAuthStore {
    current: DashMap<String, TokenEntry>,
    expired: DashMap<String, TokenEntry>,
}

impl FederationAuthStore {
    pub fn new() -> Self {
        Self {
            current: DashMap::new(),
            expired: DashMap::new(),
        }
    }

    /// Seed a current token from static configuration.
    pub fn seed_current(&self, partner_id: &str, token: String) {
        let entry = TokenEntry {
            token,
            expires_at: u64::MAX,
        };
        self.current.insert(partner_id.to_string(), entry);
    }

    /// Seed a previous (expired) token from static configuration.
    pub fn seed_expired(&self, partner_id: &str, token: String, expires_at: u64) {
        let entry = TokenEntry { token, expires_at };
        self.expired.insert(partner_id.to_string(), entry);
    }

    /// Generate a new auth token for a partner.
    ///
    /// If a current token exists, it is moved to the expired map with
    /// `expires_at = now` (immediately invalid).
    pub fn generate_auth_token(&self, partner_id: &str) -> String {
        let now = epoch_secs();
        let token = generate_random_token();

        if let Some((_, old)) = self.current.remove(partner_id) {
            self.expired.insert(
                partner_id.to_string(),
                TokenEntry {
                    token: old.token,
                    expires_at: now,
                },
            );
        }

        let entry = TokenEntry {
            token: token.clone(),
            expires_at: now.saturating_add(FEDERATION_TOKEN_LIFETIME_SECS),
        };
        self.current.insert(partner_id.to_string(), entry);
        token
    }

    /// Validate whether a token is current and not expired.
    pub fn validate_auth_token(&self, token: &str) -> bool {
        let now = epoch_secs();
        for entry in self.current.iter() {
            if witness_core::constant_time_eq(&entry.value().token, token)
                && entry.value().expires_at > now
            {
                return true;
            }
        }
        false
    }

    /// Check if any current tokens are configured.
    pub fn has_current_tokens(&self) -> bool {
        !self.current.is_empty()
    }

    /// Remove all expired entries (both current and expired maps).
    pub fn cleanup_expired(&self, now: u64) {
        let before_current = self.current.len();
        self.current.retain(|_, entry| entry.expires_at > now);
        let after_current = self.current.len();
        if before_current != after_current {
            tracing::info!(
                "Cleaned up {} expired current federation tokens",
                before_current - after_current
            );
        }

        let before_expired = self.expired.len();
        self.expired.retain(|_, entry| entry.expires_at > now);
        let after_expired = self.expired.len();
        if before_expired != after_expired {
            tracing::info!(
                "Cleaned up {} expired previous federation tokens",
                before_expired - after_expired
            );
        }
    }
}

impl Default for FederationAuthStore {
    fn default() -> Self {
        Self::new()
    }
}

fn generate_random_token() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const TOKEN_LEN: usize = 64;
    let mut rng = rand::thread_rng();
    (0..TOKEN_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn federation_old_token_invalidated_on_rotation() {
        let store = FederationAuthStore::new();
        let partner = "peer-network-1";

        let token_a = store.generate_auth_token(partner);
        assert!(
            store.validate_auth_token(&token_a),
            "initial token should be valid"
        );

        let token_b = store.generate_auth_token(partner);
        assert!(
            !store.validate_auth_token(&token_a),
            "old token should be invalidated after rotation"
        );
        assert!(
            store.validate_auth_token(&token_b),
            "new token should be valid"
        );
    }

    #[test]
    fn federation_expired_tokens_cleaned_up() {
        let store = FederationAuthStore::new();
        let partner = "peer-network-1";

        let token_a = store.generate_auth_token(partner);
        let _token_b = store.generate_auth_token(partner);

        assert!(
            store.expired.contains_key(partner),
            "old token should be in expired map"
        );

        store.cleanup_expired(epoch_secs());

        assert!(
            !store.expired.contains_key(partner),
            "expired token should be cleaned up"
        );
        assert!(
            store.current.contains_key(partner),
            "current token should remain after cleanup"
        );
        assert!(
            !store.validate_auth_token(&token_a),
            "cleaned-up old token should no longer validate"
        );
    }
}
