//! Typed error model for the `witness-client` SDK.
//!
//! Every gateway failure mode a consumer must branch on is mapped to a typed
//! variant; consumers never string-match on error messages.

use witness_core::types::AttestationJobStatus;

/// Errors returned by the Witness client SDK.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A hash was not a valid 32-byte value.
    #[error("invalid hash: {0}")]
    InvalidHash(String),

    /// A transport-level failure (connect, TLS, timeout, etc.).
    #[error("transport error")]
    Transport(#[from] reqwest::Error),

    /// The gateway returned a non-2xx status that is not a 404 on a read
    /// endpoint.
    #[error("gateway returned {status}: {body}")]
    Http { status: u16, body: String },

    /// The gateway returned 404 on a read endpoint (e.g. unknown attestation).
    #[error("not found: {0}")]
    NotFound(String),

    /// An attestation job reached the terminal `failed` state.
    #[error("attestation job failed after {attempts} attempt(s): {last_error:?}")]
    JobFailed {
        hash: String,
        attempts: u32,
        last_error: Option<String>,
    },

    /// `wait_for_confirmation` exceeded its timeout before the job reached a
    /// terminal state.
    #[error("timed out waiting for confirmation of {hash} after {elapsed:?}")]
    ConfirmationTimeout {
        hash: String,
        elapsed: std::time::Duration,
        last_status: AttestationJobStatus,
    },

    /// The gateway returned a response that could not be decoded, or a
    /// protocol violation (e.g. `confirmed` without a `signed_attestation`).
    #[error("failed to decode gateway response")]
    Decode(#[from] serde_json::Error),

    /// A WebSocket-level failure.
    #[error("websocket error: {0}")]
    WebSocket(String),

    /// The WebSocket server requires authentication, or rejected the supplied
    /// authentication token.
    #[error("websocket authentication failed: {0}")]
    WebSocketAuth(String),

    /// The supplied gateway URL is malformed or uses an unsupported scheme.
    #[error("invalid gateway URL: {0}")]
    InvalidUrl(String),

    /// Local verification failed (wrapped from `witness_core`).
    #[error("verification failed")]
    Verification(#[from] witness_core::WitnessError),
}

/// Convenience alias for SDK results.
pub type Result<T> = std::result::Result<T, Error>;
