use axum::{http::StatusCode, response::IntoResponse, Json};

use crate::freebird::FreebirdError;

pub enum AppError {
    InvalidHash,
    NotFound,
    NotBatched,
    InvalidSignature,
    InsufficientSignatures { got: usize, required: usize },
    InternalError,
    Unauthorized,
    RateLimited,
    DatabaseError(sqlx::Error),
    Other(anyhow::Error),
    FreebirdTokenRequired,
    FreebirdTokenInvalid,
    FreebirdVerificationFailed(String),
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::DatabaseError(e)
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Other(e)
    }
}

impl From<FreebirdError> for AppError {
    fn from(e: FreebirdError) -> Self {
        match e {
            FreebirdError::TokenInvalid => AppError::FreebirdTokenInvalid,
            FreebirdError::VerificationFailed(msg) => AppError::FreebirdVerificationFailed(msg),
            FreebirdError::HttpError(e) => {
                AppError::FreebirdVerificationFailed(format!("HTTP error: {}", e))
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            AppError::InvalidHash => (StatusCode::BAD_REQUEST, "Invalid hash format".to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Attestation not found".to_string()),
            AppError::NotBatched => (
                StatusCode::NOT_FOUND,
                "Attestation not yet batched".to_string(),
            ),
            AppError::InvalidSignature => {
                (StatusCode::BAD_REQUEST, "Invalid signature".to_string())
            }
            AppError::InsufficientSignatures { got, required } => {
                tracing::error!(
                    "Insufficient signatures: got {}, required {}",
                    got,
                    required
                );
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable".to_string(),
                )
            }
            AppError::InternalError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            ),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            AppError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many requests".to_string(),
            ),
            AppError::DatabaseError(e) => {
                tracing::error!("Database error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database error".to_string(),
                )
            }
            AppError::Other(e) => {
                tracing::error!("Error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            }
            AppError::FreebirdTokenRequired => (
                StatusCode::UNAUTHORIZED,
                "Freebird token required".to_string(),
            ),
            AppError::FreebirdTokenInvalid => (
                StatusCode::FORBIDDEN,
                "Freebird token invalid or already used".to_string(),
            ),
            AppError::FreebirdVerificationFailed(msg) => {
                tracing::error!("Freebird verification failed: {}", msg);
                (
                    StatusCode::BAD_GATEWAY,
                    "Freebird verification failed".to_string(),
                )
            }
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
