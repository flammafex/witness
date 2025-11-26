use thiserror::Error;

#[derive(Error, Debug)]
pub enum WitnessError {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Insufficient signatures: got {got}, required {required}")]
    InsufficientSignatures { got: usize, required: usize },

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid hash format: {0}")]
    InvalidHash(String),

    #[error("Witness not found: {0}")]
    WitnessNotFound(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Timestamp too old or in future")]
    InvalidTimestamp,

    #[error("Duplicate attestation")]
    DuplicateAttestation,
}

pub type Result<T> = std::result::Result<T, WitnessError>;
