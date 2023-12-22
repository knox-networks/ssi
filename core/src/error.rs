#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unknown Error: {0}")]
    Unknown(String),

    #[error("Serde Error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Serde Valid Error: {0}")]
    SerdeValid(#[from] serde_valid::Error<serde_json::Error>),

    #[error("Signature Error: {0}")]
    Signature(#[from] signature::suite::error::Error),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolverError {
    #[error("Unknown Error: {0}")]
    Unknown(String),

    #[error("Document not found: {0}")]
    DocumentNotFound(String),

    #[error("InvalidData: {0}")]
    InvalidData(String),

    #[error("Network Failure: {0}")]
    NetworkFailure(String),
}
