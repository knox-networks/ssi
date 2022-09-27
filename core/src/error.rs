#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unknown Error: {0}")]
    Unknown(String),
}

#[derive(Debug, thiserror::Error)]
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
