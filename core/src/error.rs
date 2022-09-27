#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unknown Error: {0}")]
    Unknown(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    #[error("Unknown Error: {0}")]
    Unknown(String),

    #[error("Document not found")]
    DocumentNotFound,

    #[error("InvalidData")]
    InvalidData,

    #[error("Network Failure")]
    NetworkFailure,
}
