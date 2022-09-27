#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unknown Error: {0}")]
    Unknown(String),

    #[error("Message Verification Error: {0}")]
    Verify(String),
}
