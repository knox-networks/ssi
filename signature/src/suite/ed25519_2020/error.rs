#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Bip39 Error: {0}")]
    Bip39(String),

    #[error("Error converting hashed seed to byte array {0}")]
    SeedHashConversion(String),

    #[error("Error converting byte array to signer key: {0}")]
    SigningKeyConversion(String),
}
