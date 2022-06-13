/// Placeholder
pub trait DidResolver {
    /// Placeholder
    fn read(&self, did: &str) -> serde_json::Value;
    /// Placeholder
    fn create(&self, did: &str, doc: serde_json::Value) -> String;
}

/// Placeholder
pub fn create_credential(
    _cred_type: &str,
    _cred_subject: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    unimplemented!();
}

/// Placeholder
pub fn create_presentation(
    _creds: Vec<serde_json::Value>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    unimplemented!();
}

// Placeholder
pub fn create_identity(
    _mnemonic: &str,
    _password: Option<String>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    unimplemented!();
}

/// Placeholder
pub fn create_data_integrity_proof(
    _doc: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    unimplemented!();
}

///Placeholders
pub fn verify_data_integrity_proof(
    _doc: serde_json::Value,
    _resolver: &impl DidResolver,
) -> Result<bool, Box<dyn std::error::Error>> {
    unimplemented!();
}

///Placeholder
pub fn verify_presentation(
    _doc: serde_json::Value,
    _resolver: &impl DidResolver,
) -> Result<bool, Box<dyn std::error::Error>> {
    unimplemented!();
}
