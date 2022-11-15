const DID_METHOD: &str = "ephemeral";

#[derive(Debug, Clone)]
pub struct EphemeralResolver {}

#[async_trait::async_trait]
impl ssi_core::DIDResolver for EphemeralResolver {
    fn get_method() -> &'static str {
        DID_METHOD
    }

    async fn create(
        &self,
        _did: String,
        _document: serde_json::Value,
    ) -> Result<(), ssi_core::error::ResolverError> {
        unimplemented!()
    }

    async fn read(
        &self,
        _did: String,
    ) -> Result<serde_json::Value, ssi_core::error::ResolverError> {
        unimplemented!()
    }
}
