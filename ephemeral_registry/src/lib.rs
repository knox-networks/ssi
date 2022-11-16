const DID_METHOD: &str = "ephemeral";

#[derive(Debug, Clone)]
pub struct EphemeralResolver {
    registry:
        std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, serde_json::Value>>>,
}

#[async_trait::async_trait]
impl ssi_core::DIDResolver for EphemeralResolver {
    fn get_method() -> &'static str {
        DID_METHOD
    }

    async fn create(
        &self,
        did: String,
        document: serde_json::Value,
    ) -> Result<(), ssi_core::error::ResolverError> {
        self.registry.write().await.insert(did, document);
        Ok(())
    }

    async fn read(&self, did: String) -> Result<serde_json::Value, ssi_core::error::ResolverError> {
        let document = self
            .registry
            .read()
            .await
            .get(&did)
            .ok_or(ssi_core::error::ResolverError::DocumentNotFound(
                "No document found with did".to_string(),
            ))?
            .clone();

        Ok(document)
    }
}
