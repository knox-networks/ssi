use mockall::predicate::*;
use registry_client::RegistryClient;
use std::collections::HashMap;

mod registry_client;

const DID_METHOD: &'static str = "knox";

pub struct RegistryResolver {
    client: registry_client::GrpcClient,
}

impl RegistryResolver {
    pub async fn new(url: String) -> Self {
        let client = registry_client::GrpcClient::new(url).await;
        return Self { client };
    }

    const fn get_method_helper() -> &'static str {
        return DID_METHOD;
    }
}
#[async_trait::async_trait]
impl ssi::DIDResolver for RegistryResolver {
    fn get_method() -> &'static str {
        return Self::get_method_helper();
    }

    async fn create(
        self,
        did: String,
        document: serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let document: HashMap<String, pbjson_types::Value> =
            serde_json::from_value(document).unwrap();
        self.client
            .create(did, Some(document.into()))
            .await
            .unwrap();

        Ok(())
    }

    async fn read(self, did: String) -> serde_json::Value {
        let res = self.client.read(did).await.unwrap();
        let document =
            serde_json::to_value(res.into_inner().document.unwrap_or_default()).unwrap_or_default();

        return document;
    }
}

#[cfg(test)]
mod tests {
    use ssi::DIDResolver;

    use crate::RegistryResolver;

    #[test]
    fn test_create() -> Result<(), String> {
        assert!(false);
        Ok(())
    }

    #[test]
    fn test_read() -> Result<(), String> {
        assert!(false);
        Ok(())
    }

    #[test]
    fn test_get_method() -> Result<(), String> {
        assert_eq!(RegistryResolver::get_method(), "knox");
        Ok(())
    }

    #[test]
    fn test_create_verification_method() -> Result<(), String> {
        let did = String::from("12345");
        let key_id = String::from("123456");
        assert_eq!(
            RegistryResolver::create_verification_method(did, key_id),
            "did:knox:12345#123456"
        );
        Ok(())
    }
}
