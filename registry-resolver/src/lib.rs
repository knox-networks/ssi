use registry::registry_service_client::RegistryServiceClient;
use std::collections::HashMap;

#[path = "gen/registry_api.v1.rs"]
pub mod registry;

pub struct RegistryResolver {
    url: String,
}

impl RegistryResolver {
    pub async fn new(url: String) -> Self {
        return Self { url };
    }
}
#[async_trait::async_trait]
impl ssi::DIDResolver for RegistryResolver {
    async fn create(
        self: &RegistryResolver,
        did: String,
        document: serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = RegistryServiceClient::connect(self.url.clone())
            .await
            .unwrap();
        let doc: HashMap<String, pbjson_types::Value> = serde_json::from_value(doc).unwrap();
        client
            .create(registry::CreateRequest {
                did,
                document: Some(doc.into()),
            })
            .await
            .unwrap();
        Ok(())
    }

    async fn read(&self, did: String) -> serde_json::Value {
        let mut client = RegistryServiceClient::connect(self.url.clone())
            .await
            .unwrap();
        let res = client.read(registry::ReadRequest { did }).await.unwrap();
        let doc =
            serde_json::to_value(res.into_inner().document.unwrap_or_default()).unwrap_or_default();

        return doc;
    }
}
