use mockall::predicate::*;

mod registry_client;
const DID_METHOD: &'static str = "knox";
use registry_client::GrpcClient;

pub struct RegistryResolver {
    client: Box<dyn registry_client::RegistryClient + Send + Sync>,
}

impl RegistryResolver {
    pub async fn new(url: String) -> Self {
        let client = GrpcClient::new(url).await;
        return Self {
            client: Box::new(client),
        };
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
        let document: pbjson_types::Struct = serde_json::from_value(document)?;
        self.client.create(did, Some(document)).await?;

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
    use super::*;
    use serde_json::json;
    use ssi::DIDResolver;

    use crate::{registry_client::registry::CreateResponse, RegistryResolver};

    macro_rules! tokio_await {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    // Test Case One - Succeeds
    // Test Case Two - Fails Due To Network Error
    // Test Case Three - Fails Due To Parsing Error
    #[test]
    fn test_create() -> Result<(), String> {
        let mut mock_client = registry_client::MockRegistryClient::default();

        let did = String::from("did:knox:123456");
        let doc = json!({
                "@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/ed25519-2020/v1"],
                "id":"z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh",
                "authentication":[
                    {"id":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh#z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh","type":"Ed25519VerificationKey2020","controller":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh","publicKeyMultibase":"z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh"
                }],
                "capabilityInvocation":[
                    {"id":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh#z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh","type":"Ed25519VerificationKey2020","controller":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh","publicKeyMultibase":"z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh"
                }],
                "capabilityDelegation":[
                    {"id":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh#z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh","type":"Ed25519VerificationKey2020","controller":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh","publicKeyMultibase":"z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh"
                }],
                "assertionMethod":[
                    {"id":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh#z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh","type":"Ed25519VerificationKey2020","controller":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh","publicKeyMultibase":"z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh"
                }]
            }
        );
        //Err(tonic::Status::invalid_argument("message"))
        //Ok(tonic::Response::new(CreateResponse {}))
        let document: pbjson_types::Struct = serde_json::from_value(doc.clone()).unwrap();
        mock_client
            .expect_create()
            .with(eq(did.clone()), eq(Some(document.clone())))
            .return_once(|_, _| (Ok(tonic::Response::new(CreateResponse {}))));

        let resolver = RegistryResolver {
            client: Box::new(mock_client),
        };

        let res = tokio_await!(resolver.create(did, doc));
        assert!(res.is_ok());
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
