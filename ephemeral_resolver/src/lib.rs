const DID_METHOD: &str = "ephemeral";

#[derive(Debug, Clone, Default)]
pub struct EphemeralResolver {
    registry:
        std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, serde_json::Value>>>,
}

impl EphemeralResolver {
    pub fn new() -> Self {
        Self {
            registry: std::sync::Arc::new(tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
        }
    }
}

#[async_trait::async_trait]
impl ssi_core::DIDResolver for EphemeralResolver {
    fn get_method(&self) -> &'static str {
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

    async fn resolve(
        &self,
        did: String,
    ) -> Result<ssi_core::ResolveResponse, ssi_core::error::ResolverError> {
        let document = self
            .registry
            .read()
            .await
            .get(&did)
            .ok_or_else(|| {
                ssi_core::error::ResolverError::DocumentNotFound(
                    "No document found with did".to_string(),
                )
            })?
            .clone();

        Ok(ssi_core::ResolveResponse {
            did_document: Some(document),
            did_document_metadata: None,
            did_resolution_metadata: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use ssi_core::DIDResolver;

    use crate::EphemeralResolver;

    fn create_did_doc(public_key: String) -> serde_json::Value {
        let did = create_did(public_key.clone());
        let sub_key = format!("{did}#{public_key}");
        serde_json::json!({
                "@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/ed25519-2020/v1"],
                "id":did,
                "authentication":[
                    {
                        "id":sub_key,
                        "type":"Ed25519VerificationKey2020",
                        "controller":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh",
                        "publicKeyMultibase":public_key
                }],
                "capabilityInvocation":[
                    {
                    "id":sub_key,
                    "type":"Ed25519VerificationKey2020",
                    "controller":did,
                    "publicKeyMultibase":public_key
                }],
                "capabilityDelegation":[
                    {
                    "id":sub_key,
                    "type":"Ed25519VerificationKey2020",
                    "controller":did,
                    "publicKeyMultibase":public_key
                }],
                "assertionMethod":[
                    {
                        "id":sub_key,
                        "type":"Ed25519VerificationKey2020",
                        "controller":did,
                        "publicKeyMultibase":public_key
                }]
            }
        )
    }

    fn get_public_key() -> String {
        String::from("z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh")
    }

    fn get_secondary_public_key() -> String {
        String::from("z6Mkj4iAWTZF4idaE1Xcv88X1cbBt8ty3xEvYEM6kziwnc5R")
    }

    fn create_did(public_key: String) -> String {
        format!("did:knox:{public_key}")
    }

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[test]
    fn test_read() {
        let public_key = get_public_key();
        let secondary_public_key = get_secondary_public_key();

        let did = create_did(public_key.clone());
        let secondary_did = create_did(secondary_public_key);

        let did_doc = create_did_doc(public_key);
        let secondary_did_doc = create_did_doc(secondary_did.clone());

        assert_ne!(did, secondary_did);
        assert_ne!(did_doc, secondary_did_doc);

        let resolver = EphemeralResolver::new();

        aw!(resolver.create(did.clone(), did_doc.clone())).unwrap();
        aw!(resolver.create(secondary_did.clone(), secondary_did_doc.clone())).unwrap();

        let retrieved_did_doc = aw!(resolver.resolve(did)).unwrap();
        assert_ne!(retrieved_did_doc.did_document.unwrap(), secondary_did_doc);

        let retrieved_did_doc = aw!(resolver.resolve(secondary_did)).unwrap();
        assert_ne!(retrieved_did_doc.did_document.unwrap(), did_doc);
    }

    #[test]
    fn test_create() {
        let public_key = get_public_key();
        let did = create_did(public_key.clone());
        let did_doc = create_did_doc(public_key);

        let resolver = EphemeralResolver::new();

        aw!(resolver.create(did.clone(), did_doc.clone())).unwrap();

        let retrieved_did_doc = aw!(resolver.resolve(did)).unwrap();

        assert_eq!(did_doc, retrieved_did_doc.did_document.unwrap());
    }
}
