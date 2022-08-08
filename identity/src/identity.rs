#![allow(unused_variables)]
#![allow(dead_code)]
use mockall::*;
use serde::{Deserialize, Serialize};
use signature::keypair::SSIKeyMaterial;

use registry_resolver::RegistryResolver;
use signature::signer::DIDSigner;
use signature::keypair::Ed25519SSIKeyPair;
use ssi::DIDResolver;


#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Identity {
    resolver: RegistryResolver,
}

impl Identity {
    pub fn new(resolver: RegistryResolver) -> Identity {
        Identity{
            resolver:resolver,
        }
    }
    // here Ed25519DidSigner has to be replaced by SSIKeyPair
    pub async fn generate(&mut self, key_pair: Ed25519SSIKeyPair) -> Result<DidDocument, ssi::error::ResolverError> {
        let signer = signature::signer::Ed25519DidSigner::from(&key_pair);
        let signed_doc = self.create_did_document(key_pair, signer);
        let signed_doc_json = serde_json::to_value(signed_doc).unwrap();
        let did = String::from("did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh");
        let res = self.resolver.create(did, signed_doc_json);
        res.await?;
        Ok(signed_doc)
    }

    pub fn create_did_document(self, key_pair: signature::keypair::Ed25519SSIKeyPair, signer: signature::signer::Ed25519DidSigner) -> DidDocument {
        let did_doc = DidDocument {
        context: vec!("default".to_string()),
        id: "default".to_string(),
        authentication: vec![
                SSIKeyMaterial{
                    master_public_key:key_pair.get_master_public_key_encoded(),
                    id: key_pair.get_verification_method(signature::suite::VerificationRelation::Authentication),
                    proof_type: signer.get_proof_type(),
                    controller: key_pair.get_controller(signature::suite::VerificationRelation::Authentication),
                    public_key_multibase: signature::suite::VerificationRelation::Authentication,
                },
            ],
        capability_invocation: vec![
                SSIKeyMaterial{
                    master_public_key:key_pair.get_master_public_key_encoded(),
                    id: key_pair.get_verification_method(signature::suite::VerificationRelation::CapabilityInvocation),
                    proof_type: signer.get_proof_type(),
                    controller: key_pair.get_controller(signature::suite::VerificationRelation::CapabilityInvocation),
                    public_key_multibase: signature::suite::VerificationRelation::CapabilityInvocation,
                },
            ],
        capability_delegation: vec![
            SSIKeyMaterial{
                    master_public_key:key_pair.get_master_public_key_encoded(),
                    id: key_pair.get_verification_method(signature::suite::VerificationRelation::CapabilityDelegation),
                    proof_type: signer.get_proof_type(),
                    controller: key_pair.get_controller(signature::suite::VerificationRelation::CapabilityDelegation),
                    public_key_multibase:  signature::suite::VerificationRelation::CapabilityDelegation,
                },
            ],
        assertion_method: vec![
            SSIKeyMaterial{
                master_public_key:key_pair.get_master_public_key_encoded(),
                id: key_pair.get_verification_method(signature::suite::VerificationRelation::AssertionMethod),
                proof_type: signer.get_proof_type(),
                controller: key_pair.get_controller(signature::suite::VerificationRelation::AssertionMethod),
                public_key_multibase: signature::suite::VerificationRelation::AssertionMethod,
            },]
        };
        
        return did_doc;
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DidDocument {
    context: Vec<String>,
    id: String,
    authentication: Vec<SSIKeyMaterial>,
    capability_invocation: Vec<SSIKeyMaterial>,
    capability_delegation: Vec<SSIKeyMaterial>,
    assertion_method: Vec<SSIKeyMaterial>,
}

#[cfg(test)]
mod tests {
    use registry_resolver::{
        registry_client::{MockRegistryClient},
        RegistryResolver,
    };

    impl IdentityUser {
        pub fn new() -> Self {
            Self {}
        }
    }

    impl DocumentBuilder for TestObj {}

    impl IdentityBuilder for IdentityUser {}

    #[test]
    fn test_create_identity() -> Result<(), String> {
        let mut mock_client = MockRegistryClient::default();
        if mock_create_response.is_some() {
            mock_client
                .expect_create()
                .with(
                    mockall::predicate::eq(did.clone()),
                    mockall::predicate::eq(Some(create_did_struct(doc.clone()))),
                )
                .return_once(|_, _| (mock_create_response.unwrap()));
        }

        let resolver = RegistryResolver {
            client: Box::new(mock_client),
        };
        let iu = IdentityUser::new(resolver);
        let builder = iu.new_identity_builder(registry::RegistryResolver);

        let identity = builder.create_identity();
        Ok(())
    }
}
