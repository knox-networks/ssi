#![allow(unused_variables)]
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use signature::keypair::SSIKeyMaterial;

// use registry_resolver::RegistryResolver;
use signature::keypair::Ed25519SSIKeyPair;
use signature::signer::DIDSigner;

#[derive(Clone, Debug, Copy)]
pub struct Identity<T> {
    resolver: T,
}

impl<T: crate::DIDResolver> Identity<T> {
    pub fn new(resolver: T) -> Identity<T> {
        Identity { resolver: resolver }
    }
    // here Ed25519DidSigner has to be replaced by SSIKeyPair
    pub async fn generate(
        self,
        key_pair: Ed25519SSIKeyPair,
    ) -> Result<DidDocument, crate::error::ResolverError> {
        let signer = signature::signer::Ed25519DidSigner::from(&key_pair);
        let signed_doc = self.create_did_document(&key_pair, signer);
        let signed_doc_json = serde_json::to_value(signed_doc.clone()).unwrap();
        let did = key_pair.get_master_public_key_encoded();
        let res = self.resolver.create(did, signed_doc_json).await?;
        Ok(signed_doc)
    }

    pub fn create_did_document(
        &self,
        key_pair: &signature::keypair::Ed25519SSIKeyPair,
        signer: signature::signer::Ed25519DidSigner,
    ) -> DidDocument {
        let did_doc = DidDocument {
            context: vec!["default".to_string()],
            id: "default".to_string(),
            authentication: vec![SSIKeyMaterial {
                master_public_key: key_pair.get_master_public_key_encoded(),
                id: key_pair.get_verification_method(
                    signature::suite::VerificationRelation::Authentication,
                ),
                proof_type: signer.get_proof_type(),
                controller: key_pair
                    .get_controller(signature::suite::VerificationRelation::Authentication),
                public_key_multibase: signature::suite::VerificationRelation::Authentication,
            }],
            capability_invocation: vec![SSIKeyMaterial {
                master_public_key: key_pair.get_master_public_key_encoded(),
                id: key_pair.get_verification_method(
                    signature::suite::VerificationRelation::CapabilityInvocation,
                ),
                proof_type: signer.get_proof_type(),
                controller: key_pair
                    .get_controller(signature::suite::VerificationRelation::CapabilityInvocation),
                public_key_multibase: signature::suite::VerificationRelation::CapabilityInvocation,
            }],
            capability_delegation: vec![SSIKeyMaterial {
                master_public_key: key_pair.get_master_public_key_encoded(),
                id: key_pair.get_verification_method(
                    signature::suite::VerificationRelation::CapabilityDelegation,
                ),
                proof_type: signer.get_proof_type(),
                controller: key_pair
                    .get_controller(signature::suite::VerificationRelation::CapabilityDelegation),
                public_key_multibase: signature::suite::VerificationRelation::CapabilityDelegation,
            }],
            assertion_method: vec![SSIKeyMaterial {
                master_public_key: key_pair.get_master_public_key_encoded(),
                id: key_pair.get_verification_method(
                    signature::suite::VerificationRelation::AssertionMethod,
                ),
                proof_type: signer.get_proof_type(),
                controller: key_pair
                    .get_controller(signature::suite::VerificationRelation::AssertionMethod),
                public_key_multibase: signature::suite::VerificationRelation::AssertionMethod,
            }],
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
    use crate::identity::Identity;
    use crate::MockDIDResolver;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[test]
    fn test_create_identity() -> Result<(), String> {
        let mut resolver = MockDIDResolver::default();
        let iu = Identity::new(resolver);
        let kp = signature::keypair::Ed25519SSIKeyPair::new();
        let identity = iu.generate(kp);
        Ok(())
    }
}
