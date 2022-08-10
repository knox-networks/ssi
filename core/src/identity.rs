use serde::{Deserialize, Serialize};
use signature::keypair::SSIKeyMaterial;

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
    pub async fn generate(
        self,
        key_pair: Ed25519SSIKeyPair,
    ) -> Result<DidDocument, crate::error::ResolverError> {
        let signer = signature::signer::Ed25519DidSigner::from(&key_pair);
        let signed_doc = self.create_did_document(&key_pair, signer);
        let signed_doc_json = serde_json::to_value(signed_doc.clone()).unwrap();
        let did = key_pair.get_master_public_key_encoded();

        match self.resolver.create(did, signed_doc_json).await {
            Ok(()) => {
                return Ok(signed_doc);
            }
            Err(_) => Err(crate::error::ResolverError::new(
                "Failed to create DID document",
                crate::error::ErrorKind::InvalidData,
            )),
        }
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
    use serde_json::json;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    fn get_json_input_mock() -> serde_json::Value {
        json!({
            "context": ["default"],
            "id": "default",
            "authentication": [
                {
                    "master_public_key": "did:example:123#key-1",
                    "id": "did:example:123#key-1",
                    "proof_type": "Ed25519Signature2018",
                    "controller": "did:example:123",
                    "public_key_multibase": "Ed25519VerificationKey2018"
                }
            ],
            "capability_invocation": [
                {
                    "master_public_key": "did:example:123#key-1",
                    "id": "did:example:123#key-1",
                    "proof_type": "Ed25519Signature2018",
                    "controller": "did:example:123",
                    "public_key_multibase": "Ed25519VerificationKey2018"
                }
            ],
            "capability_delegation": [
                {
                    "master_public_key": "did:example:123#key-1",
                    "id": "did:example:123#key-1",
                    "proof_type": "Ed25519Signature2018",
                    "controller": "did:example:123",
                    "public_key_multibase": "Ed25519VerificationKey2018"
                }
            ],
            "assertion_method": [
                {
                    "master_public_key": "did:example:123#key-1",
                    "id": "did:example:123#key-1",
                    "proof_type": "Ed25519Signature2018",
                    "controller": "did:example:123",
                    "public_key_multibase": "Ed25519VerificationKey2018"
                }
            ]
        })
    }

    fn get_did() -> String {
        String::from("jjjj")
    }

    #[rstest::rstest]
    #[case::created_successfully(
        Some(Ok(())),
        get_did(),
        get_json_input_mock(),
        true
    )]
    #[case::created_error(
        Some(Err(crate::error::ResolverError{
            message: "testErr".to_string(), 
            kind: crate::error::ErrorKind::NetworkFailure})),
        get_did(),
        get_json_input_mock(),
        false
    )]
    fn test_create_identity(
        #[case] mock_create_response: Option<Result<(), crate::error::ResolverError>>,
        #[case] did_doc: String,
        #[case] serde_json_value: serde_json::Value,
        #[case] expect_ok: bool,
    ) -> Result<(), String> {
        let mut resolver_mock = MockDIDResolver::default();

        resolver_mock
            .expect_create()
            // .with(
            //     mockall::predicate::eq(did_doc),
            //     mockall::predicate::eq(serde_json_value),
            // )
            .return_once(|_, _| (mock_create_response.unwrap()));

        let iu = Identity::new(resolver_mock);
        let kp = signature::keypair::Ed25519SSIKeyPair::new();
        let gn = iu.generate(kp);
        let identity = aw!(gn);

        match identity {
            Ok(DidDocument) => {
                if expect_ok {
                    Ok(())
                } else {
                    Err("Expected error".to_string())
                }
            }
            Err(_) => {
                if expect_ok {
                    Err("Expected success".to_string())
                } else {
                    Ok(())
                }
            }
        }
    }
}
