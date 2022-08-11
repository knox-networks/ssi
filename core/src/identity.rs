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

    pub async fn recover(
        self,
        did: String,
        key_pair: Ed25519SSIKeyPair,
    ) -> Result<serde_json::Value, crate::error::ResolverError> {
        let did = key_pair.get_master_public_key_encoded();
        let rsp = self.resolver.read(did).await?;
        Ok(rsp)
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
    use super::*;
    use crate::identity::Identity;
    use crate::MockDIDResolver;
    use serde_json::json;
    use sha2::digest::typenum::Len;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    fn get_json_restore_mock_ok() -> Result<serde_json::Value, crate::error::ResolverError> {
        Ok(get_json_input_mock())
    }

    fn get_json_input_mock() -> serde_json::Value {
        json!({
        "assertion_method":[
            {
                "controller":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                "id":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ#zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                "master_public_key":"zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                "proof_type":"Ed25519Signature2018",
                "public_key_multibase":"AssertionMethod"
            }],
            "authentication":[
                {
                    "controller":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "id":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ#zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "master_public_key":"zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "proof_type":"Ed25519Signature2018","public_key_multibase":"Authentication"
                }],
                "capability_delegation":[{
                    "controller":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "id":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ#zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "master_public_key":"zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "proof_type":"Ed25519Signature2018",
                    "public_key_multibase":"CapabilityDelegation"
                }],
                "capability_invocation":[{
                    "controller":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "id":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ#zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "master_public_key":"zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "proof_type":"Ed25519Signature2018",
                    "public_key_multibase":"CapabilityInvocation"
                }],
                "context":["default"],
                "id":"default"
            })
    }

    fn get_did() -> String {
        String::from("123456789")
    }

    #[rstest::rstest]
    #[case::restored_successfully(get_did(), get_json_restore_mock_ok(), true)]
    fn test_restore_identity(
        #[case] did: String,
        #[case] restore_response: Result<serde_json::Value, crate::error::ResolverError>,
        #[case] expect_ok: bool,
    ) -> Result<(), String> {
        let mut resolver_mock = MockDIDResolver::default();
        resolver_mock
            .expect_read()
            .return_once(|_| (restore_response));

        let iu = Identity::new(resolver_mock);
        let kp = signature::keypair::Ed25519SSIKeyPair::new();
        let gn = iu.recover(did, kp);
        let restored_identity = aw!(gn);

        match restored_identity {
            Ok(did_document) => {
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
        #[case] did_document_input_mock: serde_json::Value,
        #[case] expect_ok: bool,
    ) -> Result<(), String> {
        let mut resolver_mock = MockDIDResolver::default();

        resolver_mock
            .expect_create()
            .with(
                mockall::predicate::function(|did_doc: &String| -> bool {
                    did_doc.clone().len() > 0
                }),
                mockall::predicate::function(move |doc_input: &serde_json::Value| -> bool {
                    let did_doc_input: DidDocument =
                        serde_json::from_value(doc_input.clone()).unwrap();
                    let did_doc_mock: DidDocument =
                        serde_json::from_value(did_document_input_mock.clone()).unwrap();

                    if did_doc_input.id != did_doc_mock.id {
                        return false;
                    }
                    if did_doc_input.context != did_doc_mock.context {
                        return false;
                    }
                    if did_doc_input.assertion_method[0].public_key_multibase
                        != did_doc_mock.assertion_method[0].public_key_multibase
                    {
                        return false;
                    }
                    return true;
                }),
            )
            .return_once(|_, _| (mock_create_response.unwrap()));

        let iu = Identity::new(resolver_mock);
        let kp = signature::keypair::Ed25519SSIKeyPair::new();
        let gn = iu.generate(kp);
        let identity = aw!(gn);

        match identity {
            Ok(_) => {
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
