use serde::{Deserialize, Serialize};
use signature::keypair::SSIKeyMaterial;

#[derive(Clone, Debug, Copy)]
pub struct Identity<D> {
    resolver: D,
}

pub trait Signature: signature::suite::Signature{}

pub trait IdentitySigner <S, P, K>: signature::signer::DIDSigner<S> + signature::keypair::KeyPair<P, K> 
where S: Signature,
      P: signature::keypair::PrivateKey,
      K: signature::keypair::PublicKey
{
    fn get_controller(&self, relation: signature::suite::VerificationRelation) -> String;
    fn get_master_public_key_encoded(&self) -> String;
}

impl <D>Identity <D> 
where 
D: super::DIDResolver {
    pub fn new(resolver: D) -> Identity<D> {
        Identity { resolver: resolver }
    }
    pub async fn generate<S, P, K>(
        self,
        identity_signer: Box<dyn IdentitySigner<S, P, K>>, 
    ) -> Result<DidDocument, crate::error::ResolverError> 
    where 
    S: Signature,
    P: signature::keypair::PrivateKey,
    K: signature::keypair::PublicKey {
        let signed_doc = self.create_did_document(&identity_signer);
        let signed_doc_json = serde_json::to_value(signed_doc.clone()).unwrap();
        let did = identity_signer.get_master_public_key_encoded();
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

    pub fn create_did_document <S, P, K>(
        &self,
        signer: &Box<dyn IdentitySigner<S, P, K>>,
    ) -> DidDocument
    where 
    P: signature::keypair::PrivateKey,
    K: signature::keypair::PublicKey,
    S: Signature {
        let did_doc = DidDocument {
            context: vec!["default".to_string()],
            id: "default".to_string(),
            authentication: vec![SSIKeyMaterial {
                master_public_key: signer.get_master_public_key_encoded(),
                id: signer.get_verification_method(
                    signature::suite::VerificationRelation::Authentication,
                ),
                proof_type: signer.get_proof_type(),
                controller: signer
                    .get_controller(signature::suite::VerificationRelation::Authentication),
                public_key_multibase: signature::suite::VerificationRelation::Authentication,
            }],
            capability_invocation: vec![SSIKeyMaterial {
                master_public_key: signer.get_master_public_key_encoded(),
                id: signer.get_verification_method(
                    signature::suite::VerificationRelation::CapabilityInvocation,
                ),
                proof_type: signer.get_proof_type(),
                controller: signer
                    .get_controller(signature::suite::VerificationRelation::CapabilityInvocation),
                public_key_multibase: signature::suite::VerificationRelation::CapabilityInvocation,
            }],
            capability_delegation: vec![SSIKeyMaterial {
                master_public_key: signer.get_master_public_key_encoded(),
                id: signer.get_verification_method(
                    signature::suite::VerificationRelation::CapabilityDelegation,
                ),
                proof_type: signer.get_proof_type(),
                controller: signer
                    .get_controller(signature::suite::VerificationRelation::CapabilityDelegation),
                public_key_multibase: signature::suite::VerificationRelation::CapabilityDelegation,
            }],
            assertion_method: vec![SSIKeyMaterial {
                master_public_key: signer.get_master_public_key_encoded(),
                id: signer.get_verification_method(
                    signature::suite::VerificationRelation::AssertionMethod,
                ),
                proof_type: signer.get_proof_type(),
                controller: signer
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

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
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

                    return did_doc_input.id == did_doc_mock.id
                        && did_doc_input.context == did_doc_mock.context
                        && did_doc_input.assertion_method[0].public_key_multibase
                            == did_doc_mock.assertion_method[0].public_key_multibase;
                }),
            )
            .return_once(|_, _| (mock_create_response.unwrap()));

        let iu = Identity::new(resolver_mock);
        let kp = signature::keypair::Ed25519SSIKeyPair::new();
        let gn = iu.generate(kp);
        let identity = aw!(gn);

        assert_eq!(identity.is_err(), !expect_ok);
        Ok(())
    }
}
