use serde::{Deserialize, Serialize};

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct KeyMaterial {
    pub id: String,
    #[serde(rename = "type")]
    pub proof_type: String,
    pub controller: String,
    pub public_key_multibase: String,
}

pub async fn generate<S: signature::suite::Signature>(
    resolver: impl super::DIDResolver,
    verifier: impl signature::verifier::DIDVerifier<S>,
) -> Result<DidDocument, crate::error::Error>
where
    S: signature::suite::Signature,
{
    let did_doc = create_did_document(verifier);
    let encoded_did_doc = serde_json::to_value(did_doc.clone()).unwrap();

    resolver
        .create(did_doc.id.clone(), encoded_did_doc)
        .await
        .unwrap();

    Ok(did_doc)
}

fn create_did_document<S>(verifier: impl signature::verifier::DIDVerifier<S>) -> DidDocument
where
    S: signature::suite::Signature,
{
    let did_doc = DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
        ],
        id: verifier
            .get_public_key_by_relation(signature::suite::VerificationRelation::Authentication),
        authentication: vec![KeyMaterial {
            id: verifier
                .get_verification_method(signature::suite::VerificationRelation::Authentication),
            proof_type: verifier.get_key_material_type(),
            controller: format!(
                "{}{}",
                verifier.get_did_method(),
                verifier.get_public_key_by_relation(
                    signature::suite::VerificationRelation::Authentication
                )
            ),
            public_key_multibase: verifier
                .get_public_key_by_relation(signature::suite::VerificationRelation::Authentication),
        }],
        capability_invocation: vec![KeyMaterial {
            id: verifier.get_verification_method(
                signature::suite::VerificationRelation::CapabilityInvocation,
            ),
            proof_type: verifier.get_key_material_type(),
            controller: format!(
                "{}{}",
                verifier.get_did_method(),
                verifier.get_public_key_by_relation(
                    signature::suite::VerificationRelation::CapabilityInvocation
                )
            ),
            public_key_multibase: verifier.get_public_key_by_relation(
                signature::suite::VerificationRelation::CapabilityInvocation,
            ),
        }],
        capability_delegation: vec![KeyMaterial {
            id: verifier.get_verification_method(
                signature::suite::VerificationRelation::CapabilityDelegation,
            ),
            proof_type: verifier.get_key_material_type(),
            controller: format!(
                "{}{}",
                verifier.get_did_method(),
                verifier.get_public_key_by_relation(
                    signature::suite::VerificationRelation::CapabilityDelegation
                )
            ),
            public_key_multibase: verifier.get_public_key_by_relation(
                signature::suite::VerificationRelation::CapabilityDelegation,
            ),
        }],
        assertion_method: vec![KeyMaterial {
            id: verifier
                .get_verification_method(signature::suite::VerificationRelation::AssertionMethod),
            proof_type: verifier.get_key_material_type(),
            controller: format!(
                "{}{}",
                verifier.get_did_method(),
                verifier.get_public_key_by_relation(
                    signature::suite::VerificationRelation::AssertionMethod
                )
            ),
            public_key_multibase: verifier.get_public_key_by_relation(
                signature::suite::VerificationRelation::AssertionMethod,
            ),
        }],
    };

    return did_doc;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DidDocument {
    context: Vec<String>,
    id: String,
    authentication: Vec<KeyMaterial>,
    capability_invocation: Vec<KeyMaterial>,
    capability_delegation: Vec<KeyMaterial>,
    assertion_method: Vec<KeyMaterial>,
}

#[cfg(test)]
mod tests {
    use super::*;
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
        #[case] _did_doc: String,
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

        let kp = signature::keypair::Ed25519SSIKeyPair::new();

        let gn = generate(
            resolver_mock,
            signature::verifier::ed25519_verifier_2020::Ed25519DidVerifier::from(&kp),
        );
        let identity = aw!(gn);

        assert_eq!(identity.is_err(), !expect_ok);
        Ok(())
    }
}
