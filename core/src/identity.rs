use serde::{Deserialize, Serialize};

pub async fn recover<S>(
    resolver: impl crate::DIDResolver,
    verifier: impl signature::suite::DIDVerifier<S>,
) -> Result<serde_json::Value, crate::error::ResolverError>
where
    S: signature::suite::Signature,
{
    let rsp = resolver.resolve(verifier.get_did()).await?;
    Ok(rsp.did_document)
}

pub async fn create_identity<S>(
    verifier: impl signature::suite::DIDVerifier<S>,
) -> Result<DidDocument, crate::error::Error>
where
    S: signature::suite::Signature,
{
    let did_doc = create_did_document(verifier);

    Ok(did_doc)
}

pub async fn register_identity(
    resolver: &impl super::DIDResolver,
    did_doc: DidDocument,
) -> Result<DidDocument, crate::error::Error> {
    let encoded_did_doc = serde_json::to_value(did_doc.clone())?;
    resolver
        .create(did_doc.id.clone(), encoded_did_doc)
        .await
        .map_err(|e| crate::error::Error::Unknown(e.to_string()))?;

    Ok(did_doc)
}

fn create_did_document<S>(verifier: impl signature::suite::DIDVerifier<S>) -> DidDocument
where
    S: signature::suite::Signature,
{
    DidDocument {
        id: verifier.get_did(),
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
        ],
        authentication: vec![KeyMaterial {
            id: verifier
                .get_verification_method(signature::suite::VerificationRelation::Authentication),
            proof_type: verifier.get_key_material_type(),
            controller: verifier.get_did(),
            public_key_multibase: verifier.get_encoded_public_key_by_relation(
                signature::suite::VerificationRelation::Authentication,
            ),
        }],
        capability_invocation: vec![KeyMaterial {
            id: verifier.get_verification_method(
                signature::suite::VerificationRelation::CapabilityInvocation,
            ),
            proof_type: verifier.get_key_material_type(),
            controller: verifier.get_did(),
            public_key_multibase: verifier.get_encoded_public_key_by_relation(
                signature::suite::VerificationRelation::CapabilityInvocation,
            ),
        }],
        capability_delegation: vec![KeyMaterial {
            id: verifier.get_verification_method(
                signature::suite::VerificationRelation::CapabilityDelegation,
            ),
            proof_type: verifier.get_key_material_type(),
            controller: verifier.get_did(),
            public_key_multibase: verifier.get_encoded_public_key_by_relation(
                signature::suite::VerificationRelation::CapabilityDelegation,
            ),
        }],
        assertion_method: vec![KeyMaterial {
            id: verifier
                .get_verification_method(signature::suite::VerificationRelation::AssertionMethod),
            proof_type: verifier.get_key_material_type(),
            controller: verifier.get_did(),
            public_key_multibase: verifier.get_encoded_public_key_by_relation(
                signature::suite::VerificationRelation::AssertionMethod,
            ),
        }],
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct KeyMaterial {
    pub id: String,
    #[serde(rename = "type")]
    pub proof_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    #[serde(rename = "id")]
    pub id: String,
    pub authentication: Vec<KeyMaterial>,
    #[serde(rename = "capabilityInvocation")]
    pub capability_invocation: Vec<KeyMaterial>,
    #[serde(rename = "capabilityDelegation")]
    pub capability_delegation: Vec<KeyMaterial>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<KeyMaterial>,
}

impl DidDocument {
    pub fn to_json(&self) -> Result<String, crate::error::Error> {
        Ok(serde_json::to_string(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockDIDResolver, ResolveResponse};
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    const TEST_DID_METHOD: &str = "knox";

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    fn get_restore_response() -> Result<ResolveResponse, crate::error::ResolverError> {
        Ok(ResolveResponse {
            did_document: get_json_input_mock(),
            did_document_metadata: crate::DidDocumentMetadata {
                created: chrono::DateTime::parse_from_rfc3339("2021-04-28T20:00:00.000Z")
                    .unwrap()
                    .into(),
                updated: chrono::DateTime::parse_from_rfc3339("2021-04-28T20:00:00.000Z")
                    .unwrap()
                    .into(),
            },
            did_resolution_metadata: crate::ResolutionMetadata {
                content_type: None,
                duration: None,
                did_url: None,
                error: None,
            },
        })
    }

    fn get_json_input_mock() -> serde_json::Value {
        json!({
        "assertion_method":[
            {
                "controller":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                "id":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ#zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                "master_public_key":"zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                "type":"Ed25519Signature2020",
                "public_key_multibase":"AssertionMethod"
            }],
            "authentication":[
                {
                    "controller":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "id":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ#zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "master_public_key":"zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "type":"Ed25519Signature2020","public_key_multibase":"Authentication"
                }],
                "capability_delegation":[{
                    "controller":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "id":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ#zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "master_public_key":"zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "type":"Ed25519Signature2020",
                    "public_key_multibase":"CapabilityDelegation"
                }],
                "capability_invocation":[{
                    "controller":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "id":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ#zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "master_public_key":"zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ",
                    "type":"Ed25519Signature2020",
                    "public_key_multibase":"CapabilityInvocation"
                }],
                "@context":["https://www.w3.org/ns/did/v1"],
                "id":"did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ"
            })
    }

    fn get_did() -> String {
        String::from("123456789")
    }

    #[rstest::rstest]
    #[case::creates_successfully()]
    fn test_create_did_doc() -> Result<(), String> {
        let test_mnemonic =
            "park remain person kitchen mule spell knee armed position rail grid ankle";
        let mne = signature::suite::ed25519_2020::Mnemonic {
            language: signature::suite::ed25519_2020::MnemonicLanguage::English,
            phrase: test_mnemonic.to_string(),
        };
        let kp = signature::suite::ed25519_2020::Ed25519KeyPair::new(
            TEST_DID_METHOD.to_string(),
            Some(mne),
        )
        .unwrap();
        let verifier = signature::suite::ed25519_2020::Ed25519DidVerifier::from(kp);
        let did_doc = create_did_document(verifier);
        let vc = serde_json::to_value(did_doc).unwrap();

        let expect = json!({
        "id":"did:knox:z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1",
        "@context":["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
        "assertionMethod":[{
            "controller":"did:knox:z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1",
            "id":"did:knox:z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1#z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1",
            "publicKeyMultibase":"z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1",
            "type":"Ed25519VerificationKey2020"
            }],
            "authentication":[{
                "controller":"did:knox:z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1",
                "id":"did:knox:z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1#z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1",
                "publicKeyMultibase":"z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1",
                "type":"Ed25519VerificationKey2020"
            }],
            "capabilityDelegation":[{
                "controller":"did:knox:z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1",
                "id":"did:knox:z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1#z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1",
                "publicKeyMultibase":"z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1",
                "type":"Ed25519VerificationKey2020"
            }],
            "capabilityInvocation":[{
                "controller":"did:knox:z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1",
                "id":"did:knox:z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1#z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1",
                "publicKeyMultibase":"z6MkmgYPyjwqrMyHYBFfEcetAAoW7A9njsC4ToZ1WnjAgRL1",
                "type":"Ed25519VerificationKey2020"
            }]
            });

        assert_json_eq!(vc.to_string(), expect.to_string());
        Ok(())
    }

    #[rstest::rstest]
    #[case::restored_successfully(get_did(), get_restore_response(), true)]
    fn test_restore_identity(
        #[case] _did: String,
        #[case] restore_response: Result<ResolveResponse, crate::error::ResolverError>,
        #[case] expect_ok: bool,
    ) -> Result<(), String> {
        let mut resolver_mock = MockDIDResolver::default();
        resolver_mock
            .expect_resolve()
            .with(mockall::predicate::function(|did_doc: &String| -> bool {
                !did_doc.clone().is_empty()
            }))
            .return_once(|_| (restore_response));

        let kp =
            signature::suite::ed25519_2020::Ed25519KeyPair::new(TEST_DID_METHOD.to_string(), None)
                .unwrap();
        let verifier = signature::suite::ed25519_2020::Ed25519DidVerifier::from(kp);
        let gn = recover(resolver_mock, verifier);
        let restored_identity = aw!(gn);

        match restored_identity {
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

    #[test]
    fn test_create_identity() {
        let kp =
            signature::suite::ed25519_2020::Ed25519KeyPair::new(TEST_DID_METHOD.to_string(), None)
                .unwrap();
        let verifier = signature::suite::ed25519_2020::Ed25519DidVerifier::from(kp);

        let _did_doc = aw!(create_identity(verifier)).unwrap();
    }

    #[rstest::rstest]
    #[case::successful(
        Ok(()),
        true
    )]
    #[case::create_failure(
        Err(crate::error::ResolverError::Unknown("mock error".to_string())),
        false
    )]
    fn test_register_identity(
        #[case] mock_create_response: Result<(), crate::error::ResolverError>,
        #[case] expect_ok: bool,
    ) {
        let mut resolver_mock = MockDIDResolver::default();
        let kp =
            signature::suite::ed25519_2020::Ed25519KeyPair::new(TEST_DID_METHOD.to_string(), None)
                .unwrap();
        let verifier = signature::suite::ed25519_2020::Ed25519DidVerifier::from(kp);

        resolver_mock
            .expect_create()
            .with(
                mockall::predicate::eq(signature::suite::DIDVerifier::get_did(&verifier)),
                mockall::predicate::always(),
            )
            .return_once(|_, _| mock_create_response);

        let did_doc = aw!(create_identity(verifier)).unwrap();

        let res = aw!(register_identity(&resolver_mock, did_doc));

        assert_eq!(res.is_ok(), expect_ok);
    }
}
