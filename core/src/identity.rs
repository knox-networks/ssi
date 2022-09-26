use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Copy)]
pub struct Identity<T> {
    resolver: T,
}

impl<T: crate::DIDResolver> Identity<T> {
    pub fn new(resolver: T) -> Identity<T> {
        Identity { resolver: resolver }
    }
    pub async fn recover<S>(
        self,
        verifier: impl signature::verifier::DIDVerifier<S>,
    ) -> Result<serde_json::Value, crate::error::ResolverError> where S: signature::suite::Signature {
        let rsp = self.resolver.read(verifier.get_did()).await?;
        Ok(rsp)
    }
}

pub async fn generate<S>(
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
        .map_err(|_e| crate::error::Error::Unknown)?;

    Ok(did_doc)
}

fn create_did_document<S>(verifier: impl signature::verifier::DIDVerifier<S>) -> DidDocument where S: signature::suite::Signature{
        let did_doc = DidDocument {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            ],
            id: verifier.get_did(),
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


#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct KeyMaterial {
    pub id: String,
    #[serde(rename = "type")]
    pub proof_type: String,
    pub controller: String,
    pub public_key_multibase: String,
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
    use crate::identity::Identity;
    use crate::MockDIDResolver;
    use serde_json::json;

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
            .with(
                mockall::predicate::function(|did_doc: &String| -> bool {
                    did_doc.clone().len() > 0
                }),
            )
            .return_once(|_| (restore_response));

        let iu = Identity::new(resolver_mock);
        let kp = signature::keypair::Ed25519SSIKeyPair::new();
        let verifier = signature::verifier::ed25519_verifier_2020::Ed25519DidVerifier::from(&kp);
        let gn = iu.recover(verifier);
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

    #[rstest::rstest]
    #[case::created_successfully(
        Ok(()),
        get_did(),
        get_json_input_mock(),
        true
    )]
    #[case::created_error(
        Err(crate::error::ResolverError{
            message: "testErr".to_string(), 
            kind: crate::error::ErrorKind::NetworkFailure}),
        get_did(),
        get_json_input_mock(),
        false
    )]

    fn test_create_identity(
        #[case] mock_create_response: Result<(), crate::error::ResolverError>,
        #[case] did_doc: String,
        #[case] did_document_input_mock: serde_json::Value,
        #[case] expect_ok: bool,
    ) -> Result<(), String> {
        let mut resolver_mock = MockDIDResolver::default();
        let kp = signature::keypair::Ed25519SSIKeyPair::new();
        let verifier = signature::verifier::ed25519_verifier_2020::Ed25519DidVerifier::from(&kp);
        resolver_mock
            .expect_create()
            .with(
                mockall::predicate::eq(signature::verifier::DIDVerifier::get_did(&verifier)),
                mockall::predicate::always(),
            )
            .return_once(|_, _| (mock_create_response));

        let res = aw!(generate(resolver_mock, verifier));

        assert_eq!(res.is_err(), !expect_ok);
        Ok(())
    }
}
