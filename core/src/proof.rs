use sophia::c14n::hash::HashFunction;

mod normalization;

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
pub struct DataIntegrityProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
pub struct RsaSignature2018 {
    #[serde(rename = "type")]
    pub proof_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    pub jws: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum CredentialProof {
    Single(ProofType),
    Set(Vec<ProofType>),
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum ProofType {
    Ed25519Signature2020(DataIntegrityProof),
    RsaSignature2018(RsaSignature2018),
}

impl std::fmt::Display for DataIntegrityProof {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{{\"type\": \"{}\", \"created\": \"{:?}\", \"verificationMethod\": \"{}\", \"proofPurpose\": \"{}\", \"proofValue\": \"{}\"}}",
            self.proof_type, self.created, self.verification_method, self.proof_purpose, self.proof_value
        )
    }
}

// Use it as an example
/// Given a JSON-LD document, create a data integrity proof for the document.
/// Currently, only `Ed25519Signature2020` data integrity proofs in the JSON-LD format can be created.
/// We should move to the new spec approach as `Ed25519Signature2020` is considered legacy
/// Follows algorithm described in https://www.w3.org/TR/vc-data-integrity/#add-proof
pub fn create_data_integrity_proof<S: signature::suite::Signature>(
    signer: &impl signature::suite::DIDSigner<S>,
    unsecured_doc: serde_json::Value,
    relation: signature::suite::VerificationRelation,
) -> Result<CredentialProof, super::error::Error> {
    let transformed_data = normalization::create_hashed_normalized_doc(unsecured_doc)?;
    let mut hasher = sophia::c14n::hash::Sha256::initialize();
    hasher.update(&transformed_data);
    let hash_data = hasher.finalize();
    let proof = signer.encoded_relational_sign(&hash_data, relation)?;

    Ok(CredentialProof::Single(ProofType::Ed25519Signature2020(
        DataIntegrityProof {
            proof_type: signer.get_proof_type(),
            created: Some(chrono::Utc::now().to_rfc3339()),
            verification_method: signer.get_verification_method(relation),
            proof_purpose: relation.to_string(),
            proof_value: proof,
        },
    )))
}

#[cfg(test)]
mod tests {

    use super::create_data_integrity_proof;
    use signature::suite::DIDSigner;
    use signature::suite::DIDVerifier;
    use sophia::c14n::hash::HashFunction;

    const TEST_DID_METHOD: &str = "knox";

    #[rstest::rstest]
    #[case::success(
        create_unverified_credential_doc(),
        signature::suite::VerificationRelation::AssertionMethod
    )]
    fn test_create_data_integrity_proof(
        #[case] doc: serde_json::Value,
        #[case] relation: signature::suite::VerificationRelation,
    ) {
        let phrase = "vague sell team fee cluster poet slush topic beef dish wise enter meat brave question before exhibit purity drill reward awkward plug ice dilemma";
        let mnemonic = signature::suite::ed25519_2020::Mnemonic {
            phrase: phrase.to_string(),
            language: signature::suite::ed25519_2020::MnemonicLanguage::English,
        };
        let kp = signature::suite::ed25519_2020::Ed25519KeyPair::new(
            TEST_DID_METHOD.to_string(),
            Some(mnemonic),
        )
        .unwrap();
        let signer: signature::suite::ed25519_2020::Ed25519DidSigner = kp.clone().into();
        let verifier: signature::suite::ed25519_2020::Ed25519DidVerifier = kp.into();
        let res = create_data_integrity_proof(&signer, doc.clone(), relation);

        assert!(res.is_ok());
        match res {
            Ok(proof) => {
                if let super::CredentialProof::Single(super::ProofType::Ed25519Signature2020(
                    proof,
                )) = proof
                {
                    assert_eq!(proof.proof_type, signer.get_proof_type());
                    assert_eq!(
                        proof.verification_method,
                        signer.get_verification_method(relation)
                    );
                    assert_eq!(proof.proof_purpose, relation.to_string());
                    let transformed_data =
                        crate::proof::normalization::create_hashed_normalized_doc(doc).unwrap();
                    let mut hasher = sophia::c14n::hash::Sha256::initialize();
                    hasher.update(&transformed_data);
                    let hash_data = hasher.finalize();

                    assert!(verifier
                        .decoded_relational_verify(&hash_data, proof.proof_value, relation)
                        .is_ok());
                } else {
                    panic!("Expected single proof but got set of proofs: {:?}", proof);
                }
            }
            Err(e) => panic!("{e:?}"),
        }
    }
    fn create_unverified_credential_doc() -> serde_json::Value {
        let expect = serde_json::json!({
                "@context": [
                  "https://www.w3.org/ns/credentials/v2",
                  "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "credentialSubject": {
                  "birthCountry": "Bahamas",
                  "birthDate": "1981-04-01",
                  "commuterClassification": "C1",
                  "familyName": "Kim",
                  "gender": "Male",
                  "givenName": "Francis",
                  "id": "did:knox:z6MkoBjc4GfEWrdAXAchrDrjc7LBuTVNXySswadG3apCKy9P",
                  "image": "data:image/png;base64,iVBORw0KGgo...kJggg==",
                  "lprCategory": "C09",
                  "lprNumber": "000-000-204",
                  "residentSince": "2015-01-01",
                  "type": [
                    "PermanentResident",
                    "Person"
                  ]
                },
                "id": "http://credential_mock:8000/api/credential/z6MkoBjc4GfEWrdAXAchrDrjc7LBuTVNXySswadG3apCKy9P",
                "issuanceDate": "2022-10-28T19:35:20Z",
                "issuer": "did:knox:z6Mkv9L4S8FQ3qcu8UqG8NFHt5LKcfzPeLvPJB7uW5vrp3WF",
                "type": [
                  "VerifiableCredential",
                  "PermanentResidentCard"
                ]
        });

        expect
    }
}
