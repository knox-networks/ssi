mod normalization;

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
struct ProofOptionDocument {
    #[serde(rename = "@context")]
    context: super::credential::DocumentContext,
    #[serde(rename = "type")]
    proof_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "verificationMethod")]
    verification_method: String,
    #[serde(rename = "proofPurpose")]
    proof_purpose: signature::suite::VerificationRelation,
}

impl ProofOptionDocument {
    fn get_default_context() -> super::credential::DocumentContext {
        vec![
            super::credential::ContextValue::String(
                super::credential::BASE_CREDENTIAL_CONTEXT.to_string(),
            ),
            super::credential::ContextValue::String(
                super::credential::EXAMPLE_CREDENTIAL_CONTEXT.to_string(),
            ),
        ]
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
pub struct DataIntegrityProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: signature::suite::VerificationRelation,
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

impl ProofOptionDocument {
    pub fn into_data_integrity_proof(self, proof_value: String) -> DataIntegrityProof {
        DataIntegrityProof {
            proof_type: self.proof_type,
            created: self.created,
            verification_method: self.verification_method,
            proof_purpose: self.proof_purpose,
            proof_value,
        }
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
    let proof_options = ProofOptionDocument {
        context: ProofOptionDocument::get_default_context(),
        proof_type: signer.get_proof_type(),
        created: Some(chrono::Utc::now()),
        verification_method: signer.get_verification_method(relation),
        proof_purpose: relation,
    };
    let proof = create_ed25519_signature_2020_proof_value(signer, unsecured_doc, &proof_options)?;

    Ok(CredentialProof::Single(ProofType::Ed25519Signature2020(
        proof_options.into_data_integrity_proof(proof),
    )))
}

#[cfg(feature = "v2_test")]
pub fn create_data_integrity_proof_for_test<S: signature::suite::Signature>(
    signer: &impl signature::suite::DIDSigner<S>,
    unsecured_doc: serde_json::Value,
    proof_time: chrono::DateTime<chrono::Utc>,
    verification_method: String,
) -> Result<CredentialProof, super::error::Error> {
    let proof_options = ProofOptionDocument {
        context: ProofOptionDocument::get_default_context(),
        proof_type: signer.get_proof_type(),
        created: Some(proof_time),
        verification_method,
        proof_purpose: signature::suite::VerificationRelation::AssertionMethod,
    };

    let proof = create_ed25519_signature_2020_proof_value(signer, unsecured_doc, &proof_options)?;

    Ok(CredentialProof::Single(ProofType::Ed25519Signature2020(
        proof_options.into_data_integrity_proof(proof),
    )))
}

fn create_ed25519_signature_2020_proof_value<S: signature::suite::Signature>(
    signer: &impl signature::suite::DIDSigner<S>,
    unsecured_doc: serde_json::Value,
    proof_options: &ProofOptionDocument,
) -> Result<String, super::error::Error> {
    let serialized_proof_options = serde_json::to_value(&proof_options)?;

    let transformed_data = normalization::create_normalized_doc(unsecured_doc)?;
    let transformed_proof_options = normalization::create_normalized_doc(serialized_proof_options)?;
    let hashed_unsecured_doc = normalization::hash(&transformed_data)?;
    let hash_proof_options = normalization::hash(&transformed_proof_options)?;

    //concatenate hashed_unsecured_doc and hash_proof_options
    //hash_proof_options should be the first part of the combined hash
    let mut combined_hash_data = hash_proof_options.to_vec();
    combined_hash_data.extend_from_slice(&hashed_unsecured_doc);

    let proof = signer.encoded_relational_sign(&combined_hash_data, proof_options.proof_purpose)?;

    Ok(proof)
}

#[cfg(test)]
mod tests {

    use super::create_data_integrity_proof;

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
        let res = create_data_integrity_proof(&signer, doc.clone(), relation);
        assert!(res.is_ok());
    }
    fn create_unverified_credential_doc() -> serde_json::Value {
        let expect = serde_json::json!({
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
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
