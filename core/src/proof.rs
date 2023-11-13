mod normalization;

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
pub struct DataIntegrityProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    #[serde(rename = "created")]
    pub created: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

impl std::fmt::Display for DataIntegrityProof {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{{\"type\": \"{}\", \"created\": \"{}\", \"verificationMethod\": \"{}\", \"proofPurpose\": \"{}\", \"proofValue\": \"{}\"}}",
            self.proof_type, self.created, self.verification_method, self.proof_purpose, self.proof_value
        )
    }
}

// Use it as an example
/// Given a JSON-LD document, create a data integrity proof for the document.
/// Currently, only `Ed25519Signature2018` data integrity proofs in the JSON-LD format can be created.
pub fn create_data_integrity_proof<S: signature::suite::Signature>(
    signer: &impl signature::suite::DIDSigner<S>,
    doc: serde_json::Value,
    relation: signature::suite::VerificationRelation,
) -> Result<DataIntegrityProof, super::error::Error> {
    let hashed_normalized_doc = normalization::normalize(doc);

    println!("result {:?}", hashed_normalized_doc);

    let encoded_sig = signer.encoded_relational_sign(&hashed_normalized_doc, relation)?;

    Ok(DataIntegrityProof {
        proof_type: signer.get_proof_type(),
        created: chrono::Utc::now().to_rfc3339(),
        verification_method: signer.get_verification_method(relation),
        proof_purpose: relation.to_string(),
        proof_value: encoded_sig,
    })
}

#[cfg(test)]
mod tests {

    use super::create_data_integrity_proof;
    use signature::suite::DIDSigner;
    use signature::suite::DIDVerifier;

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
                println!("{proof}");
                assert_eq!(proof.proof_type, signer.get_proof_type());
                assert_eq!(
                    proof.verification_method,
                    signer.get_verification_method(relation)
                );
                assert_eq!(proof.proof_purpose, relation.to_string());
                let comparison = crate::proof::normalization::normalize(doc);
                // let mut hasher = sha2::Sha512::new();
                // let encoded = doc.to_string();
                // let result = encoded.into_bytes();
                // hasher.update(result);
                // let comparison = hasher.finalize();

                assert!(verifier
                    .decoded_relational_verify(&comparison, proof.proof_value, relation)
                    .is_ok());
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
