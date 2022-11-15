use sha2::{Digest, Sha512};

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

// Use it as an example
/// Given a JSON-LD document, create a data integrity proof for the document.
/// Currently, only `Ed25519Signature2018` data integrity proofs in the JSON-LD format can be created.
pub fn create_data_integrity_proof<S: signature::suite::Signature>(
    signer: &impl signature::suite::DIDSigner<S>,
    doc: serde_json::Value,
    relation: signature::suite::VerificationRelation,
) -> Result<DataIntegrityProof, Box<dyn std::error::Error>> {
    let mut hasher = Sha512::new();
    hasher.update(normalization::normalize(doc));
    let result = hasher.finalize();

    let encoded_sig = signer.try_encoded_sign(&result)?;
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
    use sha2::Digest;

    use super::create_data_integrity_proof;
    use signature::suite::DIDSigner;
    use signature::suite::DIDVerifier;

    const TEST_DID_METHOD: &str = "knox";

    #[rstest::rstest]
    #[case::success(
        serde_json::Value::default(),
        signature::suite::VerificationRelation::AssertionMethod
    )]
    fn test_create_data_integrity_proof(
        #[case] doc: serde_json::Value,
        #[case] relation: signature::suite::VerificationRelation,
    ) {
        let kp =
            signature::suite::ed25519_2020::Ed25519KeyPair::new(TEST_DID_METHOD.to_string(), None)
                .unwrap();
        let signer: signature::suite::ed25519_2020::Ed25519DidSigner = kp.clone().into();
        let verifier: signature::suite::ed25519_2020::Ed25519DidVerifier = kp.into();
        let res = create_data_integrity_proof(&signer, doc.clone(), relation);

        assert!(res.is_ok());
        match res {
            Ok(proof) => {
                assert_eq!(proof.proof_type, signer.get_proof_type());
                assert_eq!(
                    proof.verification_method,
                    signer.get_verification_method(relation)
                );
                assert_eq!(proof.proof_purpose, relation.to_string());

                let mut hasher = sha2::Sha512::new();
                let encoded = doc.to_string();
                let result = encoded.into_bytes();
                hasher.update(result);
                let comparison = hasher.finalize();

                assert!(verifier
                    .decoded_relational_verify(&comparison, proof.proof_value, relation)
                    .is_ok());
            }
            Err(e) => panic!("{:?}", e),
        }
    }
}
