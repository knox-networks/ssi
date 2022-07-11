use sha2::{Digest, Sha512};

mod normalization;

pub struct DataIntegrityProof {
    proof_type: String,
    created: String,
    verification_method: String,
    proof_purpose: String,
    proof_value: String,
}

/// Given a JSON-LD document, create a data integrity proof for the document.
/// Currently, only `Ed25519Signature2018` data integrity proofs in the JSON-LD format can be created.
pub fn create_data_integrity_proof<S: signature::Signature>(
    signer: &impl signature::DIDSigner<S>,
    doc: serde_json::Value,
    relation: signature::VerificationRelation,
) -> Result<DataIntegrityProof, Box<dyn std::error::Error>> {
    let mut hasher = Sha512::new();
    hasher.update(normalization::normalize(doc));
    let result = hasher.finalize();

    let encoded_sig = signer.encoded_sign(&result);
    return Ok(DataIntegrityProof {
        proof_type: signer.get_proof_type(),
        created: chrono::Utc::now().to_rfc3339(),
        verification_method: signer.get_verification_method(relation),
        proof_purpose: relation.to_string(),
        proof_value: encoded_sig,
    });
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sha2::Digest;

    use super::create_data_integrity_proof;
    use signature::{DIDSigner, DIDVerifier};

    #[rstest::rstest]
    #[case::success(json!("{}"), signature::VerificationRelation::AssertionMethod)]
    fn test_create_data_integrity_proof(
        #[case] doc: serde_json::Value,
        #[case] relation: signature::VerificationRelation,
    ) {
        let signer = signature::Ed25519DidSigner::new();
        let verifier = signature::Ed25519DidVerifier::from(&signer);
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
                hasher.update(crate::proof::normalization::normalize(doc.clone()));
                let comparison = hasher.finalize();
                assert!(verifier
                    .decoded_relational_verify(&comparison, proof.proof_value, relation)
                    .is_ok());
            }
            Err(e) => panic!("{:?}", e),
        }
    }
}
