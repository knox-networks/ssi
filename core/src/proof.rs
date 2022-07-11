use sha2::{Digest, Sha512};

use crate::signer;
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
    signer: &impl signer::DidSigner<S>,
    doc: serde_json::Value,
    relation: signer::VerificationRelation,
) -> Result<DataIntegrityProof, Box<dyn std::error::Error>> {
    let mut hasher = Sha512::new();
    hasher.update(normalization::normalize(doc));
    let result = hasher.finalize();

    let encoded_sig = signer.encoded_sign(&result); //multibase::encode(multibase::Base::Base58Btc, signer.sign(&result));
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

    #[rstest::rstest]
    #[case::success()]
    fn test_create_data_integrity_proof() {}
}
