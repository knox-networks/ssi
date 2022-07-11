use sha2::{Digest, Sha512};

mod normalization;
mod signer;

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
    use serde_json::json;

    use super::{create_data_integrity_proof, signer};
    use signer::DidSigner;

    /// A generalized signature that can use a variety of possible backends.
    #[derive(Debug, PartialEq, Clone)]
    struct MockSignature(Vec<u8>);

    impl AsRef<[u8]> for MockSignature {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    impl signature::Signature for MockSignature {
        fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
            Ok(MockSignature(bytes.to_vec()))
        }
    }

    struct Ed25519DidSigner {
        private_key: ed25519_zebra::SigningKey,
        public_key: ed25519_zebra::VerificationKey,
    }

    impl Ed25519DidSigner {
        fn new() -> Self {
            let sk = ed25519_zebra::SigningKey::new(rand::thread_rng());

            return Self {
                private_key: sk,
                public_key: ed25519_zebra::VerificationKey::from(&sk),
            };
        }
    }

    impl signature::Signer<MockSignature> for Ed25519DidSigner {
        fn try_sign(&self, data: &[u8]) -> Result<MockSignature, signature::Error> {
            let res: [u8; 64] = self.private_key.sign(data).into();
            return Ok(MockSignature(res.to_vec()));
        }
    }

    impl signer::DidSigner<MockSignature> for Ed25519DidSigner {
        fn get_proof_type(&self) -> String {
            return "Ed25519Signature2018".to_string();
        }
        fn get_verification_method(&self, _relation: signer::VerificationRelation) -> String {
            let encoded_pk = multibase::encode(multibase::Base::Base58Btc, self.public_key);
            return format!("did:knox:{}#keys-1", encoded_pk);
        }

        fn encode(&self, sig: MockSignature) -> String {
            multibase::encode(multibase::Base::Base58Btc, sig)
        }
    }

    #[rstest::rstest]
    #[case::success(json!("{}"), signer::VerificationRelation::AssertionMethod)]
    fn test_create_data_integrity_proof(
        #[case] doc: serde_json::Value,
        #[case] relation: signer::VerificationRelation,
    ) {
        let signer = Ed25519DidSigner::new();

        let res = create_data_integrity_proof(&signer, doc, relation);

        assert!(res.is_ok());
        match res {
            Ok(proof) => {
                assert_eq!(proof.proof_type, signer.get_proof_type());
                assert_eq!(
                    proof.verification_method,
                    signer.get_verification_method(relation)
                );
                assert_eq!(proof.proof_purpose, relation.to_string());
            }
            Err(e) => panic!("{:?}", e),
        }
    }
}
