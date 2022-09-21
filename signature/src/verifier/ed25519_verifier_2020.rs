use crate::error::{ErrorKind, SignatureError};
use crate::suite::{Ed25519Signature, Signature, VerificationRelation};

const DID_PREFIX: &str = "did:knox:";

const ED25519_VERIFICATION_KEY_2020: &str = "Ed25519VerificationKey2020";

pub struct Ed25519DidVerifier {
    public_key: ed25519_zebra::VerificationKey,
}

impl From<&crate::signer::ed25519_signer_2020::Ed25519DidSigner> for Ed25519DidVerifier {
    fn from(signer: &crate::signer::ed25519_signer_2020::Ed25519DidSigner) -> Self {
        Self {
            public_key: signer.public_key,
        }
    }
}

impl From<&crate::keypair::Ed25519SSIKeyPair> for Ed25519DidVerifier {
    fn from(kp: &crate::keypair::Ed25519SSIKeyPair) -> Self {
        Self {
            public_key: kp.master_public_key,
        }
    }
}

impl super::DIDVerifier<Ed25519Signature> for Ed25519DidVerifier {
    fn verify(&self, msg: &[u8], sig: &Ed25519Signature) -> Result<(), SignatureError> {
        let sig_bytes: [u8; 64] = sig
            .0
            .as_slice()
            .try_into()
            .map_err(|_| SignatureError::new(ErrorKind::Uncategorized))?;

        self.public_key
            .verify(&ed25519_zebra::Signature::from(sig_bytes), msg)
            .map_err(SignatureError::from)
    }
    fn decode(&self, encoded_sig: String) -> Result<Ed25519Signature, SignatureError> {
        let res = multibase::decode(encoded_sig);

        match res {
            Ok(sig) => {
                let sig_bytes: [u8; 64] = sig.1.as_slice().try_into().unwrap();
                return Ed25519Signature::from_bytes(&sig_bytes).map_err(SignatureError::from);
            }
            _ => Err(SignatureError::new(ErrorKind::Uncategorized)),
        }
    }

    fn decoded_relational_verify(
        &self,
        msg: &[u8],
        data: String,
        relation: VerificationRelation,
    ) -> Result<(), SignatureError> {
        let decoded_sig = self.decode(data)?;
        return self.relational_verify(msg, &decoded_sig, relation);
    }

    fn relational_verify(
        &self,
        msg: &[u8],
        sig: &Ed25519Signature,
        relation: VerificationRelation,
    ) -> Result<(), SignatureError> {
        let sig_bytes: [u8; 64] = sig
            .0
            .as_slice()
            .try_into()
            .map_err(|_| SignatureError::new(ErrorKind::Uncategorized))?;

        let sig = ed25519_zebra::Signature::from(sig_bytes);
        match relation {
            VerificationRelation::AssertionMethod => self
                .public_key
                .verify(&sig, msg)
                .map_err(SignatureError::from),
            VerificationRelation::Authentication => self
                .public_key
                .verify(&sig, msg)
                .map_err(SignatureError::from),
            VerificationRelation::CapabilityInvocation => self
                .public_key
                .verify(&sig, msg)
                .map_err(SignatureError::from),
            VerificationRelation::CapabilityDelegation => self
                .public_key
                .verify(&sig, msg)
                .map_err(SignatureError::from),
        }
    }

    fn get_proof_type(&self) -> String {
        ED25519_VERIFICATION_KEY_2020.to_string()
    }

    fn get_verification_method(&self, relation: VerificationRelation) -> String {
        let encoded_pk = self.get_public_key_by_relation(relation);
        return format!("did:knox:{0}#{0}", encoded_pk);
    }

    fn get_public_key_by_relation(&self, relation: crate::suite::VerificationRelation) -> String {
        match relation {
            _ => {
                let encoded_pk = multibase::encode(multibase::Base::Base58Btc, self.public_key);
                return format!("did:knox:{0}#{0}", encoded_pk);
            }
        }
    }

    fn get_did_method(&self) -> String {
        DID_PREFIX.to_string()
    }

    fn get_did(&self) -> String {
        let encoded_pk = multibase::encode(multibase::Base::Base58Btc, self.public_key);
        return format!("did:knox:{0}", encoded_pk);
    }
}
