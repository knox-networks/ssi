use crate::error::SignatureError;
use crate::suite::{Ed25519Signature, Signature, VerificationRelation};
use std::convert::From;

pub struct Ed25519DidSigner {
    private_key: ed25519_zebra::SigningKey,
    pub(crate) public_key: ed25519_zebra::VerificationKey,
}

impl Ed25519DidSigner {
    pub fn new() -> Self {
        let sk = ed25519_zebra::SigningKey::new(rand::thread_rng());

        return Self {
            private_key: sk,
            public_key: ed25519_zebra::VerificationKey::from(&sk),
        };
    }
}

impl super::DIDSigner<Ed25519Signature> for Ed25519DidSigner {
    fn try_sign(&self, data: &[u8]) -> Result<Ed25519Signature, SignatureError> {
        let res: [u8; 64] = self.private_key.sign(data).into();
        return Ed25519Signature::from_bytes(&res);
    }

    fn get_proof_type(&self) -> String {
        return crate::suite::PROOF_TYPE.to_string();
    }

    fn get_verification_method(&self, _relation: VerificationRelation) -> String {
        let encoded_pk = multibase::encode(multibase::Base::Base58Btc, self.public_key);
        return format!("did:knox:{0}#{0}", encoded_pk);
    }

    fn encode(&self, sig: Ed25519Signature) -> String {
        multibase::encode(multibase::Base::Base58Btc, sig)
    }
}
