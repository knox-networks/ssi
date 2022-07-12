use signature::Signature;

use crate::suite::{Ed25519Signature, VerificationRelation};

pub trait DIDSigner<S>: signature::Signer<S>
where
    S: signature::Signature,
{
    fn get_proof_type(&self) -> String;
    fn get_verification_method(&self, relation: VerificationRelation) -> String;
    fn encoded_sign(&self, data: &[u8]) -> String {
        let signature = self.sign(data);
        return self.encode(signature);
    }
    fn try_encoded_sign(&self, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        let signature = self.try_sign(data)?;
        return Ok(self.encode(signature));
    }
    fn encode(&self, sig: S) -> String;
}

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

impl signature::Signer<Ed25519Signature> for Ed25519DidSigner {
    fn try_sign(&self, data: &[u8]) -> Result<Ed25519Signature, signature::Error> {
        let res: [u8; 64] = self.private_key.sign(data).into();
        return Ed25519Signature::from_bytes(&res).map_err(|_| signature::Error::new());
    }
}

impl DIDSigner<Ed25519Signature> for Ed25519DidSigner {
    fn get_proof_type(&self) -> String {
        return "Ed25519Signature2018".to_string();
    }
    fn get_verification_method(&self, _relation: VerificationRelation) -> String {
        let encoded_pk = multibase::encode(multibase::Base::Base58Btc, self.public_key);
        return format!("did:knox:{}#keys-1", encoded_pk);
    }

    fn encode(&self, sig: Ed25519Signature) -> String {
        multibase::encode(multibase::Base::Base58Btc, sig)
    }
}
