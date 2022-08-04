use crate::error::SignatureError;
use crate::suite::{Ed25519Signature, Signature, VerificationRelation};
use std::convert::From;

// impl <T:Copy> From<Ed25519DidSigner> for crate::keypair::SSIKeyPair<T> {
//     fn from(signer: Ed25519DidSigner) -> crate::keypair::SSIKeyPair<T> {
//         crate::keypair::SSIKeyPair::new(signer)
//     }
// }

// impl From<&crate::signer::Ed25519DidSigner> for Ed25519DidVerifier {
//     fn from(signer: &crate::signer::Ed25519DidSigner) -> Self {
//         Self {
//             public_key: signer.public_key,
//         }
//     }
// }

impl From<&crate::signer::Ed25519DidSigner> for crate::keypair::SSIKeyPair {
    fn from(signer: &crate::signer::Ed25519DidSigner) -> Self {
        let key_pair = crate::keypair::SSIKeyPair::new(signer);
    }
}

pub trait DIDSigner<S>
where
    S: Signature,
    // T: crate::keypair::KeyPair<dyn Copy>,
{
    fn sign(&self, msg: &[u8]) -> S {
        self.try_sign(msg).expect("signature operation failed")
    }

    fn encoded_sign(&self, data: &[u8]) -> String {
        let signature = self.sign(data);
        return self.encode(signature);
    }

    fn try_encoded_sign(&self, data: &[u8]) -> Result<String, SignatureError> {
        let signature = self.try_sign(data)?;
        return Ok(self.encode(signature));
    }

    fn try_sign(&self, msg: &[u8]) -> Result<S, SignatureError>;
    fn get_proof_type(&self) -> String;
    fn get_verification_method(&self, relation: VerificationRelation) -> String;
    fn encode(&self, sig: S) -> String;
}

pub struct Ed25519DidSigner {
    private_key: ed25519_zebra::SigningKey,
    pub(crate) public_key: ed25519_zebra::VerificationKey,
    // pub(crate) key_pair: crate::keypair::SSIKeyPair<T>,
}

impl <T: Copy +AsRef<[u8]>> Ed25519DidSigner {
    pub fn new() -> Self {
        let sk = ed25519_zebra::SigningKey::new(rand::thread_rng());

        return Self {
            private_key: sk,
            public_key: ed25519_zebra::VerificationKey::from(&sk),
        };
    }
}

impl DIDSigner<Ed25519Signature> for Ed25519DidSigner {
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
