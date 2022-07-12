use crate::suite::{Ed25519Signature, VerificationRelation};
pub use signature::Signature;

pub struct Ed25519DidVerifier {
    public_key: ed25519_zebra::VerificationKey,
}

impl From<&crate::signer::Ed25519DidSigner> for Ed25519DidVerifier {
    fn from(signer: &crate::signer::Ed25519DidSigner) -> Self {
        Self {
            public_key: signer.public_key,
        }
    }
}

pub trait DIDVerifier<S>: signature::Verifier<S>
where
    S: signature::Signature,
{
    fn decoded_verify(&self, msg: &[u8], data: String) -> Result<(), signature::Error> {
        let decoded_sig = self.decode(data)?;
        return self.verify(msg, &decoded_sig);
    }

    fn decoded_relational_verify(
        &self,
        msg: &[u8],
        data: String,
        relation: VerificationRelation,
    ) -> Result<(), signature::Error>;

    fn relational_verify(
        &self,
        msg: &[u8],
        signature: &S,
        relation: VerificationRelation,
    ) -> Result<(), signature::Error>;

    fn decode(&self, encoded_sig: String) -> Result<S, signature::Error>;
}

impl signature::Verifier<Ed25519Signature> for Ed25519DidVerifier {
    fn verify(&self, msg: &[u8], sig: &Ed25519Signature) -> Result<(), signature::Error> {
        let sig_bytes: [u8; 64] = sig.0.as_slice().try_into().unwrap();
        self.public_key
            .verify(&ed25519_zebra::Signature::from(sig_bytes), msg)
            .map_err(|_| signature::Error::new())
    }
}

impl DIDVerifier<Ed25519Signature> for Ed25519DidVerifier {
    fn decode(&self, encoded_sig: String) -> Result<Ed25519Signature, signature::Error> {
        let res = multibase::decode(encoded_sig);

        match res {
            Ok(sig) => {
                let sig_bytes: [u8; 64] = sig.1.as_slice().try_into().unwrap();
                return Ed25519Signature::from_bytes(&sig_bytes)
                    .map_err(|_| signature::Error::new());
            }
            _ => Err(signature::Error::new()),
        }
    }

    fn decoded_relational_verify(
        &self,
        msg: &[u8],
        data: String,
        relation: VerificationRelation,
    ) -> Result<(), signature::Error> {
        let decoded_sig = self.decode(data)?;
        return self.relational_verify(msg, &decoded_sig, relation);
    }

    fn relational_verify(
        &self,
        msg: &[u8],
        sig: &Ed25519Signature,
        relation: VerificationRelation,
    ) -> Result<(), signature::Error> {
        let sig_bytes: [u8; 64] = sig
            .0
            .as_slice()
            .try_into()
            .map_err(|_| signature::Error::new())?;
        let sig = ed25519_zebra::Signature::from(sig_bytes);
        match relation {
            VerificationRelation::AssertionMethod => self
                .public_key
                .verify(&sig, msg)
                .map_err(|_| signature::Error::new()),
            VerificationRelation::Authentication => self
                .public_key
                .verify(&sig, msg)
                .map_err(|_| signature::Error::new()),
            VerificationRelation::CapabilityInvocation => self
                .public_key
                .verify(&sig, msg)
                .map_err(|_| signature::Error::new()),
            VerificationRelation::CapabilityDelegation => self
                .public_key
                .verify(&sig, msg)
                .map_err(|_| signature::Error::new()),
        }
    }
}
