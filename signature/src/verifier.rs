use crate::error::SignatureError;
use crate::suite::{Signature, VerificationRelation};

pub mod ed25519_verifier_2020;

pub trait DIDVerifier<S>
where
    S: Signature,
{
    fn decoded_verify(&self, msg: &[u8], data: String) -> Result<(), SignatureError> {
        let decoded_sig = self.decode(data)?;
        return self.verify(msg, &decoded_sig);
    }

    fn verify(&self, msg: &[u8], signature: &S) -> Result<(), SignatureError>;
    fn decoded_relational_verify(
        &self,
        msg: &[u8],
        data: String,
        relation: VerificationRelation,
    ) -> Result<(), SignatureError>;
    fn relational_verify(
        &self,
        msg: &[u8],
        signature: &S,
        relation: VerificationRelation,
    ) -> Result<(), SignatureError>;
    fn decode(&self, encoded_sig: String) -> Result<S, SignatureError>;
    fn get_did_method(&self) -> String;
    fn get_did(&self) -> String;
    fn get_key_material_type(&self) -> String;
    fn get_verification_method(&self, relation: VerificationRelation) -> String;
    fn get_public_key_by_relation(&self, relation: crate::suite::VerificationRelation) -> String;
}
