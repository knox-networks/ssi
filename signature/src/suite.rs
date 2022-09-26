use crate::error::SignatureError;
pub mod ed25519_2020;

#[derive(
    serde::Serialize, serde::Deserialize, Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum VerificationRelation {
    AssertionMethod,
    Authentication,
    CapabilityInvocation,
    CapabilityDelegation,
}

pub trait Signature: AsRef<[u8]> + core::fmt::Debug + Sized {
    /// Parse a signature from its byte representation
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError>;

    /// Borrow a byte slice representing the serialized form of this signature
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

impl std::fmt::Display for VerificationRelation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            VerificationRelation::AssertionMethod => write!(f, "assertionMethod"),
            VerificationRelation::Authentication => write!(f, "authentication"),
            VerificationRelation::CapabilityInvocation => write!(f, "capabilityInvocation"),
            VerificationRelation::CapabilityDelegation => write!(f, "capabilityDelegation"),
        }
    }
}

pub trait PrivateKey: Copy + Clone {}

pub trait PublicKey: Copy + Clone {}

pub trait KeyPair<T: PrivateKey, U: PublicKey> {
    fn get_public_key_encoded(&self, relation: crate::suite::VerificationRelation) -> String
    where
        Self: Sized;

    fn get_master_public_key(&self) -> U
    where
        Self: Sized;
    fn get_master_private_key(&self) -> T
    where
        Self: Sized;

    fn get_private_key_by_relation(&self, relation: crate::suite::VerificationRelation) -> T
    where
        Self: Sized;
}

pub trait DIDSigner<S>
where
    S: Signature,
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
