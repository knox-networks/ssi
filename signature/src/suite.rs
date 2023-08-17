pub mod ed25519_2020;
pub mod error;

#[derive(
    serde::Serialize, serde::Deserialize, Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum VerificationRelation {
    AssertionMethod,
    Authentication,
    CapabilityInvocation,
    CapabilityDelegation,
}

pub trait Signature: AsRef<[u8]> + core::fmt::Debug + Sized + Send + Sync {
    /// Parse a signature from its byte representation
    fn from_bytes(bytes: &[u8]) -> Result<Self, error::Error>;

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

pub trait PublicKey: Copy + Clone {
    fn get_encoded_public_key(&self) -> String;
}

pub trait KeyPair<T, U>
where
    T: PrivateKey,
    U: PublicKey,
    Self: Send + Sync + std::fmt::Debug,
{
    fn get_did_method(&self) -> String;
    fn get_did(&self) -> String;

    fn get_public_key_encoded(&self, relation: VerificationRelation) -> String
    where
        Self: Sized;

    fn get_master_public_key(&self) -> U
    where
        Self: Sized;

    fn get_encoded_master_public_key(&self) -> String
    where
        Self: Sized;

    fn get_master_private_key(&self) -> T
    where
        Self: Sized;

    fn get_private_key_by_relation(&self, relation: VerificationRelation) -> T
    where
        Self: Sized;

    fn get_public_key_by_relation(&self, relation: VerificationRelation) -> U
    where
        Self: Sized;
}

pub trait DIDSigner<S>
where
    S: Signature,
    Self: Send + Sync + std::fmt::Debug,
{
    fn sign(&self, msg: &[u8]) -> S {
        self.try_sign(msg).expect("signature operation failed")
    }

    fn encoded_sign(&self, data: &[u8]) -> String {
        let signature = self.sign(data);
        self.encode(signature)
    }

    fn encoded_relational_sign(
        &self,
        data: &[u8],
        relation: VerificationRelation,
    ) -> Result<String, error::Error> {
        let signature = self.relational_sign(data, relation)?;
        Ok(self.encode(signature))
    }

    fn relational_sign(
        &self,
        msg: &[u8],
        relation: VerificationRelation,
    ) -> Result<S, error::Error>;

    fn try_encoded_sign(&self, data: &[u8]) -> Result<String, error::Error> {
        let signature = self.try_sign(data)?;
        Ok(self.encode(signature))
    }

    fn try_sign(&self, msg: &[u8]) -> Result<S, error::Error>;
    fn get_proof_type(&self) -> String;
    fn get_verification_method(&self, relation: VerificationRelation) -> String;
    fn encode(&self, sig: S) -> String;
}

pub trait DIDVerifier<S>
where
    S: Signature,
    Self: Send + Sync + std::fmt::Debug,
{
    fn decoded_verify(&self, msg: &[u8], data: String) -> Result<(), error::Error> {
        let decoded_sig = self.decode(data)?;
        self.verify(msg, &decoded_sig)
    }

    fn verify(&self, msg: &[u8], signature: &S) -> Result<(), error::Error>;
    fn decoded_relational_verify(
        &self,
        msg: &[u8],
        data: String,
        relation: VerificationRelation,
    ) -> Result<(), error::Error>;
    fn relational_verify(
        &self,
        msg: &[u8],
        signature: &S,
        relation: VerificationRelation,
    ) -> Result<(), error::Error>;
    fn decode(&self, encoded_sig: String) -> Result<S, error::Error>;
    fn get_did_method(&self) -> String;
    fn get_did(&self) -> String;
    fn get_key_material_type(&self) -> String;
    fn get_verification_method(&self, relation: VerificationRelation) -> String;
    fn get_encoded_public_key_by_relation(&self, relation: VerificationRelation) -> String;
}
