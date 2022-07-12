#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum VerificationRelation {
    AssertionMethod,
    Authentication,
    CapabilityInvocation,
    CapabilityDelegation,
}
/// A generalized signature that can use a variety of possible backends.
#[derive(Debug, PartialEq, Clone)]
pub struct Ed25519Signature(pub Vec<u8>);

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
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

impl signature::Signature for Ed25519Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        Ok(Ed25519Signature(bytes.to_vec()))
    }
}
