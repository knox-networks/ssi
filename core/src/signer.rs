#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum VerificationRelation {
    AssertionMethod,
    Authentication,
    CapabilityInvocation,
    CapabilityDelegation,
}
pub trait DidSigner<S>: signature::Signer<S>
where
    S: signature::Signature,
{
    fn get_proof_type(&self) -> String;
    fn get_verification_method(&self, relation: VerificationRelation) -> String;
}

impl std::fmt::Display for VerificationRelation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
