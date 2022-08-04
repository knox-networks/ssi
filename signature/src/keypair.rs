use std::any::type_name;

// use ed25519_zebra::VerificationKey;

fn type_of<T>(_: T) -> &'static str {
    type_name::<T>()
}

const DID_PREFIX: &str = "did:knox:";
const DEFAULT_VERIFICATION_METHOD: &str = "Ed25519Signature2018";

// pub trait KeyPair: core::fmt::Debug + Copy +AsRef<[u8]> + Sized {

    // And then the Signer can be created from the KeyPair similarly to how I create the verifier from the signer

pub trait KeyPair <T: Copy +AsRef<[u8]>>: core::fmt::Debug + Sized {
    fn get_public_key_encoded(&self) -> String
    where
        Self: Sized;
    fn get_private_key_encoded(&self) -> String
    where
        Self: Sized;
    fn get_public_key(&self) -> T
    where
        Self: Sized;
    fn get_private_key(&self) -> T
    where
        Self: Sized;
}

#[derive(Debug)]
pub struct SSIKeyPair {
    pub (crate) relation: crate::suite::VerificationRelation,

    pub(crate) private_key: ed25519_zebra::SigningKey,
    pub(crate) public_key: ed25519_zebra::VerificationKey,
   
    pub(crate) master_public_key: ed25519_zebra::VerificationKey,
    pub(crate) master_private_key: ed25519_zebra::SigningKey,

    pub(crate) authetication_public_key: ed25519_zebra::VerificationKey,
    pub(crate) authetication_private_key: ed25519_zebra::SigningKey,

    pub(crate) capability_invocation_public_key: ed25519_zebra::VerificationKey,
    pub(crate) capability_invocation_private_key: ed25519_zebra::SigningKey,

    pub(crate) capability_delegation_public_key: ed25519_zebra::VerificationKey,
    pub(crate) capability_delegation_private_key: ed25519_zebra::SigningKey,

    pub(crate) assertion_method_public_key: ed25519_zebra::VerificationKey,
    pub(crate) assertion_method_private_key: ed25519_zebra::SigningKey,
}

pub struct SSIKeyMaterial{
    id:                 String,
    proof_type:         String,
    controller:         String,
    public_key_multibase: crate::suite::VerificationRelation,
    master_public_key:  String,
}

impl SSIKeyPair{
    pub(crate) fn get_verification_method(self, relation: crate::suite::VerificationRelation) -> String {
        match relation {
            crate::suite::VerificationRelation::AssertionMethod => {
                DID_PREFIX + self.master_public_key + self.assertion_method_public_key
            },
            crate::suite::VerificationRelation::Authentication => {
                DID_PREFIX + self.master_public_key + self.authetication_public_key
            },
            crate::suite::VerificationRelation::CapabilityInvocation => {
                DID_PREFIX + self.master_public_key + self.capability_invocation_public_key
            },
            crate::suite::VerificationRelation::CapabilityDelegation => {
                DID_PREFIX + self.master_public_key + self.capability_delegation_public_key
            },
        }
    }

    pub(crate) fn get_public_key_by_relation(&self, relation: crate::suite::VerificationRelation) -> String {
        match relation {
            crate::suite::VerificationRelation::AssertionMethod => {
                self.assertion_method_public_key
            },
            crate::suite::VerificationRelation::Authentication => {
                self.authetication_public_key
            },
            crate::suite::VerificationRelation::CapabilityInvocation => {
                self.capability_invocation_public_key
            },
            crate::suite::VerificationRelation::CapabilityDelegation => {
                self.capability_delegation_public_key
            },
        }
    }

    pub(crate) fn get_controller(&self, relation: crate::suite::VerificationRelation) -> String {
        format!("{}{}", DID_PREFIX, self.master_public_key)
    }

}

impl<T: Copy + core::fmt::Debug+AsRef<[u8]>> KeyPair<T> for SSIKeyPair<T> {
    fn get_public_key_encoded(&self) -> String {
        multibase::encode(multibase::Base::Base58Btc, self.public_key)
    }
    fn get_private_key_encoded(&self) -> String {
        multibase::encode(multibase::Base::Base58Btc, self.private_key)
    }
    fn get_public_key(&self) -> T {
        return self.public_key.clone();
    }
    fn get_private_key(&self) -> T {
        return self.private_key.clone();
    }
}
