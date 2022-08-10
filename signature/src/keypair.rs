#![allow(unused_variables)]
#![allow(dead_code)]

use ed25519_zebra::VerificationKey;
use serde::{Deserialize, Serialize};
use std::any::type_name;

// use ed25519_zebra::VerificationKey;

fn type_of<T>(_: T) -> &'static str {
    type_name::<T>()
}

const DID_PREFIX: &str = "did:knox:";
const DEFAULT_VERIFICATION_METHOD: &str = "Ed25519Signature2018";

pub trait PrivateKey: Copy + Clone {}

pub trait PublicKey: Copy + Clone {}

pub trait KeyPair<T: PrivateKey, U: PublicKey> {
    fn get_public_key_encoded(&self) -> String
    where
        Self: Sized;
    fn get_private_key_encoded(&self) -> String
    where
        Self: Sized;
    fn get_public_key(&self) -> U
    where
        Self: Sized;
    fn get_private_key(&self) -> T
    where
        Self: Sized;
}

impl PrivateKey for ed25519_zebra::SigningKey {}
impl PublicKey for ed25519_zebra::VerificationKey {}

impl KeyPair<ed25519_zebra::SigningKey, ed25519_zebra::VerificationKey> for Ed25519SSIKeyPair {
    fn get_public_key_encoded(&self) -> String {
        multibase::encode(multibase::Base::Base58Btc, self.public_key)
    }
    fn get_private_key_encoded(&self) -> String {
        multibase::encode(multibase::Base::Base58Btc, self.private_key)
    }

    fn get_public_key(&self) -> ed25519_zebra::VerificationKey {
        return self.public_key;
    }
    fn get_private_key(&self) -> ed25519_zebra::SigningKey {
        return self.private_key.clone();
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SSIKeyMaterial {
    pub id: String,
    pub proof_type: String,
    pub controller: String,
    pub public_key_multibase: crate::suite::VerificationRelation,
    pub master_public_key: String,
}

#[derive(Debug, Clone, Copy)]
pub struct Ed25519SSIKeyPair {
    pub(crate) relation: crate::suite::VerificationRelation,

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

impl Ed25519SSIKeyPair {
    pub fn new() -> Self {
        let sk = ed25519_zebra::SigningKey::new(rand::thread_rng());
        let vk = ed25519_zebra::VerificationKey::from(&sk);

        return Self {
            private_key: sk,
            public_key: vk,
            relation: crate::suite::VerificationRelation::AssertionMethod,

            master_public_key: vk,
            master_private_key: sk,

            authetication_public_key: vk,
            authetication_private_key: sk,

            capability_invocation_public_key: vk,
            capability_invocation_private_key: sk,

            capability_delegation_public_key: vk,
            capability_delegation_private_key: sk,

            assertion_method_public_key: vk,
            assertion_method_private_key: sk,
        };
    }

    pub fn get_public_key_encoded(&self) -> String {
        multibase::encode(multibase::Base::Base58Btc, self.public_key)
    }

    pub fn get_master_public_key_encoded(&self) -> String {
        multibase::encode(multibase::Base::Base58Btc, self.master_public_key)
    }

pub fn get_verification_method(self, relation: crate::suite::VerificationRelation) -> String {
        let verification_key = match relation {
            crate::suite::VerificationRelation::AssertionMethod => self.assertion_method_public_key,
            crate::suite::VerificationRelation::Authentication => self.authetication_public_key,
            crate::suite::VerificationRelation::CapabilityInvocation => {
                self.capability_invocation_public_key
            }
            crate::suite::VerificationRelation::CapabilityDelegation => {
                self.capability_delegation_public_key
            }
        };
        format!(
            "{DID_PREFIX}{}#{}",
            multibase::encode(multibase::Base::Base58Btc, self.master_public_key),
            multibase::encode(multibase::Base::Base58Btc, verification_key)
        )
    }

    pub fn get_public_key_by_relation(
        &self,
        relation: crate::suite::VerificationRelation,
    ) -> ed25519_zebra::VerificationKey {
        match relation {
            crate::suite::VerificationRelation::AssertionMethod => self.assertion_method_public_key,
            crate::suite::VerificationRelation::Authentication => self.authetication_public_key,
            crate::suite::VerificationRelation::CapabilityInvocation => {
                self.capability_invocation_public_key
            }
            crate::suite::VerificationRelation::CapabilityDelegation => {
                self.capability_delegation_public_key
            }
        }
    }

    pub fn get_controller(&self, relation: crate::suite::VerificationRelation) -> String {
        format!(
            "{}{}",
            DID_PREFIX,
            multibase::encode(multibase::Base::Base58Btc, self.master_public_key)
        )
    }
}
