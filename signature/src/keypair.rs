use serde::{Deserialize, Serialize};

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

    fn get_private_key(&self, relation: crate::suite::VerificationRelation) -> T
    where
        Self: Sized;
}

impl PrivateKey for ed25519_zebra::SigningKey {}
impl PublicKey for ed25519_zebra::VerificationKey {}

impl KeyPair<ed25519_zebra::SigningKey, ed25519_zebra::VerificationKey> for Ed25519SSIKeyPair {
    fn get_public_key_encoded(&self, relation: crate::suite::VerificationRelation) -> String {
        match relation {
            crate::suite::VerificationRelation::AssertionMethod => {
                multibase::encode(multibase::Base::Base58Btc, self.assertion_method_public_key)
            }
            crate::suite::VerificationRelation::Authentication => {
                multibase::encode(multibase::Base::Base58Btc, self.authetication_public_key)
            }
            crate::suite::VerificationRelation::CapabilityInvocation => multibase::encode(
                multibase::Base::Base58Btc,
                self.capability_invocation_public_key,
            ),
            crate::suite::VerificationRelation::CapabilityDelegation => multibase::encode(
                multibase::Base::Base58Btc,
                self.capability_delegation_public_key,
            ),
        }
    }

    fn get_master_public_key(&self) -> ed25519_zebra::VerificationKey {
        return self.master_public_key;
    }

    fn get_master_private_key(&self) -> ed25519_zebra::SigningKey {
        return self.master_private_key;
    }

    fn get_private_key(
        &self,
        relation: crate::suite::VerificationRelation,
    ) -> ed25519_zebra::SigningKey {
        match relation {
            crate::suite::VerificationRelation::AssertionMethod => {
                return self.assertion_method_private_key
            }
            crate::suite::VerificationRelation::Authentication => {
                return self.authetication_private_key
            }
            crate::suite::VerificationRelation::CapabilityInvocation => {
                return self.capability_invocation_private_key
            }

            crate::suite::VerificationRelation::CapabilityDelegation => {
                return self.capability_delegation_private_key
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ed25519SSIKeyPair {
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
    pub fn generate_mnemonic(
        phrase: &str,
        language: bip39::Language,
    ) -> Result<bip39::Mnemonic, crate::error::Error> {
        bip39::Mnemonic::validate(phrase, language)?;
        let mnemonic = bip39::Mnemonic::from_phrase(phrase, language)?;
        Ok(mnemonic)
    }

    pub fn new() -> Self {
        let sk = ed25519_zebra::SigningKey::new(rand::thread_rng());
        let vk = ed25519_zebra::VerificationKey::from(&sk);

        return Self {
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
}
