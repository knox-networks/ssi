use super::Signature;

const DID_PREFIX: &str = "did:knox:";

const ED25519_SIGNATURE_2020: &str = "Ed25519Signature2020";
const ED25519_VERIFICATION_KEY_2020: &str = "Ed25519VerificationKey2020";

// Implementation of https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/

#[derive(Debug, PartialEq, Clone)]
pub struct Ed25519Signature(pub Vec<u8>);

#[derive(Debug, Clone, Copy)]
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

pub struct Ed25519DidVerifier {
    public_key: ed25519_zebra::VerificationKey,
}

pub struct Ed25519DidSigner {
    private_key: ed25519_zebra::SigningKey,
    pub(crate) public_key: ed25519_zebra::VerificationKey,
}

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl super::Signature for Ed25519Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, super::SignatureError> {
        Ok(Ed25519Signature(bytes.to_vec()))
    }
}

impl super::PrivateKey for ed25519_zebra::SigningKey {}
impl super::PublicKey for ed25519_zebra::VerificationKey {}

impl super::KeyPair<ed25519_zebra::SigningKey, ed25519_zebra::VerificationKey>
    for Ed25519SSIKeyPair
{
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

impl Ed25519SSIKeyPair {
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

impl Ed25519DidSigner {
    pub fn new() -> Self {
        let sk = ed25519_zebra::SigningKey::new(rand::thread_rng());

        return Self {
            private_key: sk,
            public_key: ed25519_zebra::VerificationKey::from(&sk),
        };
    }
}

impl super::DIDSigner<Ed25519Signature> for Ed25519DidSigner {
    fn try_sign(&self, data: &[u8]) -> Result<Ed25519Signature, super::SignatureError> {
        let res: [u8; 64] = self.private_key.sign(data).into();
        return Ed25519Signature::from_bytes(&res);
    }

    fn get_proof_type(&self) -> String {
        return ED25519_SIGNATURE_2020.to_string();
    }

    fn get_verification_method(&self, _relation: super::VerificationRelation) -> String {
        let encoded_pk = multibase::encode(multibase::Base::Base58Btc, self.public_key);
        return format!("did:knox:{0}#{0}", encoded_pk);
    }

    fn encode(&self, sig: Ed25519Signature) -> String {
        multibase::encode(multibase::Base::Base58Btc, sig)
    }
}

impl From<&Ed25519DidSigner> for Ed25519DidVerifier {
    fn from(signer: &Ed25519DidSigner) -> Self {
        Self {
            public_key: signer.public_key,
        }
    }
}

impl From<&Ed25519SSIKeyPair> for Ed25519DidVerifier {
    fn from(kp: &Ed25519SSIKeyPair) -> Self {
        Self {
            public_key: kp.master_public_key,
        }
    }
}

impl super::DIDVerifier<Ed25519Signature> for Ed25519DidVerifier {
    fn verify(&self, msg: &[u8], sig: &Ed25519Signature) -> Result<(), super::SignatureError> {
        let sig_bytes: [u8; 64] = sig
            .0
            .as_slice()
            .try_into()
            .map_err(|_| super::SignatureError::new(crate::error::ErrorKind::Uncategorized))?;

        self.public_key
            .verify(&ed25519_zebra::Signature::from(sig_bytes), msg)
            .map_err(super::SignatureError::from)
    }
    fn decode(&self, encoded_sig: String) -> Result<Ed25519Signature, super::SignatureError> {
        let res = multibase::decode(encoded_sig);

        match res {
            Ok(sig) => {
                let sig_bytes: [u8; 64] = sig.1.as_slice().try_into().unwrap();
                return Ed25519Signature::from_bytes(&sig_bytes)
                    .map_err(super::SignatureError::from);
            }
            _ => Err(super::SignatureError::new(
                crate::error::ErrorKind::Uncategorized,
            )),
        }
    }

    fn decoded_relational_verify(
        &self,
        msg: &[u8],
        data: String,
        relation: super::VerificationRelation,
    ) -> Result<(), super::SignatureError> {
        let decoded_sig = self.decode(data)?;
        return self.relational_verify(msg, &decoded_sig, relation);
    }

    fn relational_verify(
        &self,
        msg: &[u8],
        sig: &Ed25519Signature,
        relation: super::VerificationRelation,
    ) -> Result<(), super::SignatureError> {
        let sig_bytes: [u8; 64] = sig
            .0
            .as_slice()
            .try_into()
            .map_err(|_| super::SignatureError::new(crate::error::ErrorKind::Uncategorized))?;

        let sig = ed25519_zebra::Signature::from(sig_bytes);
        match relation {
            super::VerificationRelation::AssertionMethod => self
                .public_key
                .verify(&sig, msg)
                .map_err(super::SignatureError::from),
            super::VerificationRelation::Authentication => self
                .public_key
                .verify(&sig, msg)
                .map_err(super::SignatureError::from),
            super::VerificationRelation::CapabilityInvocation => self
                .public_key
                .verify(&sig, msg)
                .map_err(super::SignatureError::from),
            super::VerificationRelation::CapabilityDelegation => self
                .public_key
                .verify(&sig, msg)
                .map_err(super::SignatureError::from),
        }
    }

    fn get_key_material_type(&self) -> String {
        ED25519_VERIFICATION_KEY_2020.to_string()
    }

    fn get_verification_method(&self, relation: super::VerificationRelation) -> String {
        let encoded_pk = self.get_public_key_by_relation(relation);
        return format!("did:knox:{0}#{0}", encoded_pk);
    }

    fn get_public_key_by_relation(&self, relation: crate::suite::VerificationRelation) -> String {
        match relation {
            _ => {
                let encoded_pk = multibase::encode(multibase::Base::Base58Btc, self.public_key);
                return format!("did:knox:{0}#{0}", encoded_pk);
            }
        }
    }

    fn get_did_method(&self) -> String {
        DID_PREFIX.to_string()
    }

    fn get_did(&self) -> String {
        let encoded_pk = multibase::encode(multibase::Base::Base58Btc, self.public_key);
        return format!("did:knox:{0}", encoded_pk);
    }
}
