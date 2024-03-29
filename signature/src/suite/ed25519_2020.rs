use super::Signature;
use sha2::Digest;

const ED25519_SIGNATURE_2020: &str = "Ed25519Signature2020";
const ED25519_VERIFICATION_KEY_2020: &str = "Ed25519VerificationKey2020";

/// Ed25519 Multicodec constant
pub const MULTICODEC_ED25519_PUB: &[u8] = &[0xed, 0x01];

pub mod error;

// Implementation of https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/

#[derive(Debug, Clone, Copy)]
pub enum MnemonicLanguage {
    English,
}

impl std::fmt::Display for MnemonicLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MnemonicLanguage::English => write!(f, "english"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Mnemonic {
    pub language: MnemonicLanguage,
    pub phrase: String,
}

impl From<MnemonicLanguage> for bip39::Language {
    fn from(lang: MnemonicLanguage) -> Self {
        match lang {
            MnemonicLanguage::English => bip39::Language::English,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ed25519Signature(pub Vec<u8>);

impl From<Ed25519Signature> for [u8; 64] {
    fn from(sig: Ed25519Signature) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes.copy_from_slice(&sig.0[0..64]);
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct Ed25519KeyPair {
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

    pub(crate) mnemonic: Mnemonic,

    pub(crate) did_method: String,
}

#[derive(Debug)]
pub struct Ed25519DidVerifier {
    pub public_key: ed25519_zebra::VerificationKey,
    pub did_method: String,
}

#[derive(Debug)]
pub struct Ed25519DidSigner {
    private_key: ed25519_zebra::SigningKey,
    public_key: ed25519_zebra::VerificationKey,
    did_method: String,
}

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl super::Signature for Ed25519Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, super::error::Error> {
        Ok(Ed25519Signature(bytes.to_vec()))
    }
}

impl super::PrivateKey for ed25519_zebra::SigningKey {}
impl super::PublicKey for ed25519_zebra::VerificationKey {
    fn get_encoded_public_key(&self) -> String {
        multibase::encode(multibase::Base::Base58Btc, get_prefixed_public_key(self))
    }
}

fn get_prefixed_public_key(pk: &ed25519_zebra::VerificationKey) -> Vec<u8> {
    [MULTICODEC_ED25519_PUB, pk.as_ref()].concat()
}

impl super::KeyPair<ed25519_zebra::SigningKey, ed25519_zebra::VerificationKey> for Ed25519KeyPair {
    fn get_did_method(&self) -> String {
        self.did_method.clone()
    }

    fn get_did(&self) -> String {
        let encoded_pk = super::PublicKey::get_encoded_public_key(&self.master_public_key);
        format!("did:{0}:{1}", self.did_method, encoded_pk)
    }

    fn get_public_key_encoded(&self, relation: crate::suite::VerificationRelation) -> String {
        let public_key = self.get_public_key_by_relation(relation);
        super::PublicKey::get_encoded_public_key(&public_key)
    }

    fn get_public_key_by_relation(
        &self,
        relation: super::VerificationRelation,
    ) -> ed25519_zebra::VerificationKey
    where
        Self: Sized,
    {
        match relation {
            super::VerificationRelation::AssertionMethod => self.assertion_method_public_key,
            super::VerificationRelation::Authentication => self.authetication_public_key,
            super::VerificationRelation::CapabilityInvocation => {
                self.capability_invocation_public_key
            }
            super::VerificationRelation::CapabilityDelegation => {
                self.capability_delegation_public_key
            }
        }
    }

    fn get_master_public_key(&self) -> ed25519_zebra::VerificationKey {
        self.master_public_key
    }

    fn get_encoded_master_public_key(&self) -> String {
        super::PublicKey::get_encoded_public_key(&self.master_public_key)
    }

    fn get_master_private_key(&self) -> ed25519_zebra::SigningKey {
        self.master_private_key
    }

    fn get_private_key_by_relation(
        &self,
        relation: crate::suite::VerificationRelation,
    ) -> ed25519_zebra::SigningKey {
        match relation {
            crate::suite::VerificationRelation::AssertionMethod => {
                self.assertion_method_private_key
            }
            crate::suite::VerificationRelation::Authentication => self.authetication_private_key,
            crate::suite::VerificationRelation::CapabilityInvocation => {
                self.capability_invocation_private_key
            }
            crate::suite::VerificationRelation::CapabilityDelegation => {
                self.capability_delegation_private_key
            }
        }
    }
}

impl Ed25519KeyPair {
    pub fn from_private_key(
        did_method: String,
        formatted_encoded_private_key: String,
    ) -> Result<Self, error::Error> {
        let (base, encoded_private_key) = multibase::decode(formatted_encoded_private_key)?;
        if base != multibase::Base::Base58Btc {
            return Err(error::Error::KeyGeneration(
                "Invalid multibase encoding".to_string(),
            ));
        }

        //remove the first two elements of the private key array
        let raw_private_key = encoded_private_key
            .into_iter()
            .skip(MULTICODEC_ED25519_PUB.len())
            .collect::<Vec<u8>>();

        let sk = ed25519_zebra::SigningKey::try_from(raw_private_key.as_slice())
            .map_err(|e| error::Error::SigningKeyConversion(e.to_string()))?;

        let vk = ed25519_zebra::VerificationKey::from(&sk);

        Ok(Self {
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

            mnemonic: Mnemonic {
                language: MnemonicLanguage::English,
                phrase: "".to_string(),
            },
            did_method,
        })
    }

    pub fn new(did_method: String, mnemonic: Option<Mnemonic>) -> Result<Self, error::Error> {
        let mnemonic =
            mnemonic.unwrap_or_else(|| Self::generate_mnemonic(MnemonicLanguage::English));
        let bip39_mnemonic =
            bip39::Mnemonic::from_phrase(&mnemonic.phrase, mnemonic.language.into())
                .map_err(|e| error::Error::Bip39(e.to_string()))?;

        // we do not support passwords
        let seed = bip39::Seed::new(&bip39_mnemonic, "");

        // Hash the bip39 entropy seed into a [u8; 32] seed
        let mut hasher = sha2::Sha256::new();
        hasher.update(seed.as_bytes());

        // Use hashed bip39 seed as the signer seed.
        let seed = <[u8; 32]>::try_from(hasher.finalize())
            .map_err(|e| error::Error::SeedHashConversion(e.to_string()))?;

        let sk = ed25519_zebra::SigningKey::try_from(seed)
            .map_err(|e| error::Error::SigningKeyConversion(e.to_string()))?;

        let vk = ed25519_zebra::VerificationKey::from(&sk);

        Ok(Self {
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

            mnemonic,
            did_method,
        })
    }

    pub fn generate_mnemonic(language: MnemonicLanguage) -> Mnemonic {
        let mnemonic = bip39::Mnemonic::new(bip39::MnemonicType::Words24, language.into());

        return Mnemonic {
            language,
            phrase: mnemonic.phrase().to_string(),
        };
    }

    pub fn get_mnemonic(&self) -> Mnemonic {
        self.mnemonic.clone()
    }
}

impl super::DIDSigner<Ed25519Signature> for Ed25519DidSigner {
    fn try_sign(&self, data: &[u8]) -> Result<Ed25519Signature, super::error::Error> {
        let res: [u8; 64] = self.private_key.sign(data).into();
        Ed25519Signature::from_bytes(&res)
    }

    fn get_proof_type(&self) -> String {
        ED25519_SIGNATURE_2020.to_string()
    }

    fn get_verification_method(&self, _relation: super::VerificationRelation) -> String {
        let encoded_pk = super::PublicKey::get_encoded_public_key(&self.public_key);

        format!("did:{0}:{1}#{1}", self.did_method, encoded_pk)
    }

    fn encode(&self, sig: Ed25519Signature) -> String {
        multibase::encode(multibase::Base::Base58Btc, sig)
    }

    fn relational_sign(
        &self,
        msg: &[u8],
        relation: super::VerificationRelation,
    ) -> Result<Ed25519Signature, super::error::Error> {
        let private_key = self.get_private_key_by_relation(relation);

        let res: [u8; 64] = private_key.sign(msg).into();
        Ed25519Signature::from_bytes(&res)
    }
}

impl From<&Ed25519DidSigner> for Ed25519DidVerifier {
    fn from(signer: &Ed25519DidSigner) -> Self {
        Self {
            public_key: signer.public_key,
            did_method: signer.did_method.clone(),
        }
    }
}

impl From<Ed25519KeyPair> for Ed25519DidVerifier {
    fn from(kp: Ed25519KeyPair) -> Self {
        Self {
            public_key: kp.master_public_key,
            did_method: kp.did_method,
        }
    }
}

impl From<Ed25519KeyPair> for Ed25519DidSigner {
    fn from(kp: Ed25519KeyPair) -> Self {
        Self {
            public_key: kp.master_public_key,
            private_key: kp.master_private_key,
            did_method: kp.did_method,
        }
    }
}

impl super::DIDVerifier<Ed25519Signature> for Ed25519DidVerifier {
    fn verify(&self, msg: &[u8], sig: &Ed25519Signature) -> Result<(), super::error::Error> {
        let sig_bytes: [u8; 64] =
            sig.0
                .as_slice()
                .try_into()
                .map_err(|e: std::array::TryFromSliceError| {
                    super::error::Error::Signature(e.to_string())
                })?;

        self.public_key
            .verify(&ed25519_zebra::Signature::from(sig_bytes), msg)
            .map_err(|e| super::error::Error::Verify(e.to_string()))
    }

    fn decode(&self, encoded_sig: String) -> Result<Ed25519Signature, super::error::Error> {
        let sig = multibase::decode(encoded_sig)
            .map_err(|e| super::error::Error::Signature(e.to_string()))?;

        let sig_bytes: [u8; 64] =
            sig.1
                .as_slice()
                .try_into()
                .map_err(|e: std::array::TryFromSliceError| {
                    super::error::Error::Signature(e.to_string())
                })?;

        Ed25519Signature::from_bytes(&sig_bytes).map_err(super::error::Error::from)
    }

    fn decoded_relational_verify(
        &self,
        msg: &[u8],
        data: String,
        relation: super::VerificationRelation,
    ) -> Result<(), super::error::Error> {
        let decoded_sig = self.decode(data)?;
        self.relational_verify(msg, &decoded_sig, relation)
    }

    fn relational_verify(
        &self,
        msg: &[u8],
        sig: &Ed25519Signature,
        relation: super::VerificationRelation,
    ) -> Result<(), super::error::Error> {
        let sig_bytes: [u8; 64] =
            sig.0
                .as_slice()
                .try_into()
                .map_err(|e: std::array::TryFromSliceError| {
                    super::error::Error::Signature(e.to_string())
                })?;

        let sig = ed25519_zebra::Signature::from(sig_bytes);
        let public_key = self.get_public_key_by_relation(relation);

        public_key
            .verify(&sig, msg)
            .map_err(|e| super::error::Error::Verify(e.to_string()))
    }

    fn get_key_material_type(&self) -> String {
        ED25519_VERIFICATION_KEY_2020.to_string()
    }

    fn get_verification_method(&self, relation: super::VerificationRelation) -> String {
        let encoded_pk = self.get_encoded_public_key_by_relation(relation);
        format!("did:{0}:{1}#{1}", self.did_method, encoded_pk)
    }

    fn get_encoded_public_key_by_relation(&self, relation: super::VerificationRelation) -> String {
        super::PublicKey::get_encoded_public_key(self.get_public_key_by_relation(relation))
    }

    fn get_did_method(&self) -> String {
        self.did_method.clone()
    }

    fn get_did(&self) -> String {
        let encoded_pk = super::PublicKey::get_encoded_public_key(&self.public_key);
        format!("did:{0}:{1}", self.did_method, encoded_pk)
    }

    fn decoded_verify(&self, msg: &[u8], data: String) -> Result<(), super::error::Error> {
        let decoded_sig = self.decode(data)?;
        self.verify(msg, &decoded_sig)
    }
}

impl Ed25519DidVerifier {
    fn get_public_key_by_relation(
        &self,
        relation: super::VerificationRelation,
    ) -> &ed25519_zebra::VerificationKey {
        match relation {
            super::VerificationRelation::AssertionMethod => &self.public_key,
            super::VerificationRelation::Authentication => &self.public_key,
            super::VerificationRelation::CapabilityInvocation => &self.public_key,
            super::VerificationRelation::CapabilityDelegation => &self.public_key,
        }
    }
}

impl Ed25519DidSigner {
    fn get_private_key_by_relation(
        &self,
        relation: crate::suite::VerificationRelation,
    ) -> ed25519_zebra::SigningKey {
        match relation {
            crate::suite::VerificationRelation::AssertionMethod => self.private_key,
            crate::suite::VerificationRelation::Authentication => self.private_key,
            crate::suite::VerificationRelation::CapabilityInvocation => self.private_key,
            crate::suite::VerificationRelation::CapabilityDelegation => self.private_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::suite::KeyPair;

    #[test]
    fn test_create_keypair_from_multibase() {
        let public_key = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2".to_string();
        let private_key = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq".to_string();
        let did_method = "key".to_string();
        let kp = super::Ed25519KeyPair::from_private_key(did_method, private_key).unwrap();
        assert_eq!(kp.get_encoded_master_public_key(), public_key);
    }
}
