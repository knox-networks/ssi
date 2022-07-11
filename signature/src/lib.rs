#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]

pub enum VerificationRelation {
    AssertionMethod,
    Authentication,
    CapabilityInvocation,
    CapabilityDelegation,
}
pub use signature::Signature;

pub trait DIDSigner<S>: signature::Signer<S>
where
    S: signature::Signature,
{
    fn get_proof_type(&self) -> String;
    fn get_verification_method(&self, relation: VerificationRelation) -> String;
    fn encoded_sign(&self, data: &[u8]) -> String {
        let signature = self.sign(data);
        return self.encode(signature);
    }
    fn try_encoded_sign(&self, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        let signature = self.try_sign(data)?;
        return Ok(self.encode(signature));
    }
    fn encode(&self, sig: S) -> String;
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

pub trait DIDVerifier<S>: signature::Verifier<S>
where
    S: signature::Signature,
{
    fn decoded_verify(&self, msg: &[u8], data: String) -> Result<(), signature::Error> {
        let decoded_sig = self.decode(data)?;
        return self.verify(msg, &decoded_sig);
    }

    fn decoded_relational_verify(
        &self,
        msg: &[u8],
        data: String,
        relation: VerificationRelation,
    ) -> Result<(), signature::Error>;

    fn relational_verify(
        &self,
        msg: &[u8],
        signature: &S,
        relation: VerificationRelation,
    ) -> Result<(), signature::Error>;

    fn decode(&self, encoded_sig: String) -> Result<S, signature::Error>;
}

/// A generalized signature that can use a variety of possible backends.
#[derive(Debug, PartialEq, Clone)]
pub struct Ed25519Signature(Vec<u8>);

pub struct Ed25519DidSigner {
    private_key: ed25519_zebra::SigningKey,
    public_key: ed25519_zebra::VerificationKey,
}

pub struct Ed25519DidVerifier {
    public_key: ed25519_zebra::VerificationKey,
}

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl signature::Signature for Ed25519Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        Ok(Ed25519Signature(bytes.to_vec()))
    }
}

impl From<&Ed25519DidSigner> for Ed25519DidVerifier {
    fn from(signer: &Ed25519DidSigner) -> Self {
        Self {
            public_key: signer.public_key,
        }
    }
}

impl signature::Verifier<Ed25519Signature> for Ed25519DidVerifier {
    fn verify(&self, msg: &[u8], sig: &Ed25519Signature) -> Result<(), signature::Error> {
        let sig_bytes: [u8; 64] = sig.0.as_slice().try_into().unwrap();
        self.public_key
            .verify(&ed25519_zebra::Signature::from(sig_bytes), msg)
            .map_err(|_| signature::Error::new())
    }
}

impl DIDVerifier<Ed25519Signature> for Ed25519DidVerifier {
    fn decode(&self, encoded_sig: String) -> Result<Ed25519Signature, signature::Error> {
        let res = multibase::decode(encoded_sig);

        match res {
            Ok(sig) => {
                let sig_bytes: [u8; 64] = sig.1.as_slice().try_into().unwrap();
                Ok(Ed25519Signature(sig_bytes.to_vec()))
            }
            _ => Err(signature::Error::new()),
        }
    }

    fn decoded_relational_verify(
        &self,
        msg: &[u8],
        data: String,
        relation: VerificationRelation,
    ) -> Result<(), signature::Error> {
        let decoded_sig = self.decode(data)?;
        return self.relational_verify(msg, &decoded_sig, relation);
    }

    fn relational_verify(
        &self,
        msg: &[u8],
        sig: &Ed25519Signature,
        relation: VerificationRelation,
    ) -> Result<(), signature::Error> {
        let sig_bytes: [u8; 64] = sig
            .0
            .as_slice()
            .try_into()
            .map_err(|_| signature::Error::new())?;
        let sig = ed25519_zebra::Signature::from(sig_bytes);
        match relation {
            VerificationRelation::AssertionMethod => self
                .public_key
                .verify(&sig, msg)
                .map_err(|_| signature::Error::new()),
            VerificationRelation::Authentication => self
                .public_key
                .verify(&sig, msg)
                .map_err(|_| signature::Error::new()),
            VerificationRelation::CapabilityInvocation => self
                .public_key
                .verify(&sig, msg)
                .map_err(|_| signature::Error::new()),
            VerificationRelation::CapabilityDelegation => self
                .public_key
                .verify(&sig, msg)
                .map_err(|_| signature::Error::new()),
        }
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

impl signature::Signer<Ed25519Signature> for Ed25519DidSigner {
    fn try_sign(&self, data: &[u8]) -> Result<Ed25519Signature, signature::Error> {
        let res: [u8; 64] = self.private_key.sign(data).into();
        return Ok(Ed25519Signature(res.to_vec()));
    }
}

impl DIDSigner<Ed25519Signature> for Ed25519DidSigner {
    fn get_proof_type(&self) -> String {
        return "Ed25519Signature2018".to_string();
    }
    fn get_verification_method(&self, _relation: VerificationRelation) -> String {
        let encoded_pk = multibase::encode(multibase::Base::Base58Btc, self.public_key);
        return format!("did:knox:{}#keys-1", encoded_pk);
    }

    fn encode(&self, sig: Ed25519Signature) -> String {
        multibase::encode(multibase::Base::Base58Btc, sig)
    }
}
