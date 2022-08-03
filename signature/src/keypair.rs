use std::any::type_name;

// use ed25519_zebra::VerificationKey;

fn type_of<T>(_: T) -> &'static str {
    type_name::<T>()
}

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
pub struct SSIKeyPair <T: Copy +AsRef<[u8]>> {
    pub(crate) private_key: ed25519_zebra::SigningKey,
    // pub(crate) private_key: T,
    pub(crate) public_key: ed25519_zebra::VerificationKey,
    // pub(crate) public_key: T,
}

impl<T: Copy> SSIKeyPair<T>{
    pub fn new(signing: T) -> Self {
        match type_of(signing) {
            "signer::Ed25519DidSigner" => {
                let sk = ed25519_zebra::SigningKey::new(rand::thread_rng());
                return Self {
                    private_key: &sk,
                    public_key: ed25519_zebra::VerificationKey::from(&sk),
                };
            }
        }
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
