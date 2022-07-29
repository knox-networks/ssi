pub trait KeyPair: core::fmt::Debug + Sized {
    fn get_public_key_encoded(&mut self) -> String
    where
        Self: Sized;
    fn get_private_key_encoded(&mut self) -> String
    where
        Self: Sized;
    fn get_public_key(&self) -> ed25519_zebra::VerificationKey
    where
        Self: Sized;
    fn get_private_key(&self) -> ed25519_zebra::SigningKey
    where
        Self: Sized;
}

#[derive(Debug)]
pub struct SSIKeyPair {
    pub(crate) private_key: ed25519_zebra::SigningKey,
    pub(crate) public_key: ed25519_zebra::VerificationKey,
}

impl SSIKeyPair {
    fn new() -> Self {
        let sk = ed25519_zebra::SigningKey::new(rand::thread_rng());
        let vk = ed25519_zebra::VerificationKey::from(&sk);
        return Self {
            public_key: vk,
            private_key: sk,
        };
    }
}

impl KeyPair for SSIKeyPair {
    fn get_public_key_encoded(&mut self) -> String {
        multibase::encode(multibase::Base::Base58Btc, self.public_key)
    }
    fn get_private_key_encoded(&mut self) -> String {
        multibase::encode(multibase::Base::Base58Btc, self.private_key)
    }
    fn get_public_key(&self) -> ed25519_zebra::VerificationKey {
        return self.public_key.clone();
    }
    fn get_private_key(&self) -> ed25519_zebra::SigningKey {
        return self.private_key.clone();
    }
}
