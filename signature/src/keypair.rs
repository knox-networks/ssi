pub trait KeyPair: core::fmt::Debug + Sized {
    fn get_public_key_enc(&self) -> String;
    fn get_private_key_enc(&self) -> String;
    fn get_public_key(&self) -> ed25519_zebra::VerificationKey;
    fn get_private_key(&self) -> ed25519_zebra::SigningKey;
}

#[derive(Debug)]
pub struct SSIKeyPair {
    pub(crate) public_key_encoded : String,
    private_key_encoded: String,
    // signature_type: String, 
    private_key: ed25519_zebra::SigningKey,
    pub(crate) public_key: ed25519_zebra::VerificationKey,
}

impl SSIKeyPair {
    fn new() -> Self {
        let sk = ed25519_zebra::SigningKey::new(rand::thread_rng());
        let vk = ed25519_zebra::VerificationKey::from(&sk);
        let encoded_pk = multibase::encode(multibase::Base::Base58Btc, vk);
        let encoded_sk = multibase::encode(multibase::Base::Base58Btc, sk);

        return Self {
            public_key_encoded: encoded_pk,
            private_key_encoded: encoded_sk,
            public_key: vk,
            private_key: sk,
        };
    }
}

impl KeyPair for SSIKeyPair {
    fn get_public_key_enc(&self) -> String {
        return self.public_key_encoded.clone();
    }
    fn get_private_key_enc(&self) -> String {
        return self.private_key_encoded.clone();
    }
    fn get_public_key(&self) -> ed25519_zebra::VerificationKey {
        return self.public_key.clone();
    }
    fn get_private_key(&self) -> ed25519_zebra::SigningKey {
        return self.private_key.clone();
    }
}
