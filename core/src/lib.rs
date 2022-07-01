mod credential;

use serde_json::{self, Value};
use credential::*;
// use serde::{Deserialize, Serialize};
use serde_json::Result;
use std::{collections::HashMap, error::Error};

/// Verification of Data Integrity Proofs requires the resolution of the `verificationMethod` specified in the proof.
/// The `verificationMethod` refers to a cryptographic key stored in some external source.
/// The DIDResolver is responsible for resolving the `verificationMethod` to a key that can be used to verify the proof.
#[async_trait::async_trait]
pub trait DIDResolver {
    /// Given a `did`, resolve the full DID document associated with that matching `did`.
    /// Return the JSON-LD document representing the DID.
    async fn read(&self, did: String) -> serde_json::Value;
    /// Given a `did` and the associated DID Document, register the DID Document with the external source used by the DIDResolver.
    async fn create(
        &self,
        did: String,
        doc: serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

pub trait DocumentBuilder {
    /// Given the credential type and the credential subject information, create a unissued JSON-LD credential.
    /// In order to become a Verifiable Credential, a data integrity proof must be created for the credential and appended to the JSON-LD document.
    /// this is the default implementation of the `create` method. The `create` method can be overridden to create a custom credential.
    fn create_credential(
        &self,
        cred_type: String, 
        cred_subject: HashMap<String, Value>,
        property_set: HashMap<String, Value>,
        id: &str
    ) -> Result<VerifiableCredential, Box<dyn std::error::Error>> {
        let vc = VerifiableCredential::new(CONTEXT_CREDENTIALS,
            cred_type,
            cred_subject,
            property_set,
            id
        );
        Ok(vc);
    }

    /// Given the set of credentials, create a unsigned JSON-LD Presentation of those credentials.
    /// In order to become a Verifiable Presentation, a data integrity proof must be created for the presentation and appended to the JSON-LD document.
    fn create_presentation(
        _creds: Vec<serde_json::Value>,
    ) -> Result<VerifiableCredential, Box<dyn std::error::Error>> {
        unimplemented!();
    }
}


// // ed25519 cryptography key generation & DID Document creation
// pub fn create_identity(
//     _mnemonic: &str,
//     _password: Option<String>,
// ) -> Result<(), Error> {
//     unimplemented!();
// }

// /// Given a JSON-LD document, c
// /// reate a data integrity proof for the document.
// /// Currently, only `Ed25519Signature2018` data integrity proofs in the JSON-LD format can be created.
// pub fn create_data_integrity_proof<S: signature::Signature>(
//     _doc: serde_json::Value,
//     _signer: &impl signature::Signer<S>,
// ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
//     unimplemented!();
// }

// /// Given a JSON-LD document and a DIDResolver, verify the data integrity proof for the document.
// /// This will by parsing the `verificationMethod` property of the data integrity proof and resolving it to a key that can be used to verify the proof.
// /// Currently only `Ed25519Signature2018` is supported for data integrity proof verification.
// pub fn verify_data_integrity_proof<S: signature::Signature>(
//     _doc: serde_json::Value,
//     _resolver: &impl DIDResolver,
//     _verifier: &impl signature::Verifier<S>,
// ) -> Result<bool, Box<dyn std::error::Error>> {
//     unimplemented!();
// }

// /// Given a JSON-LD document and a DIDResolver, verify the data integrity proof for the Verifiable Presentation.
// /// Then each claimed Verifiable Credential must be verified for validity and ownership of the credential by the subject.
// pub fn verify_presentation<S: signature::Signature>(
//     _doc: serde_json::Value,
//     _resolver: &impl DIDResolver,
//     _verifier: &impl signature::Verifier<S>,
// ) -> Result<bool, Box<dyn std::error::Error>> {
//     unimplemented!();
// }

#[cfg(test)]
mod tests {
    use core::DocumentBuilder;
    use std::collections::HashMap;

    use serde_json::Value;
    struct TestObj {}

    impl TestObj {
        pub fn new() -> Self{
            TestObj {  }
        }
    }
    impl DocumentBuilder::create_credential for TestObj {}

    #[test]
    fn test_create_credential() -> Result<(), String> {
        let to = TestObj::new();
        let mut kv_body: HashMap<String, Value> = HashMap::new();
        let mut kv_subject: HashMap<String, Value> = HashMap::new();

        to.create_credential(

        );
        assert!(false);
        Ok(())
    } 
}