mod credential;

use serde_json::{self, Value};
use credential::*;
// use serde::{Deserialize, Serialize};
// use serde_json::Result;
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
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>>;
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
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
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
    use crate::DocumentBuilder;
    use std::collections::HashMap;
    use assert_json_diff::{assert_json_eq};
    use crate::serde_json::json;

    use serde_json::Value;
    struct TestObj {}

    impl TestObj {
        pub fn new() -> Self{
            TestObj {  }
        }
    }
    impl DocumentBuilder for TestObj {}

    #[test]
    fn test_create_credential() -> Result<(), String> {
        let to = TestObj::new();
        let mut kv_body: HashMap<String, Value> = HashMap::new();
        let mut kv_subject: HashMap<String, Value> = HashMap::new();

        let expect = json!({
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://w3id.org/citizenship/v1"
            ],
            "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
            "type": ["VerifiableCredential", "PermanentResidentCard"],
            "issuer": "did:example:28394728934792387",
            "identifier": "83627465",
            "name": "Permanent Resident Card",
            "description": "Government of Example Permanent Resident Card.",
            "issuanceDate": "2019-12-03T12:19:52Z",
            "expirationDate": "2029-12-03T12:19:52Z",
            "credentialSubject": {
              "id": "did:example:b34ca6cd37bbf23",
              "type": ["PermanentResident", "Person"],
              "givenName": "JOHN",
              "familyName": "SMITH",
              "gender": "Male",
              "image": "data:image/png;base64,iVBORw0KGgo...kJggg==",
              "residentSince": "2015-01-01",
              "lprCategory": "C09",
              "lprNumber": "999-999-999",
              "commuterClassification": "C1",
              "birthCountry": "Bahamas",
              "birthDate": "1958-07-17"
            },
        });

        kv_body.entry("type").insert_entry(Value::Array((["VerifiableCredential", "PermanentResidentCard"])));
        kv_body.entry("issuer").insert_entry(Value::String(("did:example:28394728934792387")));
        kv_body.entry("identifier").insert_entry(Value::String(("did:example:28394728934792387")));
        kv_body.entry("name").insert_entry(Value::String(("Permanent Resident Card")));
        kv_body.entry("description").insert_entry(Value::String(("Government of Example Permanent Resident Card.")));
        kv_body.entry("issuanceDate").insert_entry(Value::String(("2019-12-03T12:19:52Z")));
        kv_body.entry("expirationDate").insert_entry(Value::String(("2029-12-03T12:19:52Z")));
       
        kv_subject.entry("id").insert_entry(Value::String(("did:example:b34ca6cd37bbf23")));
        kv_subject.entry("type").insert_entry(Value::Array((["PermanentResident", "Person"])));
        kv_subject.entry("givenName").insert_entry(Value::String(("JOHN")));
        kv_subject.entry("familyName").insert_entry(Value::String(("SMITH")));
        kv_subject.entry("gender").insert_entry(Value::String(("Male")));
        kv_subject.entry("image").insert_entry(Value::String(("data:image/png;base64,iVBORw0KGgo...kJggg==")));
        kv_subject.entry("residentSince").insert_entry(Value::String(("2015-01-01")));
        kv_subject.entry("lprCategory").insert_entry(Value::String(("C09")));
        kv_subject.entry("lprNumber").insert_entry(Value::String(("999-999-999")));
        kv_subject.entry("commuterClassification").insert_entry(Value::String(("C1")));
        kv_subject.entry("birthCountry").insert_entry(Value::String(("Bahamas")));
        kv_subject.entry("birthDate").insert_entry(Value::String(("1958-07-17")));

        let vc = to.create_credential(
            DocumentBuilder::CRED_TYPE_PERMANENT_RESIDENT_CARD,
            kv_subject,
            kv_body,
            "https://issuer.oidp.uscis.gov/credentials/83627465",
        );
        assert_json_eq!(vc, expect);
        Ok(())
    } 
}