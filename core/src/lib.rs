mod credential;

use credential::*;
use serde_json::{self, Value};
use std::collections::HashMap;

pub mod error;
pub mod proof;

/// Verification of Data Integrity Proofs requires the resolution of the `verificationMethod` specified in the proof.
/// The `verificationMethod` refers to a cryptographic key stored in some external source.
/// The DIDResolver is responsible for resolving the `verificationMethod` to a key that can be used to verify the proof.
#[async_trait::async_trait]
pub trait DIDResolver {
    /// Given a `did`, resolve the full DID document associated with that matching `did`.
    /// Return the JSON-LD document representing the DID.
    async fn read(self, did: String) -> Result<serde_json::Value, error::ResolverError>;
    /// Given a `did` and the associated DID Document, register the DID Document with the external source used by the DIDResolver.
    async fn create(self, did: String, doc: serde_json::Value) -> Result<(), error::ResolverError>;
    // Returns the DID Method that the DID Resolver is compatible with. Each resolver can only be compatible with one.
    fn get_method() -> &'static str;
    // Given a `did` and `key` it will construct the proper `verificationMethod` to use as part of the data integrity proof creation process.
    fn create_verification_method(public_key: String, key_id: String) -> String {
        return format!(
            "did:{}:{public_key}#{key_id}",
            String::from(Self::get_method()),
        );
    }
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
        id: &str,
    ) -> Result<Credential, Box<dyn std::error::Error>> {
        let vc = Credential::new(
            CONTEXT_CREDENTIALS,
            cred_type,
            cred_subject,
            property_set,
            id,
        );
        Ok(vc)
    }

    /// Given the set of credentials, create a unsigned JSON-LD Presentation of those credentials.
    /// In order to become a Verifiable Presentation, a data integrity proof must be created for the presentation and appended to the JSON-LD document.
    fn create_presentation(
        &self,
        credentials: Vec<VerifiableCredential>,
    ) -> Result<Presentation, Box<dyn std::error::Error>> {
        let pre = Presentation::new(CONTEXT_CREDENTIALS, credentials);
        Ok(pre)
    }
}

// Commented due to failing cargo check
// ed25519 cryptography key generation & DID Document creation
pub fn create_identity(
    _mnemonic: &str,
    _password: Option<String>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    unimplemented!();
}

/// Given a JSON-LD document and a DIDResolver, verify the data integrity proof for the document.
/// This will by parsing the `verificationMethod` property of the data integrity proof and resolving it to a key that can be used to verify the proof.
/// Currently only `Ed25519Signature2018` is supported for data integrity proof verification.
pub fn verify_data_integrity_proof<S: signature::suite::Signature>(
    _doc: serde_json::Value,
    _resolver: &impl DIDResolver,
    _verifier: &impl signature::verifier::DIDVerifier<S>,
) -> Result<bool, Box<dyn std::error::Error>> {
    unimplemented!();
}

/// Given a JSON-LD document and a DIDResolver, verify the data integrity proof for the Verifiable Presentation.
/// Then each claimed Verifiable Credential must be verified for validity and ownership of the credential by the subject.
pub fn verify_presentation<S: signature::suite::Signature>(
    _doc: serde_json::Value,
    _resolver: &impl DIDResolver,
    _verifier: &impl signature::verifier::DIDVerifier<S>,
) -> Result<bool, Box<dyn std::error::Error>> {
    unimplemented!();
}

#[cfg(test)]
mod tests {
    use crate::proof::create_data_integrity_proof;
    use crate::serde_json::json;
    use crate::DocumentBuilder;
    use assert_json_diff::assert_json_eq;
    use std::{collections::HashMap, vec};

    use serde_json::Value;
    struct TestObj {}

    impl TestObj {
        pub fn new() -> Self {
            TestObj {}
        }
    }
    impl DocumentBuilder for TestObj {}

    fn get_body_subject() -> (HashMap<String, Value>, HashMap<String, Value>) {
        let mut kv_body: HashMap<String, Value> = HashMap::new();
        let mut kv_subject: HashMap<String, Value> = HashMap::new();

        let type_rs = serde_json::to_value([
            "VerifiableCredential".to_string(),
            "PermanentResidentCard".to_string(),
        ]);
        if type_rs.is_ok() {
            kv_body
                .entry("type".to_string())
                .or_insert(type_rs.unwrap());
        }
        kv_body
            .entry("issuer".to_string())
            .or_insert(Value::String("did:example:28394728934792387".to_string()));
        kv_body
            .entry("identifier".to_string())
            .or_insert(Value::String("83627465".to_string()));
        kv_body
            .entry("name".to_string())
            .or_insert(Value::String("Permanent Resident Card".to_string()));
        kv_body
            .entry("description".to_string())
            .or_insert(Value::String(
                "Government of Example Permanent Resident Card.".to_string(),
            ));
        kv_body
            .entry("issuanceDate".to_string())
            .or_insert(Value::String("2019-12-03T12:19:52Z".to_string()));
        kv_body
            .entry("expirationDate".to_string())
            .or_insert(Value::String("2029-12-03T12:19:52Z".to_string()));

        kv_subject
            .entry("id".to_string())
            .or_insert(Value::String("did:example:b34ca6cd37bbf23".to_string()));

        let type_rs = serde_json::to_value(["PermanentResident".to_string(), "Person".to_string()]);
        if type_rs.is_ok() {
            kv_subject
                .entry("type".to_string())
                .or_insert(type_rs.unwrap());
        }

        kv_subject
            .entry("givenName".to_string())
            .or_insert(Value::String("JOHN".to_string()));
        kv_subject
            .entry("familyName".to_string())
            .or_insert(Value::String("SMITH".to_string()));
        kv_subject
            .entry("gender".to_string())
            .or_insert(Value::String("Male".to_string()));
        kv_subject
            .entry("image".to_string())
            .or_insert(Value::String(
                "data:image/png;base64,iVBORw0KGgo...kJggg==".to_string(),
            ));
        kv_subject
            .entry("residentSince".to_string())
            .or_insert(Value::String("2015-01-01".to_string()));
        kv_subject
            .entry("lprCategory".to_string())
            .or_insert(Value::String("C09".to_string()));
        kv_subject
            .entry("lprNumber".to_string())
            .or_insert(Value::String("999-999-999".to_string()));
        kv_subject
            .entry("commuterClassification".to_string())
            .or_insert(Value::String("C1".to_string()));
        kv_subject
            .entry("birthCountry".to_string())
            .or_insert(Value::String("Bahamas".to_string()));
        kv_subject
            .entry("birthDate".to_string())
            .or_insert(Value::String("1958-07-17".to_string()));

        return (kv_body, kv_subject);
    }

    #[test]
    fn test_create_credential() -> Result<(), String> {
        let to = TestObj::new();
        let expect_credential = json!({
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "@id": "https://issuer.oidp.uscis.gov/credentials/83627465",
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

        let mut expect_presentation = json!({
            "@context" : ["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],
            "verifiableCredential":[{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],"@id":"https://issuer.oidp.uscis.gov/credentials/83627465","credentialSubject":{"birthCountry":"Bahamas","birthDate":"1958-07-17","commuterClassification":"C1",
                "familyName":"SMITH",
                "gender":"Male",
                "givenName":"JOHN",
                "id":"did:example:b34ca6cd37bbf23",
                "image":"data:image/png;base64,iVBORw0KGgo...kJggg==",
                "lprCategory":"C09",
                "lprNumber":"999-999-999",
                "residentSince":"2015-01-01",
                "type":["PermanentResident","Person"]},
                "description":"Government of Example Permanent Resident Card.",
                "expirationDate":"2029-12-03T12:19:52Z","identifier":"83627465",
                "issuanceDate":"2019-12-03T12:19:52Z",
                "issuer":"did:example:28394728934792387",
                "name":"Permanent Resident Card",
                "proof":{"created":"2022-07-16T05:29:53.207757+00:00",
                "proof_purpose":"assertionMethod",
                "proof_type":"Ed25519Signature2018",
                "proof_value":"z5MWmCHvVpgXSiBN5SKbCNErLN2ncGR2mUMVrUJQaAd41t4CVjk57zBqnwZyH6eCc7HypD9BqbHnWrT4MikoW11Kf",
                "verification_method":"did:knox:zHRY3o2SDaGrVjLABw3CdderfhiSfVfX1husev7KdSwdU#zHRY3o2SDaGrVjLABw3CdderfhiSfVfX1husev7KdSwdU"},
                "type":["VerifiableCredential","PermanentResidentCard"]}]});

        let (kv_body, kv_subject) = get_body_subject();

        let vc = to.create_credential(
            crate::CRED_TYPE_PERMANENT_RESIDENT_CARD.to_string(),
            kv_subject,
            kv_body,
            "https://issuer.oidp.uscis.gov/credentials/83627465",
        );

        assert!(vc.is_ok());
        let credential = vc.unwrap();
        assert_json_eq!(expect_credential, credential.serialize());

        let signer = signature::signer::Ed25519DidSigner::new();
        let proof = create_data_integrity_proof(
            &signer,
            credential.serialize(),
            signature::suite::VerificationRelation::AssertionMethod,
        );

        assert!(proof.is_ok());

        let verifiable_credential = credential.create_verifiable_credentials(proof.unwrap());
        let credentials = vec![verifiable_credential];
        let pre = to.create_presentation(credentials);

        assert!(pre.is_ok());

        let interim_presentation = pre.unwrap();

        assert!(
            interim_presentation.verifiable_credential[0]
                .proof
                .verification_method
                .len()
                >= 90
        );
        assert!(
            interim_presentation.verifiable_credential[0]
                .proof
                .proof_value
                .len()
                >= 89
        );

        expect_presentation["verifiableCredential"][0]["proof"]["verification_method"] =
            serde_json::Value::String(
                interim_presentation.verifiable_credential[0]
                    .proof
                    .verification_method
                    .clone(),
            );
        expect_presentation["verifiableCredential"][0]["proof"]["proof_value"] =
            serde_json::Value::String(
                interim_presentation.verifiable_credential[0]
                    .proof
                    .proof_value
                    .clone(),
            );
        expect_presentation["verifiableCredential"][0]["proof"]["created"] =
            serde_json::Value::String(
                interim_presentation.verifiable_credential[0]
                    .proof
                    .created
                    .clone(),
            );

        let presentation_json = interim_presentation.serialize();

        assert_json_eq!(expect_presentation, presentation_json);

        Ok(())
    }
}
