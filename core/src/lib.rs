mod credential;
pub mod error;
pub mod identity;
pub mod proof;

/// Verification of Data Integrity Proofs requires the resolution of the `verificationMethod` specified in the proof.
/// The `verificationMethod` refers to a cryptographic key stored in some external source.
/// The DIDResolver is responsible for resolving the `verificationMethod` to a key that can be used to verify the proof.

#[mockall::automock]
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
        format!(
            "did:{}:{public_key}#{key_id}",
            String::from(Self::get_method()),
        )
    }
}

pub trait DocumentBuilder {
    fn get_contexts() -> credential::VerificationContext {
        vec![
            credential::BASE_CREDENDIAL_CONTEXT.to_string(),
            credential::EXAMPLE_CREDENTIAL_CONTEXT.to_string(),
        ]
    }

    /// Given the credential type and the credential subject information, create a unissued JSON-LD credential.
    /// In order to become a Verifiable Credential, a data integrity proof must be created for the credential and appended to the JSON-LD document.
    /// this is the default implementation of the `create` method. The `create` method can be overridden to create a custom credential.
    fn create_credential(
        &self,
        cred_type: credential::CredentialType,
        cred_subject: std::collections::HashMap<String, serde_json::Value>,
        property_set: std::collections::HashMap<String, serde_json::Value>,
        id: &str,
    ) -> Result<credential::Credential, Box<dyn std::error::Error>> {
        let context = Self::get_contexts();

        Ok(credential::Credential {
            context,
            id: id.to_string(),
            cred_type: vec![credential::CredentialType::Common, cred_type],
            issuance_date: chrono::Utc::now().to_rfc3339(),
            subject: credential::CredentialSubject {
                id: id.to_string(),
                property_set: cred_subject,
            },
            property_set,
        })
    }

    /// Given the set of credentials, create a unsigned JSON-LD Presentation of those credentials.
    /// In order to become a Verifiable Presentation, a data integrity proof must be created for the
    /// presentation and appended to the JSON-LD document.
    fn create_presentation(
        &self,
        credentials: Vec<credential::VerifiableCredential>,
    ) -> Result<credential::Presentation, Box<dyn std::error::Error>> {
        let context = Self::get_contexts();
        Ok(credential::Presentation {
            context,
            verifiable_credential: credentials,
        })
    }
}

/// Given a JSON-LD document and a DIDResolver, verify the data integrity proof for the document.
/// This will by parsing the `verificationMethod` property of the data integrity proof and resolving it to a key that can be used to verify the proof.
/// Currently only `Ed25519Signature2018` is supported for data integrity proof verification.
pub fn verify_data_integrity_proof<S: signature::suite::Signature>(
    _doc: serde_json::Value,
    _resolver: &impl DIDResolver,
    _verifier: &impl signature::suite::DIDVerifier<S>,
) -> Result<bool, Box<dyn std::error::Error>> {
    unimplemented!();
}

/// Given a JSON-LD document and a DIDResolver, verify the data integrity proof for the Verifiable Presentation.
/// Then each claimed Verifiable Credential must be verified for validity and ownership of the credential by the subject.
pub fn verify_presentation<S: signature::suite::Signature>(
    _doc: serde_json::Value,
    _resolver: &impl DIDResolver,
    _verifier: &impl signature::suite::DIDVerifier<S>,
) -> Result<bool, Box<dyn std::error::Error>> {
    unimplemented!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_json_diff::assert_json_eq;
    use serde_json::json;
    use std::{collections::HashMap, vec};

    use serde_json::Value;
    struct TestObj {}

    impl TestObj {
        pub fn new() -> Self {
            Self {}
        }
    }

    impl DocumentBuilder for TestObj {}

    fn get_body_subject() -> (HashMap<String, Value>, HashMap<String, Value>) {
        let mut kv_body: HashMap<String, Value> = HashMap::new();

        let type_rs = json!(["VerifiableCredential", "PermanentResidentCard"]);
        kv_body.entry("type".to_string()).or_insert(type_rs);

        let _expect = json!({
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

        kv_body = HashMap::from([
            ("issuer", "did:example:28394728934792387"),
            ("identifier", "83627465"),
            ("name", "Permanent Resident Card"),
            (
                "description",
                "Government of Example Permanent Resident Card.",
            ),
            ("issuanceDate", "2019-12-03T12:19:52Z"),
            ("expirationDate", "2029-12-03T12:19:52Z"),
        ])
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();

        kv_body.insert(
            "type".to_string(),
            json!(["VerifiableCredential", "PermanentResidentCard"]),
        );

        let mut kv_subject: HashMap<String, serde_json::Value> = HashMap::from([
            ("id", "did:example:b34ca6cd37bbf23"),
            ("givenName", "JOHN"),
            ("familyName", "SMITH"),
            ("gender", "Male"),
            ("image", "data:image/png;base64,iVBORw0KGgo...kJggg=="),
            ("residentSince", "2015-01-01"),
            ("lprCategory", "C09"),
            ("lprNumber", "999-999-999"),
            ("commuterClassification", "C1"),
            ("birthCountry", "Bahamas"),
            ("birthDate", "1958-07-17"),
        ])
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();

        kv_subject.insert("type".to_string(), json!(["PermanentResident", "Person"]));

        (kv_body, kv_subject)
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
          },});

        let (kv_body, kv_subject) = get_body_subject();

        let vc = to.create_credential(
            credential::CredentialType::PermanentResidentCard,
            kv_subject,
            kv_body,
            "https://issuer.oidp.uscis.gov/credentials/83627465",
        );

        assert!(vc.is_ok());
        let credential = vc.unwrap();
        assert_json_eq!(expect_credential, serde_json::to_value(credential).unwrap());
        Ok(())
    }

    #[test]
    fn test_create_presentation() -> Result<(), String> {
        let to = TestObj::new();
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
        // here we test the presentation
        let signer: signature::suite::ed25519_2020::Ed25519DidSigner =
            signature::suite::ed25519_2020::Ed25519KeyPair::new(None)
                .unwrap()
                .into();

        let (kv_body, kv_subject) = get_body_subject();

        let vc = to.create_credential(
            credential::CredentialType::PermanentResidentCard,
            kv_subject,
            kv_body,
            "https://issuer.oidp.uscis.gov/credentials/83627465",
        );

        assert!(vc.is_ok());
        let credential = vc.unwrap();
        let proof = proof::create_data_integrity_proof(
            &signer,
            serde_json::to_value(credential.clone()).unwrap(),
            signature::suite::VerificationRelation::AssertionMethod,
        );

        assert!(proof.is_ok());

        let verifiable_credential = credential.into_verifiable_credential(proof.unwrap());
        let credentials = vec![verifiable_credential];
        let interim_presentation = to
            .create_presentation(credentials)
            .expect("unable to create presentation from credentials");

        let interim_proof = &interim_presentation.verifiable_credential[0].proof;
        let interim_proof = serde_json::to_value(interim_proof).unwrap();
        expect_presentation["verifiableCredential"][0]["proof"] = interim_proof;

        let presentation_json = serde_json::to_value(interim_presentation).unwrap();

        assert_json_eq!(expect_presentation, presentation_json);
        Ok(())
    }
}
