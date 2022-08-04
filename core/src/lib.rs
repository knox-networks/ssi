mod credential;

use credential::*;
use serde_json::{self, Value};
use signature::keypair::SSIKeyPair;
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
        cred_type: Vec<String>,
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
    /// In order to become a Verifiable Presentation, a data integrity proof must be created for the 
    /// presentation and appended to the JSON-LD document.
    fn create_presentation(
        &self,
        credentials: Vec<VerifiableCredential>,
    ) -> Result<Presentation, Box<dyn std::error::Error>> {
        Ok(Presentation::new(CONTEXT_CREDENTIALS, credentials))
    }
}

pub trait IdentityBuilder {
    fn create_identity(
        _mnemonic: &str,
        _password: Option<String>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {

        // GenerateMnemonic -> crypto manager -> mnemonic ? 
        // GenerateKeyPair -> crypto manager  - > key pair is generated 
        // CreateDidDocument  - > key pair
        // -> did doc has to be signed with a key pair
        // let id = Identity::new();
        let kp = SSIKeyPair::new();
        
        //////////////////// discussion ////////////////////////
        // keypair = create_keypair()
        // store_keypair(keypair)
        // create_vc(Ed25519DidSigner::from(keypair))

        //         That's roughly how I imagine it
        // 11:52
        // So the signer can source its keys from a keypair but it will not expose access to them to its consumers
        // 11:52
        // So you can share signing functionality (or verifying functionality) without increasing the exposure of 
        // the cryptographic keys themselves
        // 11:52
        // You are roughly right that the KeyPair doesn't really care about or know about the Signer
        // 11:53
        // its the Signer that cares about the KeyPair
        // 11:53
        // As that's its information source

        // My thinking is that different consumers will need to integrate at different layers and by separating the 
        // information source 
        // from the operational module (the signer and verifier) we can have a cleaner layer of abstraction and more flexibility

        // Theoretically we just need the Signer/Verifier to add support for new algorithms
        //The layers is so that lower level applications that need the crypto information can still use us

        //This won't change the core library, just the signature library

        //Well actually core will change but only the identity creation stuff 

    //         That as well and for current need
    // For instance in the custodial wallet, the DynamicKeypair has the same issue that ours does
    // 12:01
    // So I ended up having to hack around things in order to get it to work
    // 12:01
    // Because for the custodial wallet I want to be able to generate keypairs, store them, and then 
    // create signers/verifiers on demand from that keypair information

    //     Okay dope, lmk if you disagree or think there's a better way or something. This is just 
    // something that I felt was really missing while working on custodial wallet (edited) 
    // 12:04
    // And I think it'll come up for other people consuming SSI


    // and for didSigner we replace Ed25519Signature by crate::keypair::SSIKeyPair right? So the idea is to operate via 
    // SSIKeyPair to essentially be flexible and to be able to use other algorithms than Ed25519Signature


    // Luis Osta
    //   10:56 AM
    // Yes ideally
    // 10:56
    // Ideally the trait can be implemented by various signatures
    // white_check_mark
    // eyes
    // raised_hands
    

    // 10:57
    // I don't know if we should replace the signature by the SSIKeyPair or if its possible
    // 10:57
    // What do you think?
    
    
    // I'm wondering why do we need in this case SSIKeyPair struct. Maybe we need only the KeyPair trait ? It can be applied to Ed25519DidSigner


    // Luis Osta
    //   11:25 AM
    // So I have a question, how would you want key generation to work for the end user?
    
    
    // Sergey Kudryashov
    //   11:25 AM
    // basically signer will consume this generic trait
    
    
    // Luis Osta
    //   11:25 AM
    // We'd want our library to abstract the whole process right? (the signature)
    
    
    // Sergey Kudryashov
    //   11:26 AM
    // Yes
    
    
    // Luis Osta
    //   11:26 AM
    // From key generation, to creating signers, to all of the "higher" level SSI stuff
    // 11:26
    // I agree that we should definitely use traits
    // 11:26
    // But I think we should have a struct because we want to have some reasonable default that users can utilize to create keys
    // 11:26
    // In a manner in which they can control
    // 11:27
    // Without a struct, how would we achieve that?
    
    // Sergey Kudryashov
    //   11:27 AM
    // yes this is a good point in terms of key generation
    // 11:27
    // let me think
    // 11:28
    // currently Ed25519DidSigner generates key pair right?
    
 // Luis Osta
    // Yes
    // In a way inaccessible to the end user

//     The question is - who generates the keypair? In case of Ed25519DidSigner its constructor generates, in case of SSIKeyPair, again, 
// constructor does that. So applying the trait KeyPair doesn't change anything here, whether it is applied to Ed25519DidSigner or SSIKeyPair

// Okay so I think the Signers should not handle generation at all
// Instead we should implement a function called new for the KeyPair struct (not the trait ofc)
// And then the Signer can be created from the KeyPair similarly to how I create the verifier from the signer

/// ___________________________________________________________ ///
// And when we're applying from trait from std library, i assume that at this point KeyPair may get the 
// information about algorithms, based on algorithms keys have to be generated, is it like you see it?
// I think you are correct in this
// So we'd have to implement a from function for the Signer
// And yes that would have the cryptographic information ofc
// The signer could just store the KeyPair struct internally and use its functions to do the signing and verifying
// What do you think?
// Let me just have my lunch really quick and i think it through in the meantime
// Yeah sounds good no rush
        unimplemented!();
    }

    fn restore_identity(
        _mnemonic: String,
        _password: Option<String>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        unimplemented!();
    }
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

        let type_rs = json!(["VerifiableCredential", "PermanentResidentCard"]);
        kv_body.entry("type".to_string()).or_insert(type_rs);

        let expect = json!({
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

        kv_subject = HashMap::from([
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
          },});

        let (kv_body, kv_subject) = get_body_subject();

        let vc = to.create_credential(
            vec![crate::CRED_TYPE_PERMANENT_RESIDENT_CARD.to_string()],
            kv_subject,
            kv_body,
            "https://issuer.oidp.uscis.gov/credentials/83627465",
        );

        assert!(vc.is_ok());
        let credential = vc.unwrap();
        assert_json_eq!(expect_credential, credential.serialize());
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
        let signer = signature::signer::Ed25519DidSigner::new();
        let (kv_body, kv_subject) = get_body_subject();

        let vc = to.create_credential(
            vec![crate::CRED_TYPE_PERMANENT_RESIDENT_CARD.to_string()],
            kv_subject,
            kv_body,
            "https://issuer.oidp.uscis.gov/credentials/83627465",
        );

        assert!(vc.is_ok());
        let credential = vc.unwrap();
        let proof = create_data_integrity_proof(
            &signer,
            credential.serialize(),
            signature::suite::VerificationRelation::AssertionMethod,
        );

        assert!(proof.is_ok());

        let verifiable_credential = credential.create_verifiable_credentials(proof.unwrap());
        let credentials = vec![verifiable_credential];
        let interim_presentation = to
            .create_presentation(credentials)
            .expect("unable to create presentation from credentials");

        let interim_proof = &interim_presentation.verifiable_credential[0].proof;
        let interim_proof = serde_json::to_value(interim_proof).unwrap();
        expect_presentation["verifiableCredential"][0]["proof"] = interim_proof;

        let presentation_json = interim_presentation.serialize();

        assert_json_eq!(expect_presentation, presentation_json);
        Ok(())
    }
}
