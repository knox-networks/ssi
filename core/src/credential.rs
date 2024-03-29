// This module attempts to provide a relatively simple & high level way of interacting with Credentials, Verifiable Credentials, Presentations and Verifiable Presentations
// Adheres to the https://www.w3.org/TR/vc-data-model/ spec.

// cred_subject is a generic that implements trait X
// trait X allows us to encode that object into JSON-LD
// We provide types that implement trait X for the cred types that we support
// Users can also user their own types that implement trait X if they need a different structure
// ---
// Default context and Cred types are defaulted but can be redefined
mod validation;

use serde_valid::json::{FromJsonStr, ToJsonString};
use serde_valid::Validate;
use std::str::FromStr;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum ContextValue {
    String(String),
    Object(std::collections::HashMap<String, serde_json::Value>),
}

pub type DocumentContext = Vec<ContextValue>;

cfg_if::cfg_if! {
    if #[cfg(feature = "v2_test")] {
        pub const BASE_CREDENTIAL_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
        pub const EXAMPLE_CREDENTIAL_CONTEXT: &str = "https://www.w3.org/ns/credentials/examples/v2";

    } else {
        pub const BASE_CREDENTIAL_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";
        pub const EXAMPLE_CREDENTIAL_CONTEXT: &str = "https://www.w3.org/2018/credentials/examples/v1";
    }
}

pub const BANK_ACCOUNT_CREDENTIAL_CONTEXT: &str = "https://w3id.org/traceability/v1";

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum CredentialType {
    VerifiableCredential, // credential type common to all credentials
    PermanentResidentCard,
    BankCard,
    BankAccount,
    UniversityDegreeCredential,
    AlumniCredential,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum PresentationType {
    VerifiablePresentation, // presentation type common to all presentations
    CredentialManagerPresentation,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
#[serde(untagged)]
pub enum CredentialSubject {
    Single(std::collections::HashMap<String, serde_json::Value>),
    Set(Vec<std::collections::HashMap<String, serde_json::Value>>),
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, Validate)]
pub struct Credential {
    #[validate(custom(validation::credential_context_validation))]
    #[serde(rename = "@context")]
    pub context: DocumentContext,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "type")]
    pub cred_type: Vec<CredentialType>,

    #[serde(rename = "issuanceDate")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuance_date: Option<chrono::DateTime<chrono::Utc>>, //chrono by default serializes to RFC3339

    #[serde(rename = "expirationDate")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<chrono::DateTime<chrono::Utc>>, //chrono by default serializes to RFC3339

    pub issuer: String,

    #[serde(rename = "credentialSubject")]
    pub subject: CredentialSubject,

    #[serde(flatten)]
    pub property_set: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, Validate)]
pub struct VerifiableCredential {
    #[serde(flatten)]
    #[validate]
    pub credential: Credential,
    pub proof: crate::proof::CredentialProof,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, Validate)]
pub struct Presentation {
    #[serde(rename = "@context")]
    pub context: DocumentContext,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "type")]
    pub presentation_type: Vec<PresentationType>,

    #[serde(rename = "verifiableCredential")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate]
    pub verifiable_credential: Option<Vec<VerifiableCredential>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, Validate)]
pub struct VerifiablePresentation {
    #[serde(flatten)]
    #[validate]
    pub presentation: Presentation,

    pub proof: crate::proof::CredentialProof,
}

impl FromStr for CredentialType {
    type Err = super::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "VerifiableCredential" => Ok(CredentialType::VerifiableCredential),
            "PermanentResidentCard" => Ok(CredentialType::PermanentResidentCard),
            "BankCard" => Ok(CredentialType::BankCard),
            "BankAccount" => Ok(CredentialType::BankAccount),
            "UniversityDegreeCredential" => Ok(CredentialType::UniversityDegreeCredential),
            "AlumniCredential" => Ok(CredentialType::AlumniCredential),
            _ => Err(super::error::Error::Unknown(
                "Unknown CredentialType".to_string(),
            )),
        }
    }
}

impl CredentialType {
    pub fn as_str(&self) -> &str {
        match self {
            CredentialType::VerifiableCredential => "VerifiableCredential",
            CredentialType::PermanentResidentCard => "PermanentResidentCard",
            CredentialType::BankCard => "BankCard",
            CredentialType::BankAccount => "BankAccount",
            CredentialType::UniversityDegreeCredential => "UniversityDegreeCredential",
            CredentialType::AlumniCredential => "AlumniCredential",
        }
    }
}

impl std::fmt::Display for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.to_json_string() {
            Ok(vc) => write!(f, "{}", vc),
            Err(e) => write!(f, "Error: {}", e),
        }
    }
}

impl std::fmt::Display for VerifiableCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.to_json_string() {
            Ok(vc) => write!(f, "{}", vc),
            Err(e) => write!(f, "Error: {}", e),
        }
    }
}

impl FromStr for Credential {
    type Err = super::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Credential::from_json_str(s)?)
    }
}

impl FromStr for VerifiableCredential {
    type Err = super::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(VerifiableCredential::from_json_str(s)?)
    }
}

impl Credential {
    pub fn try_into_verifiable_credential<S: signature::suite::Signature>(
        self,
        issuer_signer: &impl signature::suite::DIDSigner<S>,
        relation: signature::suite::VerificationRelation,
    ) -> Result<VerifiableCredential, super::error::Error> {
        let serialized_credential = serde_json::to_value(&self)?;
        let proof = crate::proof::create_data_integrity_proof(
            issuer_signer,
            serialized_credential,
            relation,
        )?;

        Ok(VerifiableCredential {
            credential: self,
            proof,
        })
    }

    #[cfg(feature = "v2_test")]
    pub fn try_into_verifiable_credential_for_test<S: signature::suite::Signature>(
        self,
        issuer_signer: &impl signature::suite::DIDSigner<S>,
        proof_time: String,
        verification_method: String,
    ) -> Result<VerifiableCredential, super::error::Error> {
        let proof_time = chrono::DateTime::parse_from_rfc3339(&proof_time).unwrap();
        let serialized_credential = serde_json::to_value(&self)?;
        let proof = crate::proof::create_data_integrity_proof_for_test(
            issuer_signer,
            serialized_credential,
            proof_time.into(),
            verification_method,
        )?;

        Ok(VerifiableCredential {
            credential: self,
            proof,
        })
    }

    pub fn into_verifiable_credential(
        self,
        integrity_proof: crate::proof::CredentialProof,
    ) -> VerifiableCredential {
        VerifiableCredential {
            credential: self,
            proof: integrity_proof,
        }
    }
}

impl Presentation {
    pub fn try_into_verifiable_presentation<S: signature::suite::Signature>(
        self,
        issuer_signer: &impl signature::suite::DIDSigner<S>,
        relation: signature::suite::VerificationRelation,
    ) -> Result<VerifiablePresentation, super::error::Error> {
        let serialized_presentation = serde_json::to_value(&self)?;
        let proof = crate::proof::create_data_integrity_proof(
            issuer_signer,
            serialized_presentation,
            relation,
        )?;

        Ok(VerifiablePresentation {
            presentation: self,
            proof,
        })
    }
}

impl FromStr for Presentation {
    type Err = super::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Presentation::from_json_str(s)?)
    }
}

impl FromStr for VerifiablePresentation {
    type Err = super::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(VerifiablePresentation::from_json_str(s)?)
    }
}

impl std::fmt::Display for VerifiablePresentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.to_json_string() {
            Ok(vp) => write!(f, "{}", vp),
            Err(e) => write!(f, "Error: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    #[test]
    fn test_create_verifiable_credential_from_string() -> Result<(), String> {
        let expect = json!({
                "@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],
                "id":"http://credential_mock:8000/api/credential/z6MkoBjc4GfEWrdAXAchrDrjc7LBuTVNXySswadG3apCKy9P",
                "type":["VerifiableCredential","PermanentResidentCard"],
                "issuanceDate":"2022-10-28T19:35:20Z",
                "issuer":"did:knox:z6Mkv9L4S8FQ3qcu8UqG8NFHt5LKcfzPeLvPJB7uW5vrp3WF",
                "credentialSubject":{"birthCountry":"Bahamas","birthDate":"1981-04-01","commuterClassification":"C1","familyName":"Kim","gender":"Male",
                "givenName":"Francis","id":"did:knox:z6MkoBjc4GfEWrdAXAchrDrjc7LBuTVNXySswadG3apCKy9P",
                "image":"data:image/png;base64,iVBORw0KGgo...kJggg==","lprCategory":"C09","lprNumber":"000-000-204","residentSince":"2015-01-01",
                "type":["PermanentResident","Person"]},
                "proof":{
                    "type":"Ed25519Signature2020","created":"2022-10-28T19:35:20Z",
                    "verificationMethod":"did:knox:z6Mkv9L4S8FQ3qcu8UqG8NFHt5LKcfzPeLvPJB7uW5vrp3WF#z6Mkv9L4S8FQ3qcu8UqG8NFHt5LKcfzPeLvPJB7uW5vrp3WF",
                    "proofPurpose":"assertionMethod",
                    "proofValue":"z4xTXcWHhZY8oXCXTKSw3N9qmRKjQAUUVbNnQz1FqKCAYiGieYohBRcSKGK9YcBuKqyqzjbaohmtMZBAenC9huBJ"
            }
        });

        let res = VerifiableCredential::from_str(&expect.to_string());
        assert!(res.is_ok());
        if let Ok(vc) = res {
            let vc = serde_json::to_value(vc).unwrap();
            println!("{}", vc);
            assert_json_eq!(expect, vc);
        }
        Ok(())
    }

    #[test]
    fn test_create_credential_from_string() -> Result<(), String> {
        let expect = json!({
            "@context":["https://www.w3.org/2018/credentials/v1"],
            "id":"https://issuer.oidp.uscis.gov/credentials/83627465",
            "type":["VerifiableCredential", "PermanentResidentCard"],
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

        let res = Credential::from_str(&expect.to_string());
        assert!(res.is_ok());
        if let Ok(vc) = res {
            let vc = serde_json::to_value(vc).unwrap();
            assert_json_eq!(expect, vc);
        }

        Ok(())
    }
}
