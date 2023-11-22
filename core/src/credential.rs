// This module attempts to provide a relatively simple & high level way of interacting with Credentials, Verifiable Credentials, Presentations and Verifiable Presentations
// Adheres to the https://www.w3.org/TR/vc-data-model/ spec.

// cred_subject is a generic that implements trait X
// trait X allows us to encode that object into JSON-LD
// We provide types that implement trait X for the cred types that we support
// Users can also user their own types that implement trait X if they need a different structure
// ---
// Default context and Cred types are defaulted but can be redefined

use serde_valid::json::FromJsonStr;
use serde_valid::Validate;
use std::str::FromStr;

pub type VerificationContext = Vec<String>;

pub const BASE_CREDENDIAL_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";
pub const BANK_ACCOUNT_CREDENTIAL_CONTEXT: &str = "https://w3id.org/traceability/v1";

mod validation;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum CredentialType {
    #[serde(rename = "VerifiableCredential")]
    Common,
    PermanentResidentCard,
    BankCard,
    BankAccount,
    UniversityDegreeCredential,
    AlumniCredential,
}

impl CredentialType {
    pub fn as_str(&self) -> &str {
        match self {
            CredentialType::Common => "VerifiableCredential",
            CredentialType::PermanentResidentCard => "PermanentResidentCard",
            CredentialType::BankCard => "BankCard",
            CredentialType::BankAccount => "BankAccount",
            CredentialType::UniversityDegreeCredential => "UniversityDegreeCredential",
            CredentialType::AlumniCredential => "AlumniCredential",
        }
    }

    pub fn from_string(cred_type: &str) -> Option<Self> {
        match cred_type {
            "BankCard" => Some(CredentialType::BankCard),
            "BankAccount" => Some(CredentialType::BankAccount),
            "PermanentResidentCard" => Some(CredentialType::PermanentResidentCard),
            "VerifiableCredential" => Some(CredentialType::Common),
            "UniversityDegreeCredential" => Some(CredentialType::UniversityDegreeCredential),
            "AlumniCredential" => Some(CredentialType::AlumniCredential),
            _ => None,
        }
    }
}

pub type CredentialSubject = std::collections::HashMap<String, serde_json::Value>;

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, Validate)]
pub struct VerifiableCredential {
    #[serde(flatten)]
    #[validate]
    pub credential: Credential,
    pub proof: crate::proof::CredentialProof,
}

impl std::fmt::Display for VerifiableCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vc = serde_json::to_string(&self).expect("Failed to serialize VerifiableCredential");
        write!(f, "{}", vc)
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, Validate)]
pub struct Credential {
    #[validate(custom(validation::credential_context_validation))]
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "type")]
    pub cred_type: Vec<CredentialType>,

    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,

    pub issuer: String,

    #[serde(rename = "credentialSubject")]
    pub subject: CredentialSubject,

    #[serde(flatten)]
    pub property_set: std::collections::HashMap<String, serde_json::Value>,
}

impl FromStr for VerifiableCredential {
    type Err = super::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vc = VerifiableCredential::from_json_str(s)?;
        Ok(vc)
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

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct VerifiablePresentation {
    #[serde(flatten)]
    pub presentation: Presentation,
    pub proof: crate::proof::CredentialProof,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct Presentation {
    #[serde(rename = "@context")]
    pub context: VerificationContext,
    #[serde(rename = "verifiableCredential")]
    pub verifiable_credential: Vec<VerifiableCredential>,
}

impl FromStr for VerifiablePresentation {
    type Err = super::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vc = serde_json::from_str::<VerifiablePresentation>(s)?;
        Ok(vc)
    }
}

impl std::fmt::Display for VerifiablePresentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vp = serde_json::to_string(&self).expect("Failed to serialize VerifiablePresentation");
        write!(f, "{}", vp)
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

        let res = serde_json::from_str::<VerifiableCredential>(&expect.to_string());
        assert!(res.is_ok());
        if let Ok(vc) = res {
            let vc = serde_json::to_value(vc).unwrap();
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

        let res = serde_json::from_str::<Credential>(&expect.to_string());
        assert!(res.is_ok());
        if let Ok(vc) = res {
            let vc = serde_json::to_value(vc).unwrap();
            assert_json_eq!(expect, vc);
        }

        Ok(())
    }
}
