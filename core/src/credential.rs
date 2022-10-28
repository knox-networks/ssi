// This module attempts to provide a relatively simple & high level way of interacting with Credentials, Verifiable Credentials, Presentations and Verifiable Presentations
// Adheres to the https://www.w3.org/TR/vc-data-model/ spec.

// cred_subject is a generic that implements trait X
// trait X allows us to encode that object into JSON-LD
// We provide types that implement trait X for the cred types that we support
// Users can also user their own types that implement trait X if they need a different structure
// ---
// Default context and Cred types are defaulted but can be redefined

pub type VerificationContext = Vec<String>;

pub const BASE_CREDENDIAL_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";
pub const EXAMPLE_CREDENTIAL_CONTEXT: &str = "https://www.w3.org/2018/credentials/examples/v1";

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum CredentialType {
    #[serde(rename = "VerifiableCredential")]
    Common,
    PermanentResidentCard,
    BankCard,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct CredentialSubject {
    pub id: String,
    #[serde(flatten)]
    pub property_set: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "type")]
    pub cred_type: Vec<CredentialType>,

    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,

    #[serde(rename = "credentialSubject")]
    pub subject: CredentialSubject,

    #[serde(flatten)]
    pub property_set: std::collections::HashMap<String, serde_json::Value>,

    pub proof: crate::proof::DataIntegrityProof,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct Credential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "type")]
    pub cred_type: Vec<CredentialType>,

    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,

    #[serde(rename = "credentialSubject")]
    pub subject: CredentialSubject,

    #[serde(flatten)]
    pub property_set: std::collections::HashMap<String, serde_json::Value>,
}

impl Credential {
    pub fn try_into_verifiable_credential<S: signature::suite::Signature>(
        self,
        issuer_signer: &impl signature::suite::DIDSigner<S>,
        relation: signature::suite::VerificationRelation,
    ) -> Result<VerifiableCredential, Box<dyn std::error::Error>> {
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
        integrity_proof: crate::proof::DataIntegrityProof,
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
    pub proof: crate::proof::DataIntegrityProof,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct Presentation {
    #[serde(rename = "@context")]
    pub context: VerificationContext,
    #[serde(rename = "verifiableCredential")]
    pub verifiable_credential: Vec<VerifiableCredential>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    #[test]
    fn test_create_credential_from_string() -> Result<(), String> {
        let expect = json!({
            "@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],
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
