#![allow(unused_variables)]
#![allow(dead_code)]
use std::time::SystemTime;

use crate::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// cred_subject is a generic that implements trait X
// trait X allows us to encode that object into JSON-LD
// We provide types that implement trait X for the cred types that we support
// Users can also user their own types that implement trait X if they need a different structure
// ---
// Default context and Cred types are defaulted but can be redefined

type VerificationContext = [&'static str; 2];

pub const CONTEXT_CREDENTIALS: VerificationContext = [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
];

pub const CRED_TYPE_PERMANENT_RESIDENT_CARD: &'static str = "PermanentResidentCard";
pub const CRED_TYPE_BANK_CARD: &'static str = "BankCard";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CredentialSubject {
    id: String,
    #[serde(flatten)]
    pub property_set: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct VerifiableCredential {
    #[serde(flatten)]
    credential: Credential,
    pub proof: crate::proof::DataIntegrityProof,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct Credential {
    #[serde(rename = "@context")]
    context: VerificationContext,
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "type")]
    cred_type: String,
    #[serde(rename = "issuanceDate")]
    issuance_date: SystemTime,
    #[serde(rename = "credentialSubject")]
    subject: CredentialSubject,
    #[serde(flatten)]
    pub property_set: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IntegrityProof {
    #[serde(rename = "type")]
    proof_type: String,
    #[serde(rename = "issuanceDate")]
    issuance_date: SystemTime,
    #[serde(rename = "verificationMethod")]
    verification_method: String,
    #[serde(rename = "verificationPurpose")]
    proof_purpose: String,
    #[serde(rename = "verificationValue")]
    proof_value: String,
}

impl Credential {
    pub fn new(
        context: VerificationContext,
        cred_type: String,
        cred_subject: HashMap<String, Value>,
        property_set: HashMap<String, Value>,
        id: &str,
    ) -> Credential {
        let vc = Credential {
            context: context,
            id: id.to_string(),
            cred_type: cred_type.to_string(),
            issuance_date: SystemTime::now(),
            subject: CredentialSubject {
                id: id.to_string(),
                property_set: cred_subject,
            },
            property_set: property_set,
        };
        vc
    }

    pub fn serialize(&self) -> Value {
        return serde_json::to_value(&self).unwrap();
    }

    pub fn create_verifiable_credentials(
        &self,
        integrity_proof: crate::proof::DataIntegrityProof,
    ) -> VerifiableCredential {
        let vc = VerifiableCredential {
            credential: self.to_owned(),
            proof: integrity_proof,
        };
        return vc;
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct VerifiablePresentation {
    #[serde(flatten)]
    presentation: Presentation,
    proof: IntegrityProof,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct Presentation {
    #[serde(rename = "@context")]
    pub context: VerificationContext,
    #[serde(rename = "verifiableCredential")]
    pub verifiable_credential: Vec<VerifiableCredential>,
}

impl Presentation {
    pub fn new(context: VerificationContext, vc: Vec<VerifiableCredential>) -> Presentation {
        Presentation {
            context: context,
            verifiable_credential: vc,
        }
    }

    pub fn serialize(&self) -> Value {
        return serde_json::to_value(&self).unwrap();
    }
}
