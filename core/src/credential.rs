
#![allow(unused_variables)]
#![allow(dead_code)]
use std::{time::{SystemTime}};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::HashMap;

// cred_subject is a generic that implements trait X
// trait X allows us to encode that object into JSON-LD
// We provide types that implement trait X for the cred types that we support
// Users can also user their own types that implement trait X if they need a different structure
// --- 
// Default context and Cred types are defaulted but can be redefined 

// type VerificationContext = Vec<String>;

// pub const CONTEXT_CREDENTIALS:  [&static str; 2] = ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"];

pub const CONTEXT_CREDENTIALS: [&'static str; 2] = ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"];

#[derive(Debug, Serialize, Clone)]
pub struct VerificationContext([&'static str; 2]);

impl VerificationContext {
    fn to_vec(&self) -> Vec<String> {
        self.0.into_iter().map(|ctx| ctx.to_string()).collect()
    }
}


pub const CRED_TYPE_PERMANENT_RESIDENT_CARD: &'static str = "PermanentResidentCard";
pub const CRED_TYPE_BANK_CARD: &'static str = "BankCard";

#[derive(Serialize, Deserialize, Clone, Debug)]
struct CredentialSubject {
    id : String,
    #[serde(flatten)]
    pub property_set: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Credential {
    #[serde(flatten)]
    verifiable_credential:VerifiableCredential,
    proof: IntegrityProof,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    context:  VerificationContext,
    #[serde(rename = "@id")]
    id: String,
    cred_type: String,
    issuance_date: SystemTime,
    subject: CredentialSubject,
    #[serde(flatten)]
    pub property_set: HashMap<String, Value>,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IntegrityProof {
    proof_type: String,
    created: String,
    verification_method: String,
    proof_purpose: String,
    proof_value: String,
}

impl VerifiableCredential {
    pub fn new (
        context: VerificationContext,
        cred_type: String, 
        cred_subject: HashMap<String, Value>, 
        property_set: HashMap<String, Value>, id: &str) 
    -> VerifiableCredential {    
        let context = CONTEXT_CREDENTIALS.map(|x| x.to_string()).collect();
        let vc = VerifiableCredential {
            context: context,
            id: id.to_string(),
            cred_type: cred_type.to_string(),
            issuance_date: SystemTime::now(),
            subject: CredentialSubject{
                id: id.to_string(),
                property_set: cred_subject,
            },
            property_set: property_set,
        };
        vc
    }

    const fn get_context(&self) -> VerificationContext {
        CONTEXT_CREDENTIALS
    }

    pub fn serialize(&self) -> Value {
        let mut serialized = serde_json::to_value(self).unwrap();
        let context = self.get_context().to_vec();
        serialized["@context"] = Value::Array(context);
        serialized
    }
}
