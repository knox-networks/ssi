
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

type VerificationContext = [&'static str;2];

pub const CONTEXT_CREDENTIALS:  VerificationContext = ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"];
pub const CRED_TYPE_PERMANENT_RESIDENT_CARD: &'static str = "PermanentResidentCard";
pub const CRED_TYPE_BANK_CARD: &'static str = "BankCard";

#[derive(Serialize, Deserialize, Clone)]
struct CredentialSubject {
    id : String,
    #[serde(flatten)]
    pub property_set: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Credential <'a> {
    #[serde(flatten)]
    verifiable_credential:VerifiableCredential <'a>,
    proof: IntegrityProof <'a>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifiableCredential <'a> {
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

pub struct IntegrityProof <'a> {
    proof_type: String,
    created: String,
    verification_method: String,
    proof_purpose: String,
    proof_value: String,
}

impl <'a> VerifiableCredential <'a>  {
    pub fn new (
        context: VerificationContext,
        cred_type: String, 
        cred_subject: HashMap<String, Value>, 
        property_set: HashMap<String, Value>, id: &str) 
    -> VerifiableCredential {    
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
    }

    pub fn serialize(self) -> Value {
        return serde_json::to_string(&self);
    }
}
