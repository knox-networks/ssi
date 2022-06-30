
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

type VerificationContext = [&'static str];

pub(crate) const JSON_LD_CONTEXT:  VerificationContext = ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"];

pub const CRED_TYPE_PERMANENT_RESIDENT_CARD: str = "PermanentResidentCard";
pub const CRED_TYPE_BANK_CARD: str = "BankCard";

#[derive(Serialize, Deserialize, Clone)]
struct CredentialSubject {
    #[serde(flatten)]
    pub property_set: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Credential <'a> {
    #[serde(flatten)]
    verifiable_credential:VerifiableCredential <'a>,
    #[serde(flatten)]
    proof: CredentialProof <'a>,
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

pub struct CredentialProof <'a> {
    proof_type: String,
    created: String,
    verification_method: String,
    proof_purpose: String,
    proof_value: String,
}

pub struct CredentialManager {
    context: VerificationContext,
}

trait VC {
    fn getContext(&self) -> VerificationContext {
        self.context.clone()
    }
    fn getCredentialTypes(&self) -> [String] {
        [CRED_TYPE_PERMANENT_RESIDENT_CARD, CRED_TYPE_BANK_CARD];
    }
}

/// Default VC trait implementation for CredentialManager.
/// Callers may reimplement this trait in their code by: impl VC for CredentialManager {/...code here.../}
impl VC for CredentialManager {}

impl CredentialManager {
    pub fn new() -> CredentialManager {
        CredentialManager {
            context: JSON_LD_CONTEXT.clone(),
        }
    }
    pub fn initVerifiableCredential (&self, 
        cred_type: String, 
        cred_subject: HashMap<String, Value>, 
        property_set: HashMap<String, Value>, 
        id: &str) 
    -> VerifiableCredential {    
        let vc = VerifiableCredential::new(&self, 
            self.getContext(), 
            cred_type, 
            cred_subject, 
            property_set,
            id);
    }  
}

impl VerifiableCredential <'_>  {
    pub fn new (&self,
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
                property_set: cred_subject,
            },
            property_set: property_set,
        };
    } 
    pub fn serialize(self) -> Value {
        return serde_json::to_string(&self);
    }
}
