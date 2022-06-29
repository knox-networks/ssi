
#![allow(unused_variables)]
#![allow(dead_code)]
use std::{error::Error, time::{Instant, SystemTime}};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::HashMap;
use std::io::ErrorKind;

// cred_subject is a generic that implements trait X
// trait X allows us to encode that object into JSON-LD
// We provide types that implement trait X for the cred types that we support
// Users can also user their own types that implement trait X if they need a different structure
// --- 
// Default context and Cred types are defaulted but can be redefined 

type VCContext = [&'static str];

pub(crate) const JSON_LD_CONTEXT:  VCContext = ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"];

pub const CRED_TYPE_PERMANENT_RESIDENT_CARD: str = "PermanentResidentCard";
pub const CRED_TYPE_BANK_CARD: str = "BankCard";

type CredentialSubject = serde_json::Value;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifiableCredential <'a> {
    #[serde(rename = "@context")]
	context:  VCContext,
    #[serde(rename = "@id")]
	id: String,
    cred_type:  String,
	issuer: String,
	issuance_date: SystemTime,
	subject: CredentialSubject,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IssuedCredential <'a> {
    #[serde(flatten)]
    verifiable_credential:VerifiableCredential <'a>,
    #[serde(flatten)]
    proof: CredentialProof <'a>,
}

pub struct CredentialManager {
    credential_subject: HashMap<String, String>,
    context: VCContext,
}

trait VC {
    fn getSubject(&self, key: &str) -> Result<String, Box<dyn std::error::Error>> {
        match self.credential_subject.get(key) {
            Some(&value) => Ok(value.to_string()),
            None => Err(Error::new(ErrorKind::Other, "Key not found")),
        } 
    }
    fn getContext(&self) -> VCContext {
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
    /// returns CredentialManager cred_subject_template with default configuration accessible for overlapping via VC trait
    pub fn new() -> CredentialManager {
        let cred_subject_template: HashMap<&str, &str> = HashMap::from([
                (CRED_TYPE_PERMANENT_RESIDENT_CARD, r###"{
                    "@id": "https://w3id.org/citizenship#PermanentResidentCard",
                    "@context": {
                      "@version": 1.1,
                      "@protected": true,
                      "id": "@id",
                      "type": "[
                        "PermanentResidentCard"
                     ]",
                      "description": "http://schema.org/description",
                      "name": "http://schema.org/name",
                      "identifier": "http://schema.org/identifier",
                      "image": {"@id": "http://schema.org/image", "@type": "@id"}
                    }
                  }"###),
                (CRED_TYPE_BANK_CARD, r###"{
                    "account":"",
                    "address":"",
                    "birthDate":"",
                    "branch":"",
                    "country":"",
                    "familyName":"",
                    "gender":"",
                    "givenName":"",
                    "id":"",
                    "phone":"",
                    "type":[
                       "BankCard"
                    ]
                 }"###),
            ]);
        return Self { 
            credential_subject: cred_subject_template,
            context: JSON_LD_CONTEXT,
         }
    }

    pub fn initVerifiableCredential (&self, cred_type: String, cred_subject: serde_json::Value, issuer: &str, id: &str) 
    -> Result<VerifiableCredential, Box<dyn std::error::Error>> {
        match self.getSubject(&cred_type) {
            Ok(value) => {
                let vc = VerifiableCredential {
                    context: self.getContext(),
                    id: id.to_string(),
                    cred_type: cred_type.to_string(),
                    issuer: issuer.to_string(),
                    issuance_date: SystemTime::now(),
                    subject: value,
                };
                return Ok(vc);
            },
            Err(e) => return Err(e),
        }
    }  
}

impl VerifiableCredential <'_>  {
    pub fn serialize(self) -> serde_json::Value {
        return serde_json::to_string(&self);
    }
}

pub struct CredentialProof <'a> {
	proof_type: String,
	created: String,
	verification_method: String,
	proof_purpose: String,
	proof_value: String,
}
