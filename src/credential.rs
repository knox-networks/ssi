
#![allow(unused_variables)]
#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use serde_json::Value;

type VCContext = [String];

pub(crate) const JSON_LD_CONTEXT:  VCContext = ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"];
pub(crate) const CRED_TYPE_PASSPORT: str = "Passport";
pub(crate) const CRED_TYPE_DRIVER_LICENSE: str = "DriverLicense";

type CredentialSubject = serde_json::Value;

enum CredType {
    Passport(String),
    DriverLicense(String)
}

pub trait VCCredential {
    fn getCredType (&self) -> String;
    fn getSubject (&self) -> String;
    fn getContext (&self) -> [String];
}

impl VCCredential for VerifiableCredential<'_> {
    fn getCredType (&self) -> String {
        self.cred_type = ""
    }
    fn getSubject (&self) -> String {
        self.cred_type = ""
    }
    fn getContext (&self) ->[String] {
        return crate::credential::JSON_LD_CONTEXT
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifiableCredential <'a> {
    #[serde(rename = "@context")]
	context:  VCContext,
	id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cred_type:  Option<CredType>,
	issuer: String,
	issuance_date: String,
	subject: CredentialSubject,
	proof: *mut CredentialProof,
}

impl <'a> VerifiableCredential <'a>  {
    pub fn init(cred_type: String, cred_subject: serde_json::Value, issuer: &'a str, id: &'a str) -> Self  {
        let ctype = match cred_type {
            CRED_TYPE_PASSPORT => {
                Some(CredType::Passport(cred_type))
            },
            CRED_TYPE_DRIVER_LICENSE => {
                Some(CredType::DriverLicense(cred_type))
            },
            _ => {
                None
            }
        };
        let s = Self {
            context: JSON_LD_CONTEXT,
            id: String::from(id), 
            cred_type: ctype,
            issuer: String::from(issuer), 
            issuance_date: String::default(),
            subject: cred_subject,
            /// created empty object on VerifiableCredential init step, will be filled on "create_data_integrity_proof" step
            proof: &mut CredentialProof { 
                proof_type:String::default(),
                created:String::default(),
                verification_method:String::default(),
                proof_purpose:String::default(),
                proof_value:String::default(),
            },
        };
        s.cred_type = s.getCredType();
        s.context = s.getContext();
        s.subject = s.getSubject();
        
        return s;
    }

    pub fn serialize(self) -> serde_json::Value {
        return serde_json::to_string(&self);
    }
}


pub struct CredentialProof {
	proof_type: String,
	created: String,
	verification_method: String,
	proof_purpose: String,
	proof_value: String,
}
