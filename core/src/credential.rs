
#![allow(unused_variables)]
#![allow(dead_code)]

type CredentialSubject = serde_json::Value;
type CredentialTypes = [VerifiableCredential];


// #[derive(Deserialize, Debug)]
pub struct VerifiableCredential {
	context: String,
	id: String,
    cred_type: String,
	issuer: String,
	issuance_date: String,
	subject: CredentialSubject,
	proof: *mut CredentialProof,
}

impl <'a> VerifiableCredential {
    pub fn init(cred_type: &'a str, cred_subject: serde_json::Value) -> Self  {
        Self {
            /// context is a slice, it is  defined by us based on parsed cred type and cred subject
            context: String::default(), 
            /// provided  by client
            id: String::default(), 
            cred_type: String::from(cred_type),
            /// provided  by client 
            issuer: String::default(), 
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
        }
    }

    pub fn serialize(self) -> serde_json::Value {
        return self.subject
    }
}


pub struct CredentialProof {
	proof_type: String,
	created: String,
	verification_method: String,
	proof_purpose: String,
	proof_value: String,
}

pub struct VerifiablePresentation {
    nonce: String,
    endpoint: String, 
    credential_types: CredentialTypes,
}