
#![allow(unused_variables)]
#![allow(dead_code)]

type JsonContext = [&'static str; 2];
const JSON_LD_CONTEXT:  JsonContext = ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"];

type CredentialSubject = serde_json::Value;


pub struct VerifiableCredential <'a> {
	context:  JsonContext,
	id: String,
    cred_type:  &'a [String],
	issuer: String,
	issuance_date: String,
	subject: CredentialSubject,
	proof: *mut CredentialProof,
}

impl <'a> VerifiableCredential <'a>  {
    pub fn init(cred_type: &'a[String], cred_subject: serde_json::Value, issuer: &'a str, id: &'a str) -> Self  {
        Self {
            context: JSON_LD_CONTEXT,
            id: String::from(id), 
            cred_type: cred_type,
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
