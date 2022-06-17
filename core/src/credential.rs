
#[derive(Deserialize, Debug)]
pub struct VerifiableCredential {
	context: String,
	id: String,
    credType: String,
	issuer: String,
	issuanceDate: String,
	subject: CredentialSubject,
	proof: *mut CredentialProof,
}

impl <'a> VerifiableCredential {
    pub fn init(credType: &str, credSubject: serde_json::Value) -> Self  {
        Self {
            context: String::default(),
            id: String::default(),
            credType: String::from(credType),
            issuer: String::default(),
            issuanceDate: String::default(),
            subject: credSubject,
            proof: &mut CredentialProof{
                proofType:String::default(),
                created:String::default(),
                verificationMethod:String::default(),
                proofPurpose:String::default(),
                proofValue:String::default(),
            },
        }
    }
}


pub struct CredentialProof {
	proofType: String,
	created: String,
	verificationMethod: String,
	proofPurpose: String,
	proofValue: String,
}

pub enum CredentialSubject {
    String,
    Value, 
    Object(serde_json::Map<String, serde_json::Value>),
}
