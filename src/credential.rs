

// #[derive(Deserialize, Debug)]
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
    pub fn init(credType: &'a str, credSubject: serde_json::Value) -> Self  {
        Self {
            context: String::default(), // array defined by us 
            id: String::default(), // provided  by client 
            credType: String::from(credType),
            issuer: String::default(), // provided  by client 
            issuanceDate: String::default(),
            subject: credSubject, //
            proof: &mut CredentialProof{ // we don't have it 
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

type CredentialSubject = serde_json::Value;

