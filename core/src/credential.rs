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
struct CredentialSubject {
    id: String,
    #[serde(flatten)]
    pub property_set: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifiableCredential {
    #[serde(flatten)]
    credential: Credential,
    proof: crate::proof::DataIntegrityProof,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Credential {
    #[serde(rename = "@context")]
    #[serde(with = "formatter_context")]
    context: Vec<String>,

    #[serde(rename = "@id")]
    id: String,

    #[serde(rename = "type")]
    cred_type: Vec<String>,

    #[serde(rename = "issuanceDate")]
    #[serde(with = "formatter_credential_date")]
    issuance_date: SystemTime,

    #[serde(rename = "credentialSubject")]
    subject: CredentialSubject,
    #[serde(flatten)]
    pub property_set: HashMap<String, Value>,
}

impl Credential {
    pub fn new(
        context: VerificationContext,
        cred_type: Vec<String>,
        cred_subject: HashMap<String, Value>,
        property_set: HashMap<String, Value>,
        id: &str,
    ) -> Credential {
        let vc = Credential {
            context: context.into_iter().map(|s| s.to_string()).collect(),
            id: id.to_string(),
            cred_type: cred_type,
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

    pub fn deserialize(contents: String) -> Result<Credential, serde_json::Error> {
        serde_json::from_str(&contents)
    }
}

#[cfg(test)]
mod tests {
    use crate::Credential;
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    #[test]
    fn test_create_credential_from_string() -> Result<(), String> {
        let expect = json!({
            "@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],"@id":"https://issuer.oidp.uscis.gov/credentials/83627465","type":["VerifiableCredential", "PermanentResidentCard"],"issuer": "did:example:28394728934792387",
            "identifier": "83627465",
            "name": "Permanent Resident Card",
            "description": "Government of Example Permanent Resident Card.",
            "issuanceDate": "2019-12-03T12:19:52Z",
            "expirationDate": "2029-12-03T12:19:52Z",
            "credentialSubject": {
            "id": "did:example:b34ca6cd37bbf23",
            "type": ["PermanentResident", "Person"],
            "givenName": "JOHN",
            "familyName": "SMITH",
            "gender": "Male",
            "image": "data:image/png;base64,iVBORw0KGgo...kJggg==",
            "residentSince": "2015-01-01",
            "lprCategory": "C09",
            "lprNumber": "999-999-999",
            "commuterClassification": "C1",
            "birthCountry": "Bahamas",
            "birthDate": "1958-07-17"
            },
        });

        let ds = Credential::deserialize(expect.to_string());
        if ds.is_ok() {
            let vc = ds.unwrap().serialize();
            assert_json_eq!(expect, vc);
        } else {
            assert!(false);
        }
        Ok(())
    }
}

mod formatter_context {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::string::String;

    pub fn serialize<S>(ctx: &Vec<String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ctx_vec = crate::CONTEXT_CREDENTIALS
            .into_iter()
            .map(|s| s.to_string());
        serializer.collect_seq(ctx_vec)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = Vec::<String>::deserialize(deserializer)?;
        let s = crate::CONTEXT_CREDENTIALS
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        Ok(s)
    }
}

mod formatter_credential_type {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(cr_type: &String, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(cr_type.split(","))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = Vec::<String>::deserialize(deserializer)?.join(",");
        Ok(s)
    }
}

mod formatter_credential_date {
    use chrono::{DateTime, Utc};
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::string::String;
    use std::time::SystemTime;

    const FORMAT: &'static str = "%Y-%m-%dT%H:%M:%SZ";

pub fn serialize<S>(date: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let utc = DateTime::<Utc>::from(*date).format(FORMAT);
        serializer.serialize_str(&format!("{utc}"))
    }

pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        String::deserialize(deserializer) // -> Result<String, _>
            .and_then(|s: String| DateTime::parse_from_rfc3339(&s).map_err(Error::custom))
            .map(SystemTime::from)
    }
}
