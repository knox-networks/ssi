#![allow(unused_variables)]
#![allow(dead_code)]
use std::time::SystemTime;

use crate::HashMap;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::Error;

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
#[serde(bound(deserialize = "'de: 'static"))]
pub struct VerifiableCredential {
    #[serde(flatten)]
    credential: Credential,
    proof: crate::proof::DataIntegrityProof,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
// #[serde(bound(deserialize = "'de: 'static"))]
pub struct Credential {
    #[serde(rename = "@context")]
    // #[serde(with = "context_formatter")]
    context: Vec<String>,
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "type")]
    // #[serde(with = "credential_type_formatter")]
    cred_type: String,
    #[serde(rename = "issuanceDate")]
    #[serde(with = "credential_date_formatter")]
    issuance_date: SystemTime,
    #[serde(rename = "credentialSubject")]
    subject: CredentialSubject,
    #[serde(flatten)]
    pub property_set: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CredentialRequest {

    #[serde(rename = "@context")]
    #[serde(with = "context_formatter")]
    context: Vec<String>,

    #[serde(rename = "@id")]
    id: String,
    // #[serde(rename = "type")]
    // cred_type: Vec<String>,

    #[serde(rename = "type")]
    #[serde(with = "credential_type_formatter")]
    cred_type: String,

    #[serde(rename = "issuanceDate")]
    #[serde(with = "credential_date_formatter")]
    issuance_date: SystemTime,
    // issuance_date: String,

    #[serde(rename = "credentialSubject")]
    subject: CredentialSubject,
    
    #[serde(flatten)]
    pub property_set: HashMap<String, Value>,
}


mod credential_type_formatter {
    use serde::{self, Deserialize, Serializer, Deserializer};

    pub fn serialize<S>(
        cr_type: &String,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // serializer.serialize_str(cr_type.split(",").collect::<Vec<&str>>().join(" "))
        serializer.serialize_str("default_string")
        // serde_json::to_string(cred_type).unwrap()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        // let s = crate::CONTEXT_CREDENTIALS.into_iter().map(|s| s.to_string()).collect();
        // let s = String::deserialize(deserializer)?;
        // println!("{}", s);
        let s = Vec::<String>::deserialize(deserializer)?.join(",");
        // println!("{}", s);
        Ok(s)
    }
}

mod context_formatter {
    use std::time::SystemTime;
    use crate::Credential;
    use serde::{self, Deserialize, Serializer, Deserializer};
    use std::string::String;
    use super::*;

    pub fn serialize<S>(
        ctx: &Vec<String>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // let str_str = crate::CONTEXT_CREDENTIALS.into_iter().map(|s| s.to_string()).collect().join(",");
        // serializer.serialize_str(str_str)
        serializer.serialize_str("default_string")
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Vec<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = Vec::<String>::deserialize(deserializer)?;
        let s = crate::CONTEXT_CREDENTIALS.into_iter().map(|s| s.to_string()).collect();
        // deserializer.deserialize_seq(s);

        Ok(s)
    }
}

mod credential_date_formatter {
    use chrono::{DateTime, Utc, TimeZone};
    use serde::{self, Deserialize, Serializer, Deserializer};
    use std::time::SystemTime;
    use std::string::String;

    const FORMAT: &'static str = "%Y-%m-%dT%H:%M:%SZ";

    pub fn serialize<S>(
        // date: &DateTime<Utc>,
        date: &SystemTime,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let formatted = DateTime::<Utc>::from(*date).format(FORMAT);
        let s = formatted.to_string();
        let s = format!("{}", &s);
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let idate = DateTime::parse_from_rfc3339(&s);
        if idate.is_ok() {
            let sys_time = SystemTime::from(idate.unwrap());
            return Ok(sys_time.clone());
        } else {
            println!("error: {}", idate.unwrap_err());
            return Err(serde::de::Error::custom("Invalid date"))
        }
    }
}

impl Credential {
    pub fn new(
        context: VerificationContext,
        cred_type: String,
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
    
    pub fn deserialize (contents: String) -> Result<Credential, String> {
        // let dd  = serde_json::from_str(&contents);
        // if dd.is_err() {
        //     let error = dd.unwrap_err();
        //     println!("error: {}", error.to_string());
        //     return Err("error just".to_string());
        // } else {
        //     let deserialized: Credential = dd.unwrap();
        //     return Ok(deserialized);
        // }
        // return cred;
        
        let deserialized: CredentialRequest  = serde_json::from_str(&contents).unwrap();
        // let idate = DateTime::parse_from_rfc3339(deserialized.issuance_date.as_str()).unwrap();
        let cred = Credential{
            context: CONTEXT_CREDENTIALS.into_iter().map(|s| s.to_string()).collect(),
            id: deserialized.id,
            cred_type: serde_json::to_string(&deserialized.cred_type).unwrap(),
            // issuance_date: SystemTime::from(idate),
            issuance_date: deserialized.issuance_date,
            subject: deserialized.subject,
            property_set: deserialized.property_set,
        };
        
        return Ok(cred);
    }
}


#[cfg(test)]
mod tests {
    use serde_json::json;
    use crate::Credential;
    use assert_json_diff::assert_json_eq;

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
        if ds.is_ok(){
            let vc = ds.unwrap().serialize();
            assert_json_eq!(expect, vc);
        }
        
        // println!("cred type {}", ds.id);
        // println!("cred type {}", ds.context[0]);
        Ok(())
    }
}
