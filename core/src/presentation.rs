
// #![allow(unused_variables)]
// #![allow(dead_code)]
// use std::{time::{SystemTime}};

// use serde::{Deserialize, Serialize};
// use serde_json::Value;


// #[derive(Debug, Serialize, Deserialize, Clone)]
// #[serde(bound(deserialize = "'de: 'static"))]
// pub struct VerifiablePresentation {
//     #[serde(flatten)]
//     presentation: Presentation,
//     proof: IntegrityProof,
// }

// #[derive(Debug, Serialize, Deserialize, Clone)]
// #[serde(bound(deserialize = "'de: 'static"))]
// pub struct Presentation {
//     #[serde(rename = "@context")]
//     context: VerificationContext,
//     #[serde(rename = "@id")]
//     id: String,
//     #[serde(rename = "verifiableCredential")]
//     verifiable_credential: Vec<VerifiableCredential>,
// }

// impl Presentation {
//     pub fn new() -> Presentation {
//         Presentation{}
//     }
// }