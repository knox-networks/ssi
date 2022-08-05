#![allow(unused_variables)]
#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use signature::keypair::SSIKeyMaterial;
use registry_resolver::RegistryResolver;
use signature::signer::DIDSigner;
use signature::keypair::Ed25519SSIKeyPair;
// extern crate registry-resolver as registry_resolver;

pub struct Identity {
    resolver: RegistryResolver,
}

impl Identity {
    pub fn new(resolver: RegistryResolver) -> Identity {
        Identity{
            resolver:resolver,
        }
    }

    // here Ed25519DidSigner has to be replaced by SSIKeyPair
    pub fn generate(&mut self, key_pair: Ed25519SSIKeyPair) -> DidDocument {
        // let signer = signature::s::new();
        let signed_doc = self.create_did_document(key_pair);
        self.resolver.create(signed_doc);
        return signed_doc;
    }

    pub fn create_did_document(self, key_pair: signature::keypair::Ed25519SSIKeyPair, signer: signature::signer::Ed25519DidSigner) -> DidDocument {
        let did_doc = DidDocument {
        context: vec!("default".to_string()),
        id: "default".to_string(),
        authentication: vec![
                SSIKeyMaterial{
                    master_public_key:key_pair.get_master_public_key_encoded(),
                    id: key_pair.get_verification_method(signature::suite::VerificationRelation::Authentication),
                    proof_type: signer.get_proof_type(),
                    controller: key_pair.get_controller(signature::suite::VerificationRelation::Authentication),
                    public_key_multibase: signature::suite::VerificationRelation::Authentication,
                },
            ],
        capability_invocation: vec![
                SSIKeyMaterial{
                    master_public_key:key_pair.get_master_public_key_encoded(),
                    id: key_pair.get_verification_method(signature::suite::VerificationRelation::CapabilityInvocation),
                    proof_type: signer.get_proof_type(),
                    controller: key_pair.get_controller(signature::suite::VerificationRelation::CapabilityInvocation),
                    public_key_multibase: signature::suite::VerificationRelation::CapabilityInvocation,
                },
            ],
        capability_delegation: vec![
            SSIKeyMaterial{
                    master_public_key:key_pair.get_master_public_key_encoded(),
                    id: key_pair.get_verification_method(signature::suite::VerificationRelation::CapabilityDelegation),
                    proof_type: signer.get_proof_type(),
                    controller: key_pair.get_controller(signature::suite::VerificationRelation::CapabilityDelegation),
                    public_key_multibase:  signature::suite::VerificationRelation::CapabilityDelegation,
                },
            ],
        assertion_method: vec![
            SSIKeyMaterial{
                master_public_key:key_pair.get_master_public_key_encoded(),
                id: key_pair.get_verification_method(signature::suite::VerificationRelation::AssertionMethod),
                proof_type: signer.get_proof_type(),
                controller: key_pair.get_controller(signature::suite::VerificationRelation::AssertionMethod),
                public_key_multibase: signature::suite::VerificationRelation::AssertionMethod,
            },]
        };
        
        return did_doc;
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DidDocument {
    context: Vec<String>,
    id: String,
    authentication: Vec<SSIKeyMaterial>,
    capability_invocation: Vec<SSIKeyMaterial>,
    capability_delegation: Vec<SSIKeyMaterial>,
    assertion_method: Vec<SSIKeyMaterial>,
}