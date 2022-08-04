#![allow(unused_variables)]
#![allow(dead_code)]

struct Identity {
    resolver: crate::registry::resolver::RegistryResolver,
}

impl Identity {
    pub fn new(resolver: RegistryResolver) -> Identity {
        Identity{
            resolver:resolver ,
        }
    }
    pub fn generate(&mut self, doc: serde_json::Value) {
        let signer = signature::signer::Ed25519DidSigner::new();
        let signed_doc = self.create_did_document(doc, &signer, &verifier);
        self.resolver.create(did, signed_doc) 
    }

    fn create_did_document(doc: serde::Value, signer: crate::signer::Ed25519DidSigner) -> serde::Value{
        let mut did_doc: DidDocument = serde_json::try_from(doc).unwrap();
        did_doc.authentication = vec![
            crate::keypair::SSIKeyMaterial{
                id: did_doc.get_verification_method(crate::suite::VerificationRelation.Authentication),
                proof_type: did_doc.get_proof_type(),
                controller: did_doc.get_controller(),
                public_key_multibase: did_doc.get_public_key_by_relation(crate::suite::VerificationRelation.Authentication),
            },];
        did_doc.capability_invocation = vec![
            crate::keypair::SSIKeyMaterial{
                id: did_doc.get_verification_method(crate::suite::VerificationRelation.CapabilityInvocation),
                proof_type: did_doc.get_proof_type(),
                controller: did_doc.get_controller(),
                public_key_multibase: did_doc.get_public_key_by_relation(crate::suite::VerificationRelation.CapabilityInvocation),
            },];
        did_doc.capability_delegation = vec![
            crate::keypair::SSIKeyMaterial{
                id: did_doc.get_verification_method(crate::suite::VerificationRelation.CapabilityDelegation),
                proof_type: did_doc.get_proof_type(),
                controller: did_doc.get_controller(),
                public_key_multibase:  did_doc.get_public_key_by_relation(crate::suite::VerificationRelation.CapabilityDelegation),
            },];
        did_doc.assertion_method = vec![
            crate::keypair::SSIKeyMaterial{
                id: did_doc.get_verification_method(crate::suite::VerificationRelation.AssertionMethod),
                proof_type: did_doc.get_proof_type(),
                controller: did_doc.get_controller(),
                public_key_multibase: did_doc.get_public_key_by_relation(crate::suite::VerificationRelation.AssertionMethod),
            },
        ];
        serde::to_value(doc).unwrap();
    }
}

struct DidDocument {
    context: Vec<String>,
    id: String,
    authentication: Vec<crate::signature::SSIKeyMaterial>,
    capability_invocation: Vec<crate::signature::SSIKeyMaterial>,
    capability_delegation: Vec<crate::signature::SSIKeyMaterial>,
    assertion_method: Vec<crate::signature::SSIKeyMaterial>,
}


#[cfg(test)]
mod tests {
    use crate::Credential;
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    #[test]
    fn test_create_identity() -> Result<(), String> {
        if ds.is_ok() {
            let vc = ds.unwrap().serialize();
            assert_json_eq!(expect, vc);
        } else {
            assert!(false);
        }
        Ok(())
    }
}