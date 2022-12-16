use safer_ffi::prelude::*;
use signature::suite::ed25519_2020::Mnemonic;
use tokio::runtime::Runtime;
use crate::error::{MaybeRustError, Reportable, Try};

#[ffi_export]
pub fn create_identity(
    rust_error: MaybeRustError,
    did_method: repr_c::String,
    mnemonic_input: repr_c::String,
) -> repr_c::String {
    // create_did_doc
    let mnemonic_option: Option<Mnemonic>;
    if mnemonic_input.to_string().len() == 0 {
        mnemonic_option = None;
    } else {
        let mm = signature::suite::ed25519_2020::Mnemonic{
            language: signature::suite::ed25519_2020::MnemonicLanguage::English,
            phrase: mnemonic_input.to_string(),
        };
        mnemonic_option = Some(mm);
    }
    let result = rust_error
        .try_(||{
                let keypair = signature::suite::ed25519_2020::Ed25519KeyPair::new(
                    did_method.to_string(),
                    mnemonic_option,
                ).unwrap();
                let verifier = signature::suite::ed25519_2020::Ed25519DidVerifier::from(keypair);
                let rt = Runtime::new().report("failed to create runtime").expect("unable to launch runtime");
                let did_doc = 
                rt.block_on(async move {
                    ssi_core::identity::create_identity(verifier).await
                });
                Ok(did_doc)
            }
        );

        if result.is_some() {
            let r = result.unwrap();
            if r.is_ok() {
                let did_doc = r.unwrap();
                return repr_c::String::from(serde_json::to_string(&did_doc).unwrap());
            } else {
                return safer_ffi::String::from("".to_string());
            }
        } else {
            return safer_ffi::String::from("".to_string());
        }
        
}
// #[ffi_export]
// pub fn register_identity(
//     rust_error: MaybeRustError,
//     address: repr_c::String,
//     did: repr_c::String,
//     document: repr_c::String,
// ) -> repr_c::String {
//     return crate::registry::registry_create_did(rust_error, address, did, document);
// }
