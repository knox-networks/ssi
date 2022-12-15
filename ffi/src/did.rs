use safer_ffi::prelude::*;
use registry_resolver::RegistryResolver;
use tokio::runtime::Runtime;
use serde::*;
use crate::error::{MaybeRustError, Reportable, Try};

#[ffi_export]
fn create_identity(
    rust_error: MaybeRustError,
    did_method: repr_c::String,
    mnemonic_input: repr_c::String,
) -> repr_c::String {
    // create_did_doc functionality
    let mut mnemonic: Option<String>;
    if len(mnemonic_input) == 0 {
        mnemonic = Some(mnemonic_input);
    } else {
        mnemonic = None;
    }
    let some = rust_error
        .try_(||{
                let keypair = ssi::signature::suite::ed25519_2020::Ed25519KeyPair::new(
                    did_method.to_string(),
                    mnemonic,
                );
                let verifier = ssi::signature::suite::ed25519_2020::Ed25519DidVerifier::from(keypair);
                let rt = Runtime::new().report("failed to create runtime").expect("unable to launch runtime");
                let did_doc = rt.block_on(ssi::identity::create_identity(verifier).await)?;
                Ok(did_doc)
            }
        ).is_some();
        if some {
            return did_doc;
        }
}

#[ffi_export]
fn register_identity(
    rust_error: MaybeRustError,
    address: repr_c::String,
    did: repr_c::String,
    document: repr_c::String,
) -> repr_c::String {
    return crate::registry::registry_create_did(rust_error, address, did, document);
}