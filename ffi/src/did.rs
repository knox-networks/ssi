use crate::error::{MaybeRustError, Reportable, Try};
use safer_ffi::prelude::*;
use signature::suite::ed25519_2020::Mnemonic;
use tokio::runtime::Runtime;
use tracing::*;

#[derive_ReprC]
#[ReprC::opaque]
#[derive(Clone)]
pub struct DidDocument {
    pub(crate) backend: ssi_core::identity::DidDocument,
}

#[ffi_export]
pub fn create_identity(
    rust_error: MaybeRustError,
    did_method: char_p::Ref<'_>,
    mnemonic_input: char_p::Ref<'_>,
) -> Option<repr_c::Box<DidDocument>> {
    super::init();
    info!(
        did_method=?did_method, 
        mnemonic_input=?mnemonic_input,
        "ffi create_identity called with params");

    let mnemonic_option: Option<Mnemonic> = if mnemonic_input.to_string().is_empty() {
        None
    } else {
        let mm = signature::suite::ed25519_2020::Mnemonic {
            language: signature::suite::ed25519_2020::MnemonicLanguage::English,
            phrase: mnemonic_input.to_string(),
        };
        Some(mm)
    };
    let result = rust_error.try_(|| {
        let did_mt = did_method.to_string();
        let keypair =
            signature::suite::ed25519_2020::Ed25519KeyPair::new(did_mt, mnemonic_option).unwrap();
        let verifier = signature::suite::ed25519_2020::Ed25519DidVerifier::from(keypair);
        let rt = Runtime::new()
            .report("failed to create runtime")
            .expect("unable to launch runtime");
        let did_doc =
            rt.block_on(async move { ssi_core::identity::create_identity(verifier).await });
        debug!("create_identity response {:?}", did_doc);
        Ok(did_doc)
    });

    if result.is_some() {
        debug!("create_identity unpacking result {:?}", result);
        let r = result.unwrap();
        return Some(repr_c::Box::new(DidDocument {
            backend: r.unwrap(),
        }));
    }
    debug!("create_identity None result");
    None
}
