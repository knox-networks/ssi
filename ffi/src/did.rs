use crate::error::{MaybeRustError, Reportable, Try};
use safer_ffi::prelude::*;
use signature::suite::KeyPair;
use tokio::runtime::Runtime;
use tracing::*;

#[derive_ReprC]
#[ReprC::opaque]
#[derive(Clone)]
pub struct DidDocument {
    pub(crate) backend: ssi_core::identity::DidDocument,
}

#[derive_ReprC]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FFICompatEd25519KeyPair {
    pub(crate) master_public_key: [u8; 32],
    pub(crate) master_private_key: [u8; 32],

    pub(crate) authetication_public_key: [u8; 32],
    pub(crate) authetication_private_key: [u8; 32],

    pub(crate) capability_invocation_public_key: [u8; 32],
    pub(crate) capability_invocation_private_key: [u8; 32],

    pub(crate) capability_delegation_public_key: [u8; 32],
    pub(crate) capability_delegation_private_key: [u8; 32],

    pub(crate) assertion_method_public_key: [u8; 32],
    pub(crate) assertion_method_private_key: [u8; 32],
    pub(crate) mnemonic: FFICompatMnemonic,
    pub(crate) did_method: char_p::Box,
}

#[derive_ReprC]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FFICompatMnemonic {
    pub language: char_p::Box,
    pub phrase: char_p::Box,
}

#[ffi_export]
pub fn get_did(did_doc: repr_c::Box<DidDocument>) -> Option<char_p::Box> {
    let did = did_doc.backend.id.clone().try_into();
    match did {
        Ok(did) => Some(did),
        Err(e) => {
            error!("failed to convert did to string: {:?}", e);
            None
        }
    }
}

#[ffi_export]
pub fn get_encoded_did_doc(did_doc: repr_c::Box<DidDocument>) -> Option<char_p::Box> {
    let did_doc = did_doc.backend.to_json();

    match did_doc {
        Ok(did_doc) => match did_doc.try_into() {
            Ok(did_doc) => Some(did_doc),
            Err(e) => {
                error!("failed to convert did_doc to string: {:?}", e);
                None
            }
        },
        Err(e) => {
            error!("failed to convert did_doc to json: {:?}", e);
            None
        }
    }
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

    let mnemonic_option: Option<signature::suite::ed25519_2020::Mnemonic> =
        if mnemonic_input.to_string().is_empty() {
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

#[ffi_export]
pub fn create_identity_vec(
    rust_error: MaybeRustError,
    did_method: char_p::Ref<'_>,
    mnemonic_input: char_p::Ref<'_>,
) -> Option<repr_c::Box<safer_ffi::vec::Vec<u8>>> {
    let t_identity = create_identity(rust_error, did_method, mnemonic_input);
    info!(
        did_method=?did_method,
        "creating bytes vector did_doc representation");
    if let Some(did_doc) = t_identity {
        info!("did_doc received");
        let did_doc_vector = serde_json::to_vec(&did_doc.backend);

        if did_doc_vector.is_ok() {
            info!("did_doc converted to vector");
            let did_doc_c_vec: safer_ffi::vec::Vec<u8> =
                did_doc_vector.expect("unrapping did doc_vector").into();
            info!("did_doc converted to safer_ffi::vec::Vec<u8>");
            return Some(repr_c::Box::new(did_doc_c_vec));
        }
    }
    None
}

#[ffi_export]
pub fn free_identity_did_doc(did_doc: repr_c::Box<DidDocument>) {
    drop(did_doc)
}

#[ffi_export]
pub fn create_keypair(
    rust_error: MaybeRustError,
    did_method: char_p::Ref<'_>,
) -> Option<repr_c::Box<FFICompatEd25519KeyPair>> {
    super::init();

    let res = rust_error.try_(|| {
        let keypair =
            signature::suite::ed25519_2020::Ed25519KeyPair::new(did_method.to_string(), None)
                .unwrap();
        Ok(keypair)
    });

    match res {
        Some(keypair) => {
            debug!("create_keypair unpacking result {:?}", keypair);
            let r = keypair;
            Some(repr_c::Box::new(create_ffi_keypair(r)))
        }
        None => {
            debug!("create_keypair None result");
            None
        }
    }
}

#[ffi_export]
pub fn recover_keypair(
    rust_error: MaybeRustError,
    did_method: char_p::Ref<'_>,
    mnemonic_input: char_p::Ref<'_>,
) -> Option<repr_c::Box<FFICompatEd25519KeyPair>> {
    super::init();

    let res = rust_error.try_(|| {
        let keypair = signature::suite::ed25519_2020::Ed25519KeyPair::new(
            did_method.to_string(),
            Some(signature::suite::ed25519_2020::Mnemonic {
                language: signature::suite::ed25519_2020::MnemonicLanguage::English,
                phrase: mnemonic_input.to_string(),
            }),
        )
        .unwrap();
        Ok(keypair)
    });

    match res {
        Some(keypair) => {
            debug!("create_keypair unpacking result {:?}", keypair);
            let r = keypair;
            Some(repr_c::Box::new(create_ffi_keypair(r)))
        }
        None => {
            debug!("create_keypair None result");
            None
        }
    }
}

fn create_ffi_keypair(
    kp: signature::suite::ed25519_2020::Ed25519KeyPair,
) -> FFICompatEd25519KeyPair {
    let r = kp;
    let mnemonic = r.get_mnemonic();
    let language = mnemonic.language.to_string();
    let phrase = mnemonic.phrase;
    FFICompatEd25519KeyPair {
        master_public_key: r.get_master_public_key().into(),
        master_private_key: r.get_master_private_key().into(),
        authetication_public_key: r
            .get_public_key_by_relation(signature::suite::VerificationRelation::Authentication)
            .into(),
        authetication_private_key: r
            .get_private_key_by_relation(signature::suite::VerificationRelation::Authentication)
            .into(),
        capability_invocation_public_key: r
            .get_public_key_by_relation(
                signature::suite::VerificationRelation::CapabilityInvocation,
            )
            .into(),
        capability_invocation_private_key: r
            .get_private_key_by_relation(
                signature::suite::VerificationRelation::CapabilityInvocation,
            )
            .into(),
        capability_delegation_public_key: r
            .get_public_key_by_relation(
                signature::suite::VerificationRelation::CapabilityDelegation,
            )
            .into(),
        capability_delegation_private_key: r
            .get_private_key_by_relation(
                signature::suite::VerificationRelation::CapabilityDelegation,
            )
            .into(),
        assertion_method_public_key: r
            .get_public_key_by_relation(signature::suite::VerificationRelation::AssertionMethod)
            .into(),
        assertion_method_private_key: r
            .get_private_key_by_relation(signature::suite::VerificationRelation::AssertionMethod)
            .into(),
        mnemonic: FFICompatMnemonic {
            language: language.try_into().unwrap(),
            phrase: phrase.try_into().unwrap(),
        },
        did_method: r.get_did_method().try_into().unwrap(),
    }
}
