use safer_ffi::prelude::*;
use registry_resolver::RegistryResolver;
use tokio::runtime::Runtime;
use serde::*;
use crate::error::{MaybeRustError, Reportable, Try};

#[ffi_export]
pub (crate) fn registry_create_did(
    rust_error: MaybeRustError,
    address: repr_c::String,
    did: repr_c::String,
    document: repr_c::String,
) -> bool {
    let rt = Runtime::new().report("failed to create runtime").expect("unable to launch runtime");
    rust_error
        .try_(||{
                rt.block_on(async move {
                    let resolver = RegistryResolver::new(address.to_string()).await;
                    let document_serialized: serde_json::Value = serde_json::from_str(document.to_string()).into();
                    resolver.create(did, document_serialized);
                })
            }
        ).is_some()
}