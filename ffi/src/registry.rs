use safer_ffi::prelude::*;
use ssi_core::DIDResolver;
use tokio::runtime::Runtime;
use crate::error::{MaybeRustError, Reportable, Try};

#[ffi_export]
pub fn registry_create_did(
    rust_error: MaybeRustError,
    address: repr_c::String,
    did: repr_c::String,
    document: repr_c::String,
) -> bool {
    let rt = Runtime::new().report("failed to create runtime").expect("unable to launch runtime");
    let rsp = rust_error
        .try_(||{
                rt.block_on(async move {
                    let resolver = registry_resolver::RegistryResolver::new(address.to_string()).await;
                    let document_serialized = serde_json::from_str(&document.to_string()).unwrap();
                    let result = resolver.create(did.to_string(), document_serialized).await;
                    return Ok(result);
                })
            }
        );
        return rsp.is_some()
}
