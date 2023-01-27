use crate::error::{MaybeRustError, Reportable, Try};
use safer_ffi::prelude::*;
use ssi_core::DIDResolver;
use tokio::runtime::Runtime;
use tracing::*;

#[ffi_export]
pub fn registry_create_did(
    rust_error: MaybeRustError,
    address: char_p::Ref<'_>,
    did: char_p::Ref<'_>,
    document: Option<repr_c::Box<crate::did::DidDocument>>,
) -> bool {
    let r = crate::logger::init_logger("DEBUG");
    if r.is_err() {
        println!("unable to init logging");
        return false;
    }
    info!("registry_create_did called");
    let rt = Runtime::new()
        .report("failed to create runtime")
        .expect("unable to launch runtime");
    let dd = document.unwrap();
    let rsp = rust_error.try_(|| {
        rt.block_on(async move {
            debug!("entering block_on runtime state");
            let resolver = registry_resolver::RegistryResolver::new(address.to_string()).await;
            let document_serialized = serde_json::to_value(dd.backend.clone()).unwrap();
            let result = resolver.create(did.to_string(), document_serialized).await;
            info!("resolver response {:?}", result);
            Ok(result)
        })
    });
    rsp.is_some()
}