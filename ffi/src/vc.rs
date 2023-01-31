use safer_ffi::prelude::*;
use registry_resolver::RegistryResolver;
use tokio::runtime::Runtime;
use serde::*;
use crate::error::{MaybeRustError, Reportable, Try};

#[ffi_export]
fn create_vc(
    rust_error: MaybeRustError,
    public_key: repr_c::String,
    did: repr_c::String,
    document: repr_c::String,
) -> repr_c::String {
    unimplemented!("create_vc unimplemented")
}
