pub mod did;
mod error;
mod logger;
pub mod registry;

use std::sync::Once;
static START: Once = Once::new();

pub fn init() {
    START.call_once(|| logger::init_logger("DEBUG").expect("logger initialized succesfully"));
}

/// The following test function is necessary for the header generation.
#[cfg(feature = "c-headers")]
#[test]
fn generate_headers() -> ::std::io::Result<()> {
    safer_ffi::headers::builder()
        .to_file("./headers/ssi_ffi.h")?
        .generate()
}
