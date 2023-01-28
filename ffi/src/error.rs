use core::fmt::Display;

use safer_ffi::prelude::*;

#[derive_ReprC]
#[repr(C)]
pub struct RustError {
    error_str: Option<char_p::Box>,
}

#[ffi_export]
pub fn free_rust_error(rust_error: RustError) {
    drop(rust_error.error_str)
}


#[derive(Debug, thiserror::Error)]
pub enum FFIError {
    #[error(transparent)]
    InitLoggerError(#[from] tracing_subscriber::util::TryInitError),
}

/*
The C side usage is as follows:
```
RustError_t rust_error;
some_api_func(&rust_error, ...);
// later
free_rust_error(rust_error);
```
*/
pub(crate) type MaybeRustError<'a> = Option<Out<'a, RustError>>;

/// Creates a new error structure and writes it to the Out FFI parameter.
fn report_error(error: Option<&str>, rust_error: MaybeRustError) {
    if let Some(rust_error) = rust_error {
        // a pointer to RustError was given on the C side, we need to write something into it.
        let new_error = if let Some(error) = error {
            RustError {
                error_str: Some(error.to_string().try_into().unwrap()),
            }
        } else {
            RustError { error_str: None }
        };
        rust_error.write(new_error);
    }
}

/// This trait is used to serialize the erroneous result of Result/Option
/// into a string, given the explanatory message.
pub trait Reportable<T> {
    fn report(self, message: &str) -> Result<T, String>;
}

impl<T, E: Display> Reportable<T> for Result<T, E> {
    fn report(self, message: &str) -> Result<T, String> {
        self.map_err(|err| format!("{message}: {err}"))
    }
}

impl<T> Reportable<T> for Option<T> {
    fn report(self, message: &str) -> Result<T, String> {
        self.ok_or_else(|| message.to_string())
    }
}

/// This trait allows one to use ? notation funneling the error into the FFI Out parameter,
/// while ensuring that the Out parameter is only written once.
///
/// This can be implemented using the `try` syntax (https://github.com/rust-lang/rust/issues/31436)
/// when it is stabilized.
pub(crate) trait Try {
    fn try_<T>(self, block: impl FnOnce() -> Result<T, String>) -> Option<T>;
}

impl Try for Option<Out<'_, RustError>> {
    fn try_<T>(self, block: impl FnOnce() -> Result<T, String>) -> Option<T> {
        match block() {
            Ok(it) => {
                report_error(None, self);
                Some(it)
            }
            Err(err_msg) => {
                report_error(Some(&err_msg), self);
                None
            }
        }
    }
}

/// A small quality of life method for chaining after `rust_error.try_()`,
/// to write a result (if any) into the output and return the bool status flag.
pub(crate) trait Returnable<T> {
    fn write(self, out: Out<'_, T>) -> bool;
}

impl<T> Returnable<T> for Option<T> {
    fn write(self, out: Out<'_, T>) -> bool {
        self.map(|some| out.write(some)).is_some()
    }
}
