use crate::utilities::buf_from_os;
use crate::Sid;
use std::ffi::OsStr;
use std::io;
use std::ptr::{null_mut, NonNull};

/// Wraps ConvertStringSidToSidW
///
/// # Panics
///
/// Panics if the underlying WinAPI call reports success but returns a null
/// pointer. This should never happen.
#[allow(non_snake_case)]
pub fn ConvertStringSidToSid<S: AsRef<OsStr> + ?Sized>(string: &S) -> Result<Sid, io::Error> {
    let buf = buf_from_os(string);
    let mut ptr = null_mut();

    let result = unsafe { winapi::shared::sddl::ConvertStringSidToSidW(buf.as_ptr(), &mut ptr) };

    if result != 0 {
        // Success
        Ok(unsafe {
            Sid::owned_from_nonnull(
                NonNull::new(ptr)
                    .expect("ConvertStringSidToSidW reported success but returned null"),
            )
        })
    } else {
        // Failure
        Err(io::Error::last_os_error())
    }
}
