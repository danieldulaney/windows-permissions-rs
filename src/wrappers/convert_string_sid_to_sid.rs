use crate::utilities::buf_from_os;
use crate::Sid;
use std::ffi::OsStr;
use std::ptr::{null_mut, NonNull};
use windows_error::WindowsError;

/// Wraps ConvertStringSidToSidW
#[allow(non_snake_case)]
pub fn ConvertStringSidToSid(string: &OsStr) -> Result<Sid, WindowsError> {
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
        Err(WindowsError::from_last_err())
    }
}
