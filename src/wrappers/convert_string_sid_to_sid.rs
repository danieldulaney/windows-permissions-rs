use crate::utilities::buf_from_os;
use crate::{LocalBox, Sid};
use std::ffi::OsStr;
use std::io;
use std::ptr::{null_mut, NonNull};

/// Wraps [`ConvertStringSidToSidW`](https://docs.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertstringsidtosidw).
///
/// ```
/// use windows_permissions::{Sid, wrappers::ConvertStringSidToSid};
///
/// let string_sid = "S-1-5-123-456-789";
/// let sid = ConvertStringSidToSid(string_sid).unwrap();
/// assert_eq!(string_sid, &sid.to_string());
/// ```
///
/// # Panics
///
/// Panics if the underlying WinAPI call reports success but returns a null
/// pointer. This should never happen.
#[allow(non_snake_case)]
pub fn ConvertStringSidToSid<S: AsRef<OsStr> + ?Sized>(string: &S) -> io::Result<LocalBox<Sid>> {
    let buf = buf_from_os(string);
    let mut ptr = null_mut();

    let result = unsafe {
        windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW(buf.as_ptr(), &mut ptr)
    };

    if result != 0 {
        // Success
        Ok(unsafe {
            LocalBox::from_raw(
                NonNull::new(ptr as *mut _)
                    .expect("ConvertStringSidToSidW reported success but returned null"),
            )
        })
    } else {
        // Failure
        Err(io::Error::last_os_error())
    }
}
