use crate::utilities;
use crate::Sid;
use std::ffi::OsString;
use std::io;
use std::ptr::null_mut;

/// Wraps [`ConvertSidToStringSidW`](https://docs.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsidtostringsidw).
///
/// ```
/// use windows_permissions::{LocalBox, Sid, wrappers::ConvertSidToStringSid};
///
/// let string_sid = "S-1-5-123-456-789";
/// let sid: LocalBox<Sid> = string_sid.parse().unwrap();
/// let string_sid2 = ConvertSidToStringSid(&sid).unwrap();
///
/// assert_eq!(string_sid, string_sid2);
/// ```
#[allow(non_snake_case)]
pub fn ConvertSidToStringSid(sid: &Sid) -> io::Result<OsString> {
    let mut buf_ptr: *mut u16 = null_mut();
    let result = unsafe {
        windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW(
            sid as *const _ as *mut _,
            &mut buf_ptr,
        )
    };

    if result == 0 {
        // Failed! No need to clean up
        Err(io::Error::last_os_error())
    } else {
        // Success! Copy the string into an OsString and free the original buffer
        let nul_pos = unsafe { utilities::search_buffer(&0x00, buf_ptr) };
        let slice_with_nul = unsafe { std::slice::from_raw_parts(buf_ptr, nul_pos + 1) };

        let os_string = utilities::os_from_buf(slice_with_nul);

        unsafe { windows_sys::Win32::System::Memory::LocalFree(buf_ptr as isize) };

        Ok(os_string)
    }
}
