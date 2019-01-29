use crate::utilities;
use crate::Sid;
use std::ffi::OsString;
use std::ptr::null_mut;
use windows_error::WindowsError;

/// Wraps ConvertSidtoStringSidW
#[allow(non_snake_case)]
pub fn ConvertSidToStringSid(sid: &Sid) -> Result<OsString, WindowsError> {
    let mut buf_ptr: *mut u16 = null_mut();
    let result = unsafe {
        winapi::shared::sddl::ConvertSidToStringSidW(sid as *const _ as *mut _, &mut buf_ptr)
    };

    if result == 0 {
        // Failed
        Err(WindowsError::from_last_err())
    } else {
        // Success! Copy the string into an OsString and free the original buffer
        let nul_pos = unsafe { utilities::search_buffer(&0x00, buf_ptr) };
        let slice_with_nul = unsafe { std::slice::from_raw_parts(buf_ptr, nul_pos + 1) };

        let os_string = utilities::os_from_buf(slice_with_nul);

        unsafe { winapi::um::winbase::LocalFree(buf_ptr as *mut _) };

        Ok(os_string)
    }
}
