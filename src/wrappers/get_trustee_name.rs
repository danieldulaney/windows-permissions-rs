use crate::utilities::{os_from_buf, search_buffer};
use crate::Trustee;
use std::ffi::OsString;

/// Wraps [`GetTrusteeNameW`](https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-gettrusteenamew)
#[allow(non_snake_case)]
pub fn GetTrusteeName<'s>(trustee: &Trustee<'s>) -> OsString {
    unsafe {
        let ptr = winapi::um::aclapi::GetTrusteeNameW(trustee.as_ptr() as *mut _);
        let len = search_buffer(&0, ptr);
        let buf = std::slice::from_raw_parts(ptr, len);

        os_from_buf(buf)
    }
}
