use crate::utilities::os_from_buf;
use crate::Sid;
use std::ffi::OsString;
use std::io;
use std::ptr::{null, null_mut};

const BUFFER_SIZE: u32 = 256;

/// Wraps [`LookupAccountSidW`](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountsidw)
///
/// Returns (name, domain).
#[allow(non_snake_case)]
pub fn LookupAccountSid(sid: &Sid) -> Result<(OsString, OsString), io::Error> {
    let mut name_size = BUFFER_SIZE;
    let mut dom_size = BUFFER_SIZE;

    loop {
        let old_name_size = name_size;
        let old_dom_size = dom_size;

        let mut name: Vec<u16> = vec![0; name_size as usize];
        let mut dom: Vec<u16> = vec![0; dom_size as usize];

        let result = unsafe {
            winapi::um::winbase::LookupAccountSidW(
                null(),
                sid as *const Sid as *mut _,
                name.as_mut_ptr(),
                &mut name_size,
                dom.as_mut_ptr(),
                &mut dom_size,
                null_mut(),
            )
        };

        if result != 0 {
            // Success: Return the filled buffers as OsStrings
            return Ok((os_from_buf(&name), os_from_buf(&dom)));
        } else if name_size != old_name_size || dom_size != old_dom_size {
            // Failed, but requests new allocation: try again
            continue;
        } else {
            // Failed, with no new allocation request
            return Err(io::Error::last_os_error());
        }
    }
}
