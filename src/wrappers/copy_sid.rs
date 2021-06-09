use crate::{wrappers, LocalBox, Sid};
use std::io;

/// Wraps [`CopySid`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-copysid)
#[allow(non_snake_case)]
pub fn CopySid(sid: &Sid) -> io::Result<LocalBox<Sid>> {
    let size = wrappers::GetSidLengthRequired(wrappers::GetSidSubAuthorityCount(sid));

    let new_sid: LocalBox<Sid> = unsafe { LocalBox::try_allocate(true, size)? };

    let success = unsafe {
        winapi::um::securitybaseapi::CopySid(
            size as u32,
            new_sid.as_ptr() as *mut _,
            sid as *const _ as *mut _,
        )
    };

    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(new_sid)
    }
}
