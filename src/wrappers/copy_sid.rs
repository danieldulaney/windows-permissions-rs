use crate::{wrappers, LocallyOwnedSid, Sid};
use std::io;
use std::ptr::NonNull;

/// Wraps CopySid
#[allow(non_snake_case)]
pub fn CopySid(sid: &Sid) -> io::Result<LocallyOwnedSid> {
    let size = wrappers::GetSidLengthRequired(wrappers::GetSidSubAuthorityCount(sid));

    // Must be wrapped in a LocallyOwnedSid to ensure it is free'd
    let ptr = unsafe { winapi::um::winbase::LocalAlloc(winapi::um::minwinbase::LMEM_FIXED, size) };

    let ptr = NonNull::new(ptr).ok_or_else(|| io::Error::last_os_error())?;

    let success = unsafe {
        winapi::um::securitybaseapi::CopySid(size as u32, ptr.as_ptr(), sid as *const _ as *mut _)
    };

    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        unsafe { Ok(LocallyOwnedSid::owned_from_nonnull(ptr)) }
    }
}
