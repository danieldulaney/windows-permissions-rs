use crate::{wrappers, Sid};
use std::io;
use std::ptr::NonNull;

/// Wraps CopySid
#[allow(non_snake_case)]
pub fn CopySid(sid: &Sid) -> Result<Sid, io::Error> {
    let len = wrappers::GetSidLengthRequired(wrappers::GetSidSubAuthorityCount(sid));

    // Must be wrapped in a Sid to ensure it is free'd
    let ptr = unsafe { winapi::um::winbase::LocalAlloc(winapi::um::minwinbase::LMEM_FIXED, len) };

    NonNull::new(ptr)
        .map(|p| unsafe { Sid::owned_from_nonnull(p) })
        .ok_or_else(|| io::Error::last_os_error())
}
