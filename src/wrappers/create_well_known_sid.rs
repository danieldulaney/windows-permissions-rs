use crate::{wrappers, Sid};
use std::io;
use std::mem::{size_of, zeroed};
use std::ptr::{null_mut, NonNull};

/// Wraps CreateWellKnownSid
///
/// Currently only supports creating SIDs with up to 8 subauthorities; longer
/// SIDs will give an OS error (code 122).
///
/// If `domain_sid` is omitted, this has the same behavior as the underlying
/// WinAPI function.
#[allow(non_snake_case)]
pub fn CreateWellKnownSid(sid_type: u32, domain_sid: Option<&Sid>) -> Result<Sid, io::Error> {
    // Optimistically reserve enough space for a fairly large SID
    let mut sid_len = wrappers::GetSidLengthRequired(8) as u32;

    // Assumptions:
    // - Returned value must be null-checked before use
    // - Returned value must be free'd with LocalFree or similar
    let sid_ptr = unsafe {
        winapi::um::winbase::LocalAlloc(winapi::um::minwinbase::LMEM_FIXED, sid_len as usize)
    };

    // No cleanup needed on failure -- the pointer was null anyway
    let sid_ptr = NonNull::new(sid_ptr).ok_or_else(|| io::Error::last_os_error())?;

    // At this point, the memory was allocated -- it *must* be freed

    let result = unsafe {
        winapi::um::securitybaseapi::CreateWellKnownSid(sid_type, null_mut(), sid_ptr.as_ptr(), &mut sid_len)
    };

    if result != 0 {
        // Success! The SID was initialized and should be returned
        // Cleanup for the allocation will be performed when the Sid is Drop'd
        return Ok( unsafe { Sid::owned_from_nonnull(sid_ptr) } );
    } else {
        // Failure! Save off the error, free the buffer, and figure out what to do

        // It's important to get this error before freeing the buffer because
        // LocalFree could potentially set its own error code
        let error = io::Error::last_os_error();

        unsafe { winapi::um::winbase::LocalFree(sid_ptr.as_ptr()) };

        // TODO: Reallocate on error code 122 using the size that was written
        // to sid_len
        return Err(error);
    }
}
