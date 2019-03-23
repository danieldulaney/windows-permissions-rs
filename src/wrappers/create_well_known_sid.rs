use crate::{wrappers, LocalBox, Sid};
use std::io;
use std::ptr::null_mut;

/// Wraps CreateWellKnownSid
///
/// Currently only supports creating SIDs with up to 8 subauthorities; longer
/// SIDs will give an OS error (code 122).
///
/// If `domain_sid` is omitted, this has the same behavior as the underlying
/// WinAPI function.
#[allow(non_snake_case)]
pub fn CreateWellKnownSid(sid_type: u32, domain_sid: Option<&Sid>) -> io::Result<LocalBox<Sid>> {
    // Optimistically reserve enough space for a fairly large SID
    let mut sid_len = wrappers::GetSidLengthRequired(8) as u32;

    // Get the pointer to the domain SID
    let domain_sid_ptr = match domain_sid {
        None => null_mut(),
        Some(s) => s as *const _ as *mut _,
    };

    // Allocate space for the new SID
    let new_sid: LocalBox<Sid> = unsafe { LocalBox::try_allocate(true, sid_len as usize)? };

    let result = unsafe {
        winapi::um::securitybaseapi::CreateWellKnownSid(
            sid_type,
            domain_sid_ptr,
            new_sid.as_ptr() as *mut _,
            &mut sid_len,
        )
    };

    if result != 0 {
        // Success! The SID was initialized and should be returned
        return Ok(new_sid);
    } else {
        return Err(io::Error::last_os_error());
    }
}
