use crate::{wrappers, LocalBox, Sid};
use std::io;
use std::ptr::null_mut;

/// Wraps [CreateWellKnownSid](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createwellknownsid).
///
/// `sid_type` may be any value in [WELL_KNOWN_SID_TYPE](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-well_known_sid_type).
///
/// If `domain_sid` is omitted, this has the same behavior as the underlying
/// WinAPI function.
///
/// ```
/// use windows_permissions::{wrappers, Sid, LocalBox};
/// use winapi::um::winnt::WinWorldSid;
///
/// let win_world_sid = wrappers::CreateWellKnownSid(WinWorldSid, None).unwrap();
/// let another_sid = "S-1-1-0".parse().unwrap();
///
/// assert_eq!(win_world_sid, another_sid);
/// ```
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
