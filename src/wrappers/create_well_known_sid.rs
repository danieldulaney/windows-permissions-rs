use crate::Sid;
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;
use windows_error::WindowsError;

/// Wraps CreateWellKnownSid
#[allow(non_snake_case)]
pub fn CreateWellKnownSid(sid_type: u32) -> Result<Sid, WindowsError> {
    let mut sid: Sid;
    let mut size = size_of::<Sid>() as u32;

    let result = unsafe {
        sid = zeroed();

        winapi::um::securitybaseapi::CreateWellKnownSid(
            sid_type,
            null_mut(),
            &mut sid as *mut _ as *mut _,
            &mut size,
        )
    };

    if result != 0 {
        Ok(sid)
    } else {
        Err(WindowsError::from_last_err())
    }
}
