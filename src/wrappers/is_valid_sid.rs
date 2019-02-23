use crate::Sid;
use std::io;

/// Wraps IsValidSid
///
/// If the Sid isn't valid, constructs an `io::Error` with
/// `ErrorKind::InvalidData`.
#[allow(non_snake_case)]
pub fn IsValidSid(sid: &Sid) -> Result<(), io::Error> {
    match unsafe { winapi::um::securitybaseapi::IsValidSid(sid.as_ptr() as *mut _) } {
        0 => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid SID structure",
        )),
        _ => Ok(()), // Valid SID
    }
}
