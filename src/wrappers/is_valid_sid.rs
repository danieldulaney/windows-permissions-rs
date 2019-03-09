use crate::Sid;

/// Wraps IsValidSid
#[allow(non_snake_case)]
pub fn IsValidSid(sid: &Sid) -> bool {
    (unsafe { winapi::um::securitybaseapi::IsValidSid(sid.as_ptr() as *mut _) }) != 0
}
