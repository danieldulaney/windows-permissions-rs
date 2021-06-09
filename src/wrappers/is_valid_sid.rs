use crate::Sid;

/// Wraps [`IsValidSid`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-isvalidsid)
#[allow(non_snake_case)]
pub fn IsValidSid(sid: &Sid) -> bool {
    (unsafe { winapi::um::securitybaseapi::IsValidSid(sid as *const _ as *mut _) }) != 0
}
