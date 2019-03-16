use crate::Sid;

/// Wraps GetSidSubAuthorityCount
#[allow(non_snake_case)]
pub fn GetSidSubAuthorityCount(sid: &Sid) -> u8 {
    unsafe { *winapi::um::securitybaseapi::GetSidSubAuthorityCount(sid as *const _ as *mut _) }
}
