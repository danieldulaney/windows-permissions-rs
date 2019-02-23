use crate::wrappers;
use crate::Sid;

/// Wraps GetSidSubAuthority
///
/// # Requirements
///
/// The `Sid` structure *must* have enough sub authorities. This is *not* checked
/// by this function. Accessing a higher index is undefined behavior.
#[allow(non_snake_case)]
pub unsafe fn GetSidSubAuthority(sid: &Sid, sub_auth: u8) -> u32 {
    *winapi::um::securitybaseapi::GetSidSubAuthority(sid.as_ptr() as *mut _, sub_auth as u32)
}

/// Checks the SID sub authority count before trying to access it, returns `None`
/// if the SID doesn't have that many sub authorities.
#[allow(non_snake_case)]
pub fn GetSidSubAuthorityChecked(sid: &Sid, sub_auth: u8) -> Option<u32> {
    if wrappers::GetSidSubAuthorityCount(sid) > sub_auth {
        unsafe { Some(GetSidSubAuthority(sid, sub_auth)) }
    } else {
        None
    }
}
