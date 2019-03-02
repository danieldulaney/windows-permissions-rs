use crate::wrappers;
use crate::Sid;

/// Wraps GetSidSubAuthority
///
/// # Requirements
///
/// The `Sid` structure *must* have enough sub authorities. This is *not* checked
/// by this function. Accessing a higher index is undefined behavior.
#[allow(non_snake_case)]
pub unsafe fn GetSidSubAuthority(sid: &Sid, sub_auth: u8) -> *const u32 {
    winapi::um::securitybaseapi::GetSidSubAuthority(sid.as_ptr() as *mut _, sub_auth as u32)
}

/// Wraps GetSidSubAuthority
///
/// # Requirements
///
/// The `Sid` structure *must* have enough sub authorities. This is *not* checked
/// by this function. Accessing a higher index is undefined behavior.
#[allow(non_snake_case)]
pub unsafe fn GetSidSubAuthorityMut(sid: &mut Sid, sub_auth: u8) -> *mut u32 {
    winapi::um::securitybaseapi::GetSidSubAuthority(sid.as_ptr() as *mut _, sub_auth as u32)
}

/// Checks to ensure that the input SID has enough sub-authorities to defend
/// against undefined behavior.
#[allow(non_snake_case)]
pub fn GetSidSubAuthorityChecked(sid: &Sid, sub_auth: u8) -> Option<u32> {
    if wrappers::GetSidSubAuthorityCount(sid) > sub_auth {
        Some(unsafe { *GetSidSubAuthority(sid, sub_auth) })
    } else {
        None
    }
}

/// Checks to ensure that the input SID has enough sub-authorities to defend
/// against undefined behavior.
#[allow(non_snake_case)]
pub fn GetSidSubAuthorityCheckedMut(sid: &mut Sid, sub_auth: u8) -> Option<&mut u32> {
    if wrappers::GetSidSubAuthorityCount(sid) > sub_auth {
        Some(unsafe { &mut *GetSidSubAuthorityMut(sid, sub_auth) })
    } else {
        None
    }
}
