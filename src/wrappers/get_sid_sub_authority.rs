use crate::wrappers;
use crate::Sid;

/// Wraps [`GetSidSubAuthority`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsidsubauthority)
///
/// For a checked version, use [`GetSidSubAuthorityChecked`].
///
/// # Safety
///
/// The `Sid` structure *must* have enough sub authorities. This is *not* checked
/// by this function. Accessing a higher index is undefined behavior.
#[allow(non_snake_case)]
pub unsafe fn GetSidSubAuthority(sid: &Sid, sub_auth: u8) -> *mut u32 {
    winapi::um::securitybaseapi::GetSidSubAuthority(sid as *const _ as *mut _, sub_auth as u32)
}

/// Wraps [`GetSidSubAuthority`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsidsubauthority)
/// with a runtime check.
///
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
