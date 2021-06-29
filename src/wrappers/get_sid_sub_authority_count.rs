use crate::Sid;

/// Wraps [`GetSidSubAuthorityCount`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsidsubauthoritycount).
///
/// ```
/// use windows_permissions::{Sid, LocalBox};
///
/// let sid1: LocalBox<Sid> = "S-1-5-1".parse().unwrap();
/// let sid2: LocalBox<Sid> = "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15".parse().unwrap();
///
/// assert_eq!(sid1.sub_authority_count(), 1);
/// assert_eq!(sid2.sub_authority_count(), 15);
/// ```
#[allow(non_snake_case)]
pub fn GetSidSubAuthorityCount(sid: &Sid) -> u8 {
    unsafe { *winapi::um::securitybaseapi::GetSidSubAuthorityCount(sid as *const _ as *mut _) }
}
