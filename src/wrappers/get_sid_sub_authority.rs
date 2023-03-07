use crate::wrappers;
use crate::Sid;

/// Wraps [`GetSidSubAuthority`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsidsubauthority).
///
/// For a checked version, use [`GetSidSubAuthorityChecked`].
///
/// # Safety
///
/// The `Sid` structure *must* have enough sub authorities. This is *not* checked
/// by this function. Accessing a higher index is undefined behavior.
///
/// ```
/// use windows_permissions::{Sid, wrappers::GetSidSubAuthority};
///
/// let sid = Sid::new([1, 2, 3, 4, 5, 6], &[1, 2]).unwrap();
///
/// unsafe {
///     assert_eq!(*GetSidSubAuthority(&sid, 0), 1);
///     assert_eq!(*GetSidSubAuthority(&sid, 1), 2);
/// }
///
/// // Do not do this! This is undefined behavior!
/// // assert_eq!(GetSidSubAuthority(&sid, 2), None);
/// ```
#[allow(non_snake_case)]
pub unsafe fn GetSidSubAuthority(sid: &Sid, sub_auth: u8) -> *mut u32 {
    windows_sys::Win32::Security::GetSidSubAuthority(sid as *const _ as *mut _, sub_auth as u32)
}

/// Wraps [`GetSidSubAuthority`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsidsubauthority)
/// with a runtime check.
///
/// Checks to ensure that the input SID has enough sub-authorities to defend
/// against undefined behavior. To skip the check, use
/// [`GetSidSubAuthorityChecked`].
///
/// ```
/// use windows_permissions::{Sid, wrappers::GetSidSubAuthorityChecked};
///
/// let sid = Sid::new([1, 2, 3, 4, 5, 6], &[1, 2]).unwrap();
///
/// assert_eq!(GetSidSubAuthorityChecked(&sid, 0), Some(1));
/// assert_eq!(GetSidSubAuthorityChecked(&sid, 1), Some(2));
/// assert_eq!(GetSidSubAuthorityChecked(&sid, 2), None);
/// ```
#[allow(non_snake_case)]
pub fn GetSidSubAuthorityChecked(sid: &Sid, sub_auth: u8) -> Option<u32> {
    if wrappers::GetSidSubAuthorityCount(sid) > sub_auth {
        Some(unsafe { *GetSidSubAuthority(sid, sub_auth) })
    } else {
        None
    }
}
