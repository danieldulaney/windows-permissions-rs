use crate::Sid;

/// Wraps [`EqualSid`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-equalsid).
///
/// Because `&Sid` is a safe Rust construct, it must be valid. Therefore, it is
/// impossible for this function to error.
///
/// ```
/// use windows_permissions::{Sid, LocalBox, wrappers::EqualSid};
/// use winapi::um::winnt::WinCreatorGroupSid;
///
/// let sid1: LocalBox<Sid> = "S-1-3-1".parse().unwrap();
/// let sid2 = Sid::well_known_sid(WinCreatorGroupSid).unwrap();
///
/// let sid3 = Sid::new([0, 0, 0, 0, 0, 3], &[2]).unwrap();
///
/// assert!(EqualSid(&sid1, &sid2));
/// assert!(!EqualSid(&sid1, &sid3));
/// ```
#[allow(non_snake_case)]
pub fn EqualSid(sid1: &Sid, sid2: &Sid) -> bool {
    (unsafe {
        winapi::um::securitybaseapi::EqualSid(
            sid1 as *const _ as *mut _,
            sid2 as *const _ as *mut _,
        )
    } != 0)
}
