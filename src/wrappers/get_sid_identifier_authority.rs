use crate::Sid;

/// Wraps [`GetSidIdentifierAuthority`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsididentifierauthority).
///
/// ```
/// use windows_permissions::{Sid, wrappers::GetSidIdentifierAuthority};
///
/// let id_auth: [u8; 6] = *b"Hello!";
/// let sid = Sid::new(id_auth, &[1, 2, 3]).unwrap();
///
/// assert_eq!(&id_auth, GetSidIdentifierAuthority(&sid));
/// ```
#[allow(non_snake_case)]
pub fn GetSidIdentifierAuthority(sid: &Sid) -> &[u8; 6] {
    let ptr = unsafe {
        &*winapi::um::securitybaseapi::GetSidIdentifierAuthority(sid as *const _ as *mut _)
    };
    &ptr.Value
}
