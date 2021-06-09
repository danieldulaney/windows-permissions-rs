use crate::Sid;

/// Wraps [`GetSidIdentifierAuthority`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsididentifierauthority)
#[allow(non_snake_case)]
pub fn GetSidIdentifierAuthority(sid: &Sid) -> &[u8; 6] {
    let ptr = unsafe {
        &*winapi::um::securitybaseapi::GetSidIdentifierAuthority(sid as *const _ as *mut _)
    };
    &ptr.Value
}
