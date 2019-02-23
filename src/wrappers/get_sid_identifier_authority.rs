use crate::Sid;

/// Wraps GetSidIdentifierAuthority
#[allow(non_snake_case)]
pub fn GetSidIdentifierAuthority(sid: &Sid) -> &[u8; 6] {
    let ptr =
        unsafe { &*winapi::um::securitybaseapi::GetSidIdentifierAuthority(sid.as_ptr() as *mut _) };
    &ptr.Value
}
