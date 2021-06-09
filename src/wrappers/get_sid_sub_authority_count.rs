use crate::Sid;

/// Wraps [`GetSidSubAuthorityCount`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsidsubauthoritycount)
#[allow(non_snake_case)]
pub fn GetSidSubAuthorityCount(sid: &Sid) -> u8 {
    unsafe { *winapi::um::securitybaseapi::GetSidSubAuthorityCount(sid as *const _ as *mut _) }
}
