use crate::Acl;

/// Wraps [`IsValidAcl`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-isvalidacl)
#[allow(non_snake_case)]
pub fn IsValidAcl(acl: &Acl) -> bool {
    (unsafe { windows_sys::Win32::Security::IsValidAcl(acl as *const _ as *mut _) }) != 0
}
