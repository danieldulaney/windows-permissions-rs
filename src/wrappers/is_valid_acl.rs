use crate::Acl;

/// Wraps IsValidAcl
#[allow(non_snake_case)]
pub fn IsValidAcl(acl: &Acl) -> bool {
    (unsafe { winapi::um::securitybaseapi::IsValidAcl(acl as *const _ as *mut _) }) != 0
}
