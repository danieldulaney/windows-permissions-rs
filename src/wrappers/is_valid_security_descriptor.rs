use crate::SecurityDescriptor;

/// Wraps [`IsValidSecurityDescriptor`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-isvalidsecuritydescriptor)
#[allow(non_snake_case)]
pub fn IsValidSecurityDescriptor(sd: &SecurityDescriptor) -> bool {
    (unsafe { winapi::um::securitybaseapi::IsValidSecurityDescriptor(sd as *const _ as *mut _) })
        != 0
}
