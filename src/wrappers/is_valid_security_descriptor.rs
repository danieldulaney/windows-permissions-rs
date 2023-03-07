use crate::SecurityDescriptor;

/// Wraps [`IsValidSecurityDescriptor`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-isvalidsecuritydescriptor)
#[allow(non_snake_case)]
pub fn IsValidSecurityDescriptor(sd: &SecurityDescriptor) -> bool {
    (unsafe { windows_sys::Win32::Security::IsValidSecurityDescriptor(sd as *const _ as *mut _) })
        != 0
}
