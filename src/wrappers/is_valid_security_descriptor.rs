use crate::SecurityDescriptor;

/// Wraps IsValidSecurityDescriptor
#[allow(non_snake_case)]
pub fn IsValidSecurityDescriptor(sd: &SecurityDescriptor) -> bool {
    (unsafe { winapi::um::securitybaseapi::IsValidSecurityDescriptor(sd.as_ptr()) }) != 0
}
