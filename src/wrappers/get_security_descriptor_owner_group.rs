use crate::{SecurityDescriptor, Sid};
use std::io;
use std::ptr::{null_mut, NonNull};
use winapi::ctypes::c_void;

/// Wraps GetSecurityDescriptorOwner
#[allow(non_snake_case)]
pub fn GetSecurityDescriptorOwner(sd: &SecurityDescriptor) -> io::Result<Option<&Sid>> {
    let mut sid_ptr: *mut c_void = null_mut();
    let mut _sid_default: i32 = 0;

    let result = unsafe {
        winapi::um::securitybaseapi::GetSecurityDescriptorOwner(
            sd as *const _ as *mut _,
            &mut sid_ptr,
            &mut _sid_default,
        )
    };

    if result == 0 {
        // Failed
        return Err(io::Error::last_os_error());
    }

    Ok(NonNull::new(sid_ptr).map(|p| unsafe { Sid::ref_from_nonnull(p) }))
}

/// Wraps GetSecurityDescriptorGroup
#[allow(non_snake_case)]
pub fn GetSecurityDescriptorGroup(sd: &SecurityDescriptor) -> io::Result<Option<&Sid>> {
    let mut sid_ptr: *mut c_void = null_mut();
    let mut _sid_default: i32 = 0;

    let result = unsafe {
        winapi::um::securitybaseapi::GetSecurityDescriptorGroup(
            sd as *const _ as *mut _,
            &mut sid_ptr,
            &mut _sid_default,
        )
    };

    if result == 0 {
        // Failed
        return Err(io::Error::last_os_error());
    }

    Ok(NonNull::new(sid_ptr).map(|p| unsafe { Sid::ref_from_nonnull(p) }))
}
