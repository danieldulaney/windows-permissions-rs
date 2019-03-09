use crate::{SecurityDescriptor, Sid};
use winapi::ctypes::c_void;
use std::io;
use std::ptr::{NonNull, null_mut};

/// Wraps GetSecurityDescriptorOwner
#[allow(non_snake_case)]
pub fn GetSecurityDescriptorOwner(sd: &SecurityDescriptor) -> io::Result<Option<&Sid>> {
    let mut sid_ptr: *mut c_void = null_mut();
    let mut _sid_default: i32 = 0;

    let result = unsafe {
        winapi::um::securitybaseapi::GetSecurityDescriptorOwner(
            sd.as_ptr(),
            &mut sid_ptr,
            &mut _sid_default,
        )
    };

    if result != 0 {
        // Failed
        return Err(io::Error::last_os_error());
    }

    Ok(NonNull::new(sid_ptr).map(|p| unsafe { Sid::ref_from_nonnull(&p) }))
}
