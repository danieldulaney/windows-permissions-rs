use crate::{Acl, SecurityDescriptor};
use std::io;
use std::ptr::null_mut;
use winapi::um::winnt::PACL;

/// Wraps GetSecurityDescriptorDacl
#[allow(non_snake_case)]
pub fn GetSecurityDescriptorDacl(sd: &SecurityDescriptor) -> io::Result<Option<&Acl>> {
    let mut present = 0i32;
    let mut acl_ptr: PACL = null_mut();
    let mut defaulted = 0i32;

    let result = unsafe {
        winapi::um::securitybaseapi::GetSecurityDescriptorDacl(
            sd.as_ptr(),
            &mut present,
            &mut acl_ptr,
            &mut defaulted,
        )
    };

    if result == 0 {
        // Failed
        Err(io::Error::last_os_error())
    } else {
        if present == 0 {
            // Not present
            Ok(None)
        } else {
            // Present
            Ok(Some(unsafe { Acl::ref_from_ptr(&acl_ptr) }))
        }
    }
}

/// Wraps GetSecurityDescriptorSacl
#[allow(non_snake_case)]
pub fn GetSecurityDescriptorSacl(sd: &SecurityDescriptor) -> io::Result<Option<&Acl>> {
    let mut present = 0i32;
    let mut acl_ptr: PACL = null_mut();
    let mut defaulted = 0i32;

    let result = unsafe {
        winapi::um::securitybaseapi::GetSecurityDescriptorSacl(
            sd.as_ptr(),
            &mut present,
            &mut acl_ptr,
            &mut defaulted,
        )
    };

    if result == 0 {
        // Failed
        Err(io::Error::last_os_error())
    } else {
        if present == 0 {
            // Not present
            Ok(None)
        } else {
            // Present
            Ok(Some(unsafe { Acl::ref_from_ptr(&acl_ptr) }))
        }
    }
}
