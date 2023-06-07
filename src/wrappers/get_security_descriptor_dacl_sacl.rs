use windows_sys::Win32::Security::ACL;

use crate::{wrappers, Acl, SecurityDescriptor};
use std::io;
use std::ptr::null_mut;

macro_rules! get_security_descriptor_acl {
    ($f:ident; msdn: $msdn:expr) => {
        get_security_descriptor_acl!(@ $f, concat!("Wraps [`", stringify!($f), "`](", $msdn, ")"));
    };
    (@ $f:ident, $doc:expr) => {
        #[doc = $doc]
        #[allow(non_snake_case)]
        pub fn $f(sd: &SecurityDescriptor) -> io::Result<Option<&Acl>> {
            let mut present = 0i32;
            let mut acl_ptr: *mut ACL = null_mut();
            let mut defaulted = 0i32;

            let result = unsafe {
                windows_sys::Win32::Security::$f(
                    sd as *const _ as *mut _,
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
                    let acl = unsafe {
                        if acl_ptr.is_null() {
                            panic!("$f indicated success but returned NULL");
                        } else {
                            &*(acl_ptr as *const _)
                        }
                    };

                    debug_assert!(wrappers::IsValidAcl(acl));

                    Ok(Some(acl))
                }
            }
        }
    };
}

get_security_descriptor_acl!(GetSecurityDescriptorDacl;
    msdn: "https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsecuritydescriptordacl");

get_security_descriptor_acl!(GetSecurityDescriptorSacl;
    msdn: "https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsecuritydescriptorsacl");
