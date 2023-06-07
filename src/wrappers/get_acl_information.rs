use windows_sys::Win32::Security::ACL_SIZE_INFORMATION;

use crate::Acl;
use std::io;

/// Wraps [`GetAclInformation`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getaclinformation)
///
/// Always uses [`ACL_SIZE_INFORMATION`](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-acl_size_information) as the information class.
#[allow(non_snake_case)]
pub fn GetAclInformationSize(acl: &Acl) -> io::Result<ACL_SIZE_INFORMATION> {
    debug_assert!(crate::wrappers::IsValidAcl(acl));

    let mut info = ACL_SIZE_INFORMATION {
        AceCount: 0xDEADBEEF,
        AclBytesInUse: 0xDEADBEEF,
        AclBytesFree: 0xDEADBEEF,
    };

    let info_size = std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32;

    let result = unsafe {
        windows_sys::Win32::Security::GetAclInformation(
            acl as *const _ as *mut _,
            &mut info as *mut _ as *mut _,
            info_size,
            windows_sys::Win32::Security::AclSizeInformation,
        )
    };

    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        debug_assert!(info.AceCount != 0xDEADBEEF);
        debug_assert!(info.AclBytesInUse != 0xDEADBEEF);
        debug_assert!(info.AclBytesFree != 0xDEADBEEF);
        Ok(info)
    }
}
