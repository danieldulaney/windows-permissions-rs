use crate::Acl;
use winapi::um::winnt::ACL_SIZE_INFORMATION;
use std::io;

/// Wraps GetAclInformation using ACL_SIZE_INFORMATION as the information class
#[allow(non_snake_case)]
pub fn GetAclInformationSize(acl: &Acl) -> io::Result<ACL_SIZE_INFORMATION> {
    let mut info = ACL_SIZE_INFORMATION {
        AceCount: 0xDEADBEEF,
        AclBytesInUse: 0xDEADBEEF,
        AclBytesFree: 0xDEADBEEF,
    };

    let info_size = std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32;

    let result = unsafe {
        winapi::um::securitybaseapi::GetAclInformation(
            acl.as_ptr() as *mut _,
            &mut info as *mut _ as *mut _,
            info_size,
            winapi::um::winnt::AclSizeInformation,
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
