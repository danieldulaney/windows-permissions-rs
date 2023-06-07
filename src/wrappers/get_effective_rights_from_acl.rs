use crate::{constants::AccessRights, Acl, Trustee};
use std::io;

/// Wraps [`GetEffectiveRightsFromAclW`](https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-geteffectiverightsfromaclw)
#[allow(non_snake_case)]
pub fn GetEffectiveRightsFromAcl(acl: &Acl, trustee: &Trustee) -> Result<AccessRights, io::Error> {
    debug_assert!(crate::wrappers::IsValidAcl(acl));

    let mut acc_mask = 0u32;

    let result = unsafe {
        windows_sys::Win32::Security::Authorization::GetEffectiveRightsFromAclW(
            acl as *const _ as *mut _,
            trustee as *const _ as *mut _,
            &mut acc_mask,
        )
    };

    if result == windows_sys::Win32::Foundation::ERROR_SUCCESS {
        Ok(AccessRights::from_bits_truncate(acc_mask))
    } else {
        Err(io::Error::from_raw_os_error(result as i32))
    }
}
