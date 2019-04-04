use crate::{constants::AccessRights, Acl, Trustee};
use std::io;

/// Wraps GetEffectiveRightsFromAclW
#[allow(non_snake_case)]
pub fn GetEffectiveRightsFromAcl(acl: &Acl, trustee: &Trustee) -> Result<AccessRights, io::Error> {
    debug_assert!(crate::wrappers::IsValidAcl(acl));

    let mut acc_mask = 0u32;

    let result = unsafe {
        winapi::um::aclapi::GetEffectiveRightsFromAclW(
            acl as *const _ as *mut _,
            trustee as *const _ as *mut _,
            &mut acc_mask,
        )
    };

    if result == winapi::shared::winerror::ERROR_SUCCESS {
        Ok(AccessRights::from_bits_truncate(acc_mask))
    } else {
        Err(io::Error::from_raw_os_error(result as i32))
    }
}
