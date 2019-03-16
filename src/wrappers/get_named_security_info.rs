use crate::constants::{SeObjectType, SecurityInformation};
use crate::utilities::buf_from_os;
use crate::LocallyOwnedSecurityDescriptor;
use std::ffi::OsStr;
use std::io;
use std::ptr::{null_mut, NonNull};
use winapi::shared::winerror::ERROR_SUCCESS;

/// Wraps GetNamedSecurityInfoW
#[allow(non_snake_case)]
pub fn GetNamedSecurityInfo(
    name: &OsStr,
    obj_type: SeObjectType,
    sec_info: SecurityInformation,
) -> io::Result<LocallyOwnedSecurityDescriptor> {
    let name = buf_from_os(name);

    let mut sd = null_mut();

    let result_code = unsafe {
        winapi::um::aclapi::GetNamedSecurityInfoW(
            name.as_ptr(),
            obj_type as u32,
            sec_info.bits(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        )
    };

    if result_code != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result_code as i32));
    }

    let sd = NonNull::new(sd).expect("GetNamedSecurityInfoW reported success but returned null");

    Ok(unsafe { LocallyOwnedSecurityDescriptor::owned_from_nonnull(sd) })
}
