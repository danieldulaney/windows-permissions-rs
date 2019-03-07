use crate::constants::{SeObjectType, SecurityInformation};
use crate::utilities::buf_from_os;
use crate::SecurityDescriptor;
use std::ffi::OsStr;
use std::io;
use std::ptr::null_mut;
use winapi::shared::winerror::ERROR_SUCCESS;
use winapi::um::winnt::{PACL, PSECURITY_DESCRIPTOR, PSID};

/// Wraps GetNamedSecurityInfoW
#[allow(non_snake_case)]
pub fn GetNamedSecurityInfo(
    name: &OsStr,
    obj_type: SeObjectType,
    sec_info: SecurityInformation,
) -> Result<SecurityDescriptor, io::Error> {
    let name = buf_from_os(name);

    let mut owner: PSID = null_mut();
    let mut group: PSID = null_mut();
    let mut dacl: PACL = null_mut();
    let mut sacl: PACL = null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();

    let result_code = unsafe {
        winapi::um::aclapi::GetNamedSecurityInfoW(
            name.as_ptr(),
            obj_type as u32,
            sec_info.bits(),
            &mut owner,
            &mut group,
            &mut dacl,
            &mut sacl,
            &mut sd,
        )
    };

    if result_code != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result_code as i32));
    }

    let owner = if sec_info.contains(SecurityInformation::Owner) {
        owner
    } else {
        null_mut()
    };

    let group = if sec_info.contains(SecurityInformation::Group) {
        group
    } else {
        null_mut()
    };

    let dacl = if sec_info.contains(SecurityInformation::Dacl) {
        dacl
    } else {
        null_mut()
    };

    let sacl = if sec_info.contains(SecurityInformation::Sacl) {
        sacl
    } else {
        null_mut()
    };

    Ok(unsafe { SecurityDescriptor::from_raw(sd, owner, group, dacl, sacl) })
}
