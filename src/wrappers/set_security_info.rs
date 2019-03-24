use crate::constants::{SeObjectType, SecurityInformation};
use crate::utilities::ptr_from_opt;
use crate::{Acl, Sid};
use std::io;
use std::os::windows::io::AsRawHandle;
use winapi::shared::winerror::ERROR_SUCCESS;

/// Wraps `SetSecurityInfo`
///
/// The flags set in `sec_info` determines what parameters are set; others are
/// ignored following the semantics laid out in the WinAPI docs.
#[allow(non_snake_case)]
pub fn SetSecurityInfo<H: AsRawHandle>(
    handle: &mut H,
    obj_type: SeObjectType,
    sec_info: SecurityInformation,
    owner: Option<&Sid>,
    group: Option<&Sid>,
    dacl: Option<&Acl>,
    sacl: Option<&Acl>,
) -> io::Result<()> {
    let result_code = unsafe {
        winapi::um::aclapi::SetSecurityInfo(
            handle.as_raw_handle(),
            obj_type as u32,
            sec_info.bits(),
            ptr_from_opt(owner) as *mut _,
            ptr_from_opt(group) as *mut _,
            ptr_from_opt(dacl) as *mut _,
            ptr_from_opt(sacl) as *mut _,
        )
    };

    if result_code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result_code as i32))
    }
}
