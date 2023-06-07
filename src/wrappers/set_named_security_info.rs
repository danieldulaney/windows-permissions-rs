use windows_sys::Win32::Foundation::ERROR_SUCCESS;

use crate::constants::{SeObjectType, SecurityInformation};
use crate::utilities::{buf_from_os, ptr_from_opt};
use crate::{Acl, Sid};
use std::ffi::OsStr;
use std::io;

/// Wraps [`SetNamedSecurityInfoW`](https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow)
#[allow(non_snake_case)]
pub fn SetNamedSecurityInfo<S: AsRef<OsStr> + ?Sized>(
    name: &S,
    obj_type: SeObjectType,
    sec_info: SecurityInformation,
    owner: Option<&Sid>,
    group: Option<&Sid>,
    dacl: Option<&Acl>,
    sacl: Option<&Acl>,
) -> io::Result<()> {
    let name = buf_from_os(name);

    let result_code = unsafe {
        windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW(
            name.as_ptr() as *mut _,
            obj_type as _,
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
