use crate::constants::{SeObjectType, SecurityInformation};
use crate::{LocalBox, SecurityDescriptor};
use std::io;
use std::os::windows::io::AsRawHandle;
use std::ptr::{null_mut, NonNull};
use winapi::shared::winerror::ERROR_SUCCESS;

/// Wraps `GetSecurityInfo`
///
/// ## Panics
///
/// Panics if the underlying call reports success but yields a null pointer.
#[allow(non_snake_case)]
pub fn GetSecurityInfo<H: AsRawHandle>(
    handle: &H,
    obj_type: SeObjectType,
    sec_info: SecurityInformation,
) -> io::Result<LocalBox<SecurityDescriptor>> {
    let mut sd = null_mut();

    let result_code = unsafe {
        winapi::um::aclapi::GetSecurityInfo(
            handle.as_raw_handle() as *mut _,
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

    let sd =
        NonNull::new(sd as *mut _).expect("GetSecurityInfo reported success but returned null");

    Ok(unsafe { LocalBox::from_raw(sd) })
}
