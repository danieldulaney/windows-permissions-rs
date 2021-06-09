use crate::constants::{SeObjectType, SecurityInformation};
use crate::utilities::buf_from_os;
use crate::{LocalBox, SecurityDescriptor};
use std::ffi::OsStr;
use std::io;
use std::ptr::{null_mut, NonNull};
use winapi::shared::winerror::ERROR_SUCCESS;

/// Wraps [`GetNamedSecurityInfoW`](https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow)
///
/// ## Panics
///
/// Panics if the underlying call reports success but yields a null pointer.
#[allow(non_snake_case)]
pub fn GetNamedSecurityInfo<S: AsRef<OsStr> + ?Sized>(
    name: &S,
    obj_type: SeObjectType,
    sec_info: SecurityInformation,
) -> io::Result<LocalBox<SecurityDescriptor>> {
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

    let sd = NonNull::new(sd as *mut _)
        .expect("GetNamedSecurityInfoW reported success but returned null");

    Ok(unsafe { LocalBox::from_raw(sd) })
}
