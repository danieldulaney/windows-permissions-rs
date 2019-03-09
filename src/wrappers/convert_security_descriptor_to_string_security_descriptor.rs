use crate::constants::SecurityInformation;
use crate::utilities;
use crate::SecurityDescriptor;
use std::ffi::OsString;
use std::io;
use std::ptr::null_mut;
use std::slice;

/// Wraps ConvertSecurityDescriptorToStringSecurityDescriptorW
///
/// This always uses `SDDL_REVISION_1` as the SDDL revision.
#[allow(non_snake_case)]
pub fn ConvertSecurityDescriptorToStringSecurityDescriptor(
    sd: &SecurityDescriptor,
    info: SecurityInformation,
) -> io::Result<OsString> {
    let mut buf_ptr: *mut u16 = null_mut();
    let mut buf_len: u32 = 0;

    // If success, buf_ptr must be LocalFree'd
    let result = unsafe {
        winapi::shared::sddl::ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd.as_ptr(),
            winapi::shared::sddl::SDDL_REVISION_1.into(),
            info.bits(),
            &mut buf_ptr,
            &mut buf_len,
        )
    };

    if result == 0 {
        // Failed, no need to free
        return Err(io::Error::last_os_error());
    }

    let slice = unsafe { slice::from_raw_parts(buf_ptr, buf_len as usize) };

    let string = utilities::os_from_buf(slice);

    unsafe { winapi::um::winbase::LocalFree(buf_ptr as *mut _) };

    Ok(string)
}
