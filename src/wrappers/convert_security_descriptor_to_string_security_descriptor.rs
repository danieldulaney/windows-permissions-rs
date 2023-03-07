use crate::constants::SecurityInformation;
use crate::utilities;
use crate::SecurityDescriptor;
use std::ffi::OsString;
use std::io;
use std::ptr::null_mut;
use std::slice;

/// Wraps [`ConvertSecurityDescriptorToStringSecurityDescriptorW`](https://docs.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsecuritydescriptortostringsecuritydescriptorw)
///
/// This always uses `SDDL_REVISION_1` as the SDDL revision.
///
/// It may be more convenient to use [`SecurityDescriptor::as_sddl`] when all
/// security information is needed.
///
/// ```
/// use windows_permissions::wrappers::ConvertSecurityDescriptorToStringSecurityDescriptor;
/// use windows_permissions::{constants::SecurityInformation, LocalBox, SecurityDescriptor};
///
/// let string_sd = "G:S-1-5-10-20";
/// let sd: LocalBox<SecurityDescriptor> = string_sd.parse().unwrap();
///
/// let string_sd2 = ConvertSecurityDescriptorToStringSecurityDescriptor(
///     &sd,
///     SecurityInformation::all()
/// ).unwrap();
///
/// assert_eq!(string_sd, &string_sd2);
/// ```
#[allow(non_snake_case)]
pub fn ConvertSecurityDescriptorToStringSecurityDescriptor(
    sd: &SecurityDescriptor,
    info: SecurityInformation,
) -> io::Result<OsString> {
    let mut buf_ptr: *mut u16 = null_mut();
    let mut buf_len: u32 = 0;

    // If success, buf_ptr must be LocalFree'd
    let result = unsafe {
        windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd as *const _ as *mut _,
            windows_sys::Win32::Security::Authorization::SDDL_REVISION_1.into(),
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

    unsafe { windows_sys::Win32::System::Memory::LocalFree(buf_ptr as *mut _ as isize) };

    Ok(string)
}
