use crate::{utilities, LocalBox, SecurityDescriptor};
use std::ffi::OsStr;
use std::io;
use std::ptr::{null_mut, NonNull};

/// Wraps [`ConvertStringSecurityDescriptorToSecurityDescriptorW`](https://docs.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertstringsecuritydescriptortosecuritydescriptorw)
///
/// Always uses `SDDL_REVISION_1`
#[allow(non_snake_case)]
pub fn ConvertStringSecurityDescriptorToSecurityDescriptor<S: AsRef<OsStr> + ?Sized>(
    string: &S,
) -> io::Result<LocalBox<SecurityDescriptor>> {
    let buffer = utilities::buf_from_os(string);
    let mut sd_ptr = null_mut();

    let result = unsafe {
        winapi::shared::sddl::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            buffer.as_ptr(),
            winapi::shared::sddl::SDDL_REVISION_1.into(),
            &mut sd_ptr,
            null_mut(),
        )
    };

    if result == 0 {
        // Failed
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe {
        let ptr = NonNull::new(sd_ptr as *mut _)
            .expect("ConvertStringSecurityDescriptorToSecurityDescriptorW reported success but returned null");
        LocalBox::from_raw(ptr)
    })
}
