use crate::utilities;
use crate::Trustee;
use std::ffi::OsStr;

/// Wraps [`BuildTrusteeWithNameW`](https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-buildtrusteewithnamew)
#[allow(non_snake_case)]
#[allow(clippy::needless_lifetimes)]
pub fn BuildTrusteeWithName<'s>(name_buf: &'s [u16]) -> Trustee<'s> {
    let mut trustee = unsafe { Trustee::allocate() };

    unsafe {
        windows_sys::Win32::Security::Authorization::BuildTrusteeWithNameW(
            trustee.as_mut_ptr(),
            name_buf.as_ptr() as *mut _,
        );
    }

    trustee
}

/// Copies the `OsStr` into WTF-16 before creating the `Trustee`.
#[allow(non_snake_case)]
pub fn BuildTrusteeWithNameOsStr(name: &OsStr) -> Trustee<'static> {
    // Convert name into a static WTF-16 buffer
    let buffer: &'static [u16] = Box::leak(utilities::buf_from_os(name).into_boxed_slice());

    BuildTrusteeWithName(buffer)
}
