use crate::{Ace, Acl};
use std::io;
use std::ptr::{null_mut, NonNull};

/// Wraps [`GetAce`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getace)
///
/// Requests beyond the last ACE will have the same behavior as the underlying
/// WinAPI call. Experimentation suggests OS error code 87,
/// (`ERROR_INVALID_PARAMETER`, "The parameter is incorrect") but that is not
/// documented.
#[allow(non_snake_case)]
pub fn GetAce(acl: &Acl, index: u32) -> io::Result<&Ace> {
    debug_assert!(crate::wrappers::IsValidAcl(acl));

    let mut ace = null_mut();

    let result =
        unsafe { windows_sys::Win32::Security::GetAce(acl as *const _ as *mut _, index, &mut ace) };

    if result == 0 {
        // Failed
        Err(io::Error::last_os_error())
    } else {
        let ace = NonNull::new(ace as *mut _).expect("GetAce reported success but returned null");
        Ok(unsafe { Ace::ref_from_nonnull(ace) })
    }
}
