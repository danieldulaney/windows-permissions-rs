use crate::{Ace, Acl};
use std::io;

/// Wraps [`AddAce`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-addace)
///
/// This always uses the `ACL_REVISION_DS` revision, which should be
/// compatible with all modern ACLs.
#[allow(non_snake_case)]
pub fn AddAce(acl: &mut Acl, index: u32, ace: &Ace) -> io::Result<()> {
    let result = unsafe {
        windows_sys::Win32::Security::AddAce(
            acl as *mut _ as *mut _,
            windows_sys::Win32::Security::ACL_REVISION_DS,
            index,
            ace as *const _ as *mut _,
            1, // Just one in the list
        )
    };

    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
