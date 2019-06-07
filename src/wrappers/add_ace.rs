use crate::{Ace, Acl};
use std::io;

/// Wraps `AddAce`
///
/// This always uses the ACL_REVISION_DS revision, which should be compatible
/// with all modern ACLs.
#[allow(non_snake_case)]
pub fn AddAce(acl: &mut Acl, index: u32, ace: &Ace) -> io::Result<()> {
    let result = unsafe {
        winapi::um::securitybaseapi::AddAce(
            acl as *mut _ as *mut _,
            winapi::um::winnt::ACL_REVISION_DS as u32, // Only handles new-style ACLs
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
