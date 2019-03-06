use crate::{Sid, Trustee};

/// Wraps BuildTrusteeWithSidW
#[allow(non_snake_case)]
pub fn BuildTrusteeWithSid<'s>(sid: &'s Sid) -> Trustee<'s> {
    // Trustee must be initialized before return
    let mut trustee = unsafe { Trustee::allocate() };

    unsafe {
        winapi::um::aclapi::BuildTrusteeWithSidW(trustee.as_mut_ptr(), sid.as_ptr() as *mut _)
    }

    trustee
}
