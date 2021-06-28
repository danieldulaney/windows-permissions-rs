use crate::{Sid, Trustee};

/// Wraps [`BuildTrusteeWithSidW`](https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-buildtrusteewithsidw)
#[allow(non_snake_case)]
#[allow(clippy::needless_lifetimes)]
pub fn BuildTrusteeWithSid<'s>(sid: &'s Sid) -> Trustee<'s> {
    // Trustee must be initialized before return
    let mut trustee = unsafe { Trustee::allocate() };

    unsafe {
        winapi::um::aclapi::BuildTrusteeWithSidW(trustee.as_mut_ptr(), sid as *const _ as *mut _)
    }

    trustee
}
