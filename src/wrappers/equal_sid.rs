use crate::Sid;

/// Wraps [`EqualSid`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-equalsid)
///
/// Because `&Sid` is a safe Rust construct, it must be valid. Therefore, it is
/// impossible for this function to error.
#[allow(non_snake_case)]
pub fn EqualSid(sid1: &Sid, sid2: &Sid) -> bool {
    (unsafe {
        winapi::um::securitybaseapi::EqualSid(
            sid1 as *const _ as *mut _,
            sid2 as *const _ as *mut _,
        )
    } != 0)
}
