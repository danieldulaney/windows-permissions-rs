use crate::Sid;
use std::io;
use std::ptr::{null_mut, NonNull};

/// Wraps AllocateAndInitializeSid
///
/// Only the first 8 sub-authorities are considered.
#[allow(non_snake_case)]
pub fn AllocateAndInitializeSid(id_auth: [u8; 6], sub_auths: &[u32]) -> Result<Sid, io::Error> {
    let mut ptr = null_mut();

    let sa_0 = if sub_auths.len() > 0 { sub_auths[0] } else { 0 };
    let sa_1 = if sub_auths.len() > 1 { sub_auths[1] } else { 0 };
    let sa_2 = if sub_auths.len() > 2 { sub_auths[2] } else { 0 };
    let sa_3 = if sub_auths.len() > 3 { sub_auths[3] } else { 0 };
    let sa_4 = if sub_auths.len() > 4 { sub_auths[4] } else { 0 };
    let sa_5 = if sub_auths.len() > 5 { sub_auths[5] } else { 0 };
    let sa_6 = if sub_auths.len() > 6 { sub_auths[6] } else { 0 };
    let sa_7 = if sub_auths.len() > 7 { sub_auths[7] } else { 0 };

    let result = unsafe {
        winapi::um::securitybaseapi::AllocateAndInitializeSid(
            &mut winapi::um::winnt::SID_IDENTIFIER_AUTHORITY { Value: id_auth },
            sub_auths.len() as u8,
            sa_0,
            sa_1,
            sa_2,
            sa_3,
            sa_4,
            sa_5,
            sa_6,
            sa_7,
            &mut ptr,
        )
    };

    if result != 0 {
        // Success
        let nonnull =
            NonNull::new(ptr).expect("AllocateAndInitializeSid reported success but returned null");
        Ok(unsafe { Sid::owned_from_nonnull(nonnull) })
    } else {
        // Failure
        Err(io::Error::last_os_error())
    }
}
