use crate::{LocalBox, Sid};
use std::io;
use std::ptr::{null_mut, NonNull};

/// Wraps [`AllocateAndInitializeSid`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-allocateandinitializesid).
///
/// ```
/// use windows_permissions::wrappers::AllocateAndInitializeSid;
///
/// let sid = AllocateAndInitializeSid([1, 2, 3, 4, 5, 6], &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
///
/// assert_eq!(sid.id_authority(), &[1, 2, 3, 4, 5, 6]);
/// assert_eq!(sid.sub_authority_count(), 8);
/// assert_eq!(sid.sub_authorities(), &[1, 2, 3, 4, 5, 6, 7, 8]);
/// ```
///
/// This is wrapped by [`Sid::new`], which has identical behavior.
///
/// ```
/// use windows_permissions::{Sid, wrappers::AllocateAndInitializeSid};
///
/// let sid = AllocateAndInitializeSid([1, 2, 3, 4, 5, 6], &[1, 2]).unwrap();
/// let sid2 = Sid::new([1, 2, 3, 4, 5, 6], &[1, 2]).unwrap();
///
/// assert_eq!(sid, sid2);
/// ```
///
/// Only the first 8 sub-authorities are considered. If sub_auths is empty, returns
/// an error with `io::ErrorKind` of `InvalidData`. This is a workaround for
/// the WinAPI behavior, which is to silently return an invalid SID with no
/// sub-authorities. *Some* functions will handle it correctly, but lots (such
/// as `ConvertStringSidToSid`) will error.
///
/// ```
/// use windows_permissions::wrappers::AllocateAndInitializeSid;
/// use std::io::ErrorKind;
///
/// let error = AllocateAndInitializeSid([1, 2, 3, 4, 5, 6], &[]);
/// assert_eq!(error.unwrap_err().kind(), ErrorKind::InvalidInput);
/// ```
#[allow(non_snake_case)]
pub fn AllocateAndInitializeSid(id_auth: [u8; 6], sub_auths: &[u32]) -> io::Result<LocalBox<Sid>> {
    if sub_auths.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "AllocateAndInitializeSid called with 0 sub_auths",
        ));
    }

    let mut ptr = null_mut();

    #[allow(clippy::len_zero)]
    let sa_0 = if sub_auths.len() > 0 { sub_auths[0] } else { 0 };
    let sa_1 = if sub_auths.len() > 1 { sub_auths[1] } else { 0 };
    let sa_2 = if sub_auths.len() > 2 { sub_auths[2] } else { 0 };
    let sa_3 = if sub_auths.len() > 3 { sub_auths[3] } else { 0 };
    let sa_4 = if sub_auths.len() > 4 { sub_auths[4] } else { 0 };
    let sa_5 = if sub_auths.len() > 5 { sub_auths[5] } else { 0 };
    let sa_6 = if sub_auths.len() > 6 { sub_auths[6] } else { 0 };
    let sa_7 = if sub_auths.len() > 7 { sub_auths[7] } else { 0 };

    let result = unsafe {
        windows_sys::Win32::Security::AllocateAndInitializeSid(
            &mut windows_sys::Win32::Security::SID_IDENTIFIER_AUTHORITY { Value: id_auth },
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
        let nonnull = NonNull::new(ptr as *mut _)
            .expect("AllocateAndInitializeSid reported success but returned null");
        Ok(unsafe { LocalBox::from_raw(nonnull) })
    } else {
        // Failure
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_num_sub_auths() {
        let id_auth = [0xBAu8, 0xD5, 0x1D, 0xBA, 0xD5, 0x1D];

        assert_eq!(
            AllocateAndInitializeSid(id_auth.clone(), &[])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
