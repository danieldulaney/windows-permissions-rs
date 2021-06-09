use std::{
    ffi::{OsStr, OsString},
    io,
    ptr::null,
};

use winapi::um::{
    winbase::LookupAccountNameW,
    winnt::{SID_NAME_USE, WCHAR},
};

use crate::{
    constants::SidNameUse,
    utilities::{buf_from_os, os_from_buf},
    Sid,
};

// Initial buffer size to use
// If this isn't big enough, we'll try again
const BUFFER_SIZE: usize = 256;

// If we have to retry more than this many times, panic
const MAX_RETRIES: usize = 5;

/// Wraps [`LookupAccountNameW`](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountnamew)
///
/// Returns SID, referenced domain name, and use in that order.
///
/// ```
/// # use windows_permissions::wrappers::LookupAccountName;
/// # use windows_permissions::constants::SidNameUse;
/// # use windows_permissions::Sid;
/// # use std::ffi::OsStr;
/// #
/// // A well-known SID
/// let (sid, _, name_use) = LookupAccountName(Option::<&OsStr>::None, "Everyone").unwrap();
/// let win_world_sid = Sid::well_known_sid(winapi::um::winnt::WinWorldSid).unwrap();
///
/// assert_eq!(Box::as_ref(&sid), win_world_sid.as_ref());
/// assert_eq!(name_use, SidNameUse::SidTypeWellKnownGroup);
/// ```
#[allow(non_snake_case)]
pub fn LookupAccountName(
    system_name: Option<impl AsRef<OsStr>>,
    account_name: impl AsRef<OsStr>,
) -> io::Result<(Box<Sid>, OsString, SidNameUse)> {
    // Buffers to hold the SID itself, the DOM name, and the SID name use
    let mut sid_buf: Vec<u8> = vec![0; BUFFER_SIZE];
    let mut ref_dom_name_buf: Vec<WCHAR> = vec![0; BUFFER_SIZE];
    let mut sid_name_use: SID_NAME_USE = 0;

    // Convert the system name and account name into buffers
    let system_name = system_name.map(|s| buf_from_os(s.as_ref()));
    let account_name = buf_from_os(account_name.as_ref());

    let mut retry_counter = 0;

    loop {
        // Increment the retry counter
        retry_counter += 1;

        // If the retry counter passes its threshold, we panic
        assert!(
            retry_counter <= MAX_RETRIES,
            "LookupAccountName retried too many times"
        );

        // Get the current length
        let mut sid_len: u32 = sid_buf.len() as u32;
        let mut ref_dom_name_len: u32 = ref_dom_name_buf.len() as u32;

        // Convert the system name to a pointer, defaulting to null
        let system_name_ptr = match system_name {
            Some(ref b) => b.as_ptr(),
            None => null(),
        };

        // Save the original values
        // If the call fails
        let orig_sid_len = sid_len;
        let orig_ref_dom_name_len = ref_dom_name_len;

        let result = unsafe {
            LookupAccountNameW(
                system_name_ptr,
                account_name.as_ptr(),
                sid_buf.as_mut_ptr() as *mut _,
                &mut sid_len,
                ref_dom_name_buf.as_mut_ptr(),
                &mut ref_dom_name_len,
                &mut sid_name_use,
            )
        };

        if result != 0 {
            // Success! Return the appropriate values, converting as necessary

            // Resize the SID buffer based on the SID length and convert to a Box
            sid_buf.truncate(sid_len as usize);
            let sid_box = sid_buf.into_boxed_slice();
            let sid = unsafe { Box::from_raw(Box::into_raw(sid_box) as *mut Sid) };

            // Convert the referenced domain name into an OsString
            let ref_dom_name = os_from_buf(&mut ref_dom_name_buf);

            // Figure out SidNameUse
            let sid_name_use = SidNameUse::from_raw(sid_name_use).unwrap_or_else(|| {
                panic!(
                    "LookupAccountNameW returned unrecognized SidNameUse variant {:?}",
                    sid_name_use
                )
            });

            break Ok((sid, ref_dom_name, sid_name_use));
        } else if sid_len != orig_sid_len || ref_dom_name_len != orig_ref_dom_name_len {
            // Failure! They indicated a reallocation requirement

            // Resize both the SID buffer and the referenced domain name buffer based
            // on the indicated correct sizes
            sid_buf.resize(sid_len as usize, 0);
            ref_dom_name_buf.resize(ref_dom_name_len as usize, 0);
        } else {
            // Failure! We're not recovering
            break Err(io::Error::last_os_error());
        }
    }
}
