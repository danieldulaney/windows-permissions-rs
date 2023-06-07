use std::{
    ffi::{OsStr, OsString},
    io,
    ptr::null,
};

use windows_sys::Win32::Security::{LookupAccountNameW, SID_NAME_USE};

use crate::{
    constants::SidNameUse,
    utilities::{buf_from_os, os_from_buf},
    LocalBox, Sid,
};

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
/// use windows_sys::Win32::Security::WinWorldSid;
///
/// // A well-known SID
/// let (sid, _, name_use) = LookupAccountName(Option::<&OsStr>::None, "Everyone").unwrap();
/// let win_world_sid = Sid::well_known_sid(WinWorldSid).unwrap();
///
/// assert_eq!(Box::as_ref(&sid), win_world_sid.as_ref());
/// assert_eq!(name_use, SidNameUse::SidTypeWellKnownGroup);
/// ```
#[allow(non_snake_case)]
pub fn LookupAccountName(
    system_name: Option<impl AsRef<OsStr>>,
    account_name: impl AsRef<OsStr>,
) -> io::Result<(LocalBox<Sid>, OsString, SidNameUse)> {
    // Convert the system name and account name into buffers
    let system_name = system_name.map(|s| buf_from_os(s.as_ref()));
    let account_name = buf_from_os(account_name.as_ref());

    // Convert the system name to a pointer, defaulting to null
    let system_name_ptr = match system_name {
        Some(ref b) => b.as_ptr(),
        None => null(),
    };
    let mut sid_len: u32 = 0;
    let mut ref_dom_name_len: u32 = 0;
    let mut sid_name_use: SID_NAME_USE = 0;

    unsafe {
        LookupAccountNameW(
            system_name_ptr,
            account_name.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_len,
            std::ptr::null_mut(),
            &mut ref_dom_name_len,
            &mut sid_name_use,
        )
    };

    let (sid, mut ref_dom_name_buf) = if sid_len != 0 && ref_dom_name_len != 0 {
        (
            unsafe { LocalBox::<Sid>::try_allocate(true, sid_len as usize)? },
            vec![0u16; ref_dom_name_len as usize],
        )
    } else {
        return Err(io::Error::last_os_error());
    };

    let result = unsafe {
        LookupAccountNameW(
            system_name_ptr,
            account_name.as_ptr(),
            sid.as_ptr() as *mut _,
            &mut sid_len,
            ref_dom_name_buf.as_mut_ptr(),
            &mut ref_dom_name_len,
            &mut sid_name_use,
        )
    };

    if result != 0 {
        // Success! Return the appropriate values, converting as necessary

        // Convert the referenced domain name into an OsString
        let ref_dom_name = os_from_buf(&ref_dom_name_buf);

        // Figure out SidNameUse
        let sid_name_use = SidNameUse::from_raw(sid_name_use).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "LookupAccountNameW returned unrecognized SidNameUse variant {:?}",
                    sid_name_use
                ),
            )
        })?;

        Ok((sid, ref_dom_name, sid_name_use))
    } else {
        // Failure! We're not recovering
        Err(io::Error::last_os_error())
    }
}
