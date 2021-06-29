use crate::{wrappers, LocalBox, Sid};
use std::io;

/// Wraps [`CopySid`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-copysid)
///
/// When using a `LocalBox<Sid>`, it can sometimes be easier to use
/// [`LocalBox<Sid>::clone`].
///
/// ```
/// use windows_permissions::{wrappers::CopySid, Sid};
/// use winapi::um::winnt::WinBuiltinAdministratorsSid;
///
/// let original = Sid::well_known_sid(WinBuiltinAdministratorsSid).unwrap();
///
/// // Copy with CopySid
/// let copy = CopySid(&original).unwrap();
/// assert_eq!(&original, &copy);
///
/// // Copy with LocalBox<Sid>::clone
/// let copy2 = original.clone();
/// assert_eq!(&original, &copy2);
/// ```
#[allow(non_snake_case)]
pub fn CopySid(sid: &Sid) -> io::Result<LocalBox<Sid>> {
    let size = wrappers::GetSidLengthRequired(wrappers::GetSidSubAuthorityCount(sid));

    let new_sid: LocalBox<Sid> = unsafe { LocalBox::try_allocate(true, size)? };

    let success = unsafe {
        winapi::um::securitybaseapi::CopySid(
            size as u32,
            new_sid.as_ptr() as *mut _,
            sid as *const _ as *mut _,
        )
    };

    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(new_sid)
    }
}
