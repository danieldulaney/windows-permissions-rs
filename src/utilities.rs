use crate::{wrappers, LocalBox, Sid};
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr::{null, null_mut};
use winapi::um::winnt::{HANDLE, TOKEN_USER};

/// Create an `OsString` from a NUL-terminated buffer
///
/// Decodes the WTF-16 encoded buffer until it hits a NUL (code point 0).
/// Everything after and including that code point is not included.
///
/// ```
/// use std::ffi::OsString;
/// use windows_permissions::utilities::os_from_buf;
///
/// let buf = vec![0x0054, 0x0065, 0x0073, 0x0074, 0x0000, 0x0000];
///
/// assert_eq!(os_from_buf(&buf), OsString::from("Test"));
/// ```
pub fn os_from_buf(buf: &[u16]) -> OsString {
    OsString::from_wide(
        &buf.iter()
            .cloned()
            .take_while(|&n| n != 0)
            .collect::<Vec<u16>>(),
    )
}

/// Create a WTF-16-encoded NUL-terminated buffer from an `OsStr`.
///
/// Decodes the `OsStr`, then appends a NUL.
///
/// ```
/// use std::ffi::OsString;
/// use windows_permissions::utilities::buf_from_os;
///
/// let os = OsString::from("Test");
/// assert_eq!(buf_from_os(&os), vec![0x0054, 0x0065, 0x0073, 0x0074, 0x0000]);
/// ```
pub fn buf_from_os<S: AsRef<OsStr> + ?Sized>(os: &S) -> Vec<u16> {
    let mut buf: Vec<u16> = os.as_ref().encode_wide().collect();
    buf.push(0);
    buf
}

/// Unsafely hunt through memory until an item is found
///
/// This is mostly used when a WinAPI function allocates a nul-terminated
/// buffer of `u16`s. Use this to find the location of the nul, then use
/// `std::slice::from_raw_parts` to build a slice.
///
/// ## Assumptions
///
/// This function assumes that:
/// - `haystack` points to an aligned buffer of `T`s
/// - There is a `needle` somewhere in `haystack`
/// - Every value in `haystack` can be dereferenced
///
/// ```
/// use windows_permissions::utilities::{search_buffer, buf_from_os};
/// use std::ffi::OsString;
///
/// let items = ['H' as u16, 'e' as u16, 'l' as u16, 'l' as u16, 'o' as u16, 0x00, 0xBA, 0xDD];
/// let ptr = items.as_ptr();
///
/// let position = unsafe { search_buffer(&0x00, ptr) };
/// let valid_items = unsafe { std::slice::from_raw_parts(ptr, position + 1) };
///
/// assert_eq!(position, 5);
/// assert_eq!(valid_items, &buf_from_os(&OsString::from("Hello"))[..]);
/// ```
pub unsafe fn search_buffer<T: PartialEq>(needle: &T, haystack: *const T) -> usize {
    let mut position = 0usize;

    while *haystack.offset(position as isize) != *needle {
        position += 1;
    }

    position
}

/// Check whether a given bitfield has a particular bit set
///
/// ```
/// use windows_permissions::utilities::has_bit;
///
/// let a = 0x01;
/// let b = 0x02;
/// let c = 0x04;
///
/// let abc = a | b | c;
/// let ab = a | b;
///
/// assert!(has_bit(abc, a));
/// assert!(has_bit(abc, b));
/// assert!(has_bit(abc, c));
///
/// assert!(has_bit(ab, a));
/// assert!(has_bit(ab, b));
/// assert!(!has_bit(ab, c));
///
/// assert!(!has_bit(0x00, a));
/// ```
pub fn has_bit(field: u32, bit: u32) -> bool {
    field & bit != 0
}

/// Get a pointer from an option
///
/// Returns null if the option is `None`.
///
/// ```
/// use windows_permissions::utilities::ptr_from_opt;
/// use std::ptr::null;
///
/// let five: u32 = 5;
///
/// let some = Some(&five);
/// let none: Option<&u32> = None;
///
/// assert_eq!(ptr_from_opt(some), &five);
/// assert_eq!(ptr_from_opt(none), null());
/// ```
pub fn ptr_from_opt<T>(opt: Option<&T>) -> *const T {
    match opt {
        Some(inner) => inner,
        None => null(),
    }
}

/// Get the user SID of the current process
pub fn current_process_sid() -> io::Result<LocalBox<Sid>> {
    let mut process_token: HANDLE = null_mut();

    // process_token must not be used until return value is checked
    // process_token must be closed if return value is nonzero
    let result = unsafe {
        winapi::um::processthreadsapi::OpenProcessToken(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            winapi::um::winnt::TOKEN_QUERY,
            &mut process_token,
        )
    };

    if result == 0 {
        // Failed; no need for cleanup
        return Err(io::Error::last_os_error());
    }

    // Experimentation suggests that 44 bytes is the normal space required on
    // x64. Will automatically reallocate later if that's not enough
    let mut len = 44u32;
    let mut token_info;

    loop {
        token_info = vec![0u8; len as usize];

        dbg!(len);

        let result = unsafe {
            winapi::um::securitybaseapi::GetTokenInformation(
                process_token,
                winapi::um::winnt::TokenUser,
                token_info.as_mut_ptr() as *mut _,
                len.clone(),
                &mut len,
            )
        };

        if result != 0 {
            // Success!
            dbg!(&token_info);
            break;
        } else {
            // Save off the error code before CloseHandle in case CloseHandle has
            // its own error
            let error_code = io::Error::last_os_error();

            // If we got error code 122, try again
            // len was updated to the new size by the API call
            if error_code.raw_os_error()
                == Some(winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER as i32)
            {
                continue;
            }

            unsafe { winapi::um::handleapi::CloseHandle(process_token) };

            return Err(error_code);
        }
    }

    dbg!(&token_info);

    // Read from the inside out:
    // - Raw pointer to the start of the Vec<u8> underlying buffer
    // - Cast to a TOKEN_USER pointer
    // - Dereferenced to a TOKEN_USER
    // - Get the User field (type SID_AND_ATTRIBUTES)
    // - Get the Sid field (a void pointer, but we know it's a Sid pointer)
    // - Cast it to a Sid raw pointer
    // - Dereference that to a Sid
    // - Take the reference as a safe &Sid
    let sid_ref = unsafe { &*((*(token_info.as_ptr() as *const TOKEN_USER)).User.Sid as *mut Sid) };

    let sid_copy = wrappers::CopySid(sid_ref);

    unsafe {
        winapi::um::handleapi::CloseHandle(process_token);
    }

    sid_copy
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn round_trip() {
        let basic_os = OsString::from("TeSt");
        let basic_buf = vec![0x54, 0x65, 0x53, 0x74, 0x00];
        let basic_buf_nuls = vec![0x54, 0x65, 0x53, 0x74, 0x00, 0x00, 0x00, 0x00];

        assert_eq!(os_from_buf(&basic_buf), basic_os);
        assert_eq!(buf_from_os(&basic_os), basic_buf);
        assert_eq!(os_from_buf(&basic_buf_nuls), basic_os);

        let unicode_os = OsString::from("💩");
        let unicode_buf = vec![0xd83d, 0xdca9, 0x0];
        let unicode_buf_nuls = vec![0xd83d, 0xdca9, 0x0, 0x0, 0x0, 0x0, 0x0];

        assert_eq!(os_from_buf(&unicode_buf), unicode_os);
        assert_eq!(buf_from_os(&unicode_os), unicode_buf);
        assert_eq!(os_from_buf(&unicode_buf_nuls), unicode_os);
    }

    #[test]
    fn got_a_sid_for_the_current_process() {
        assert!(current_process_sid().is_ok());
    }
}
