use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

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
pub fn buf_from_os(os: &OsStr) -> Vec<u16> {
    let mut buf: Vec<u16> = os.encode_wide().collect();
    buf.push(0);
    buf
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
}
