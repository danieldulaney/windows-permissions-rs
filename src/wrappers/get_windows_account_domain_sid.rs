use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;

use crate::{wrappers, LocalBox, Sid};
use std::io;

/// Wraps [`GetWindowsAccountDomainSid`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getwindowsaccountdomainsid)
#[allow(non_snake_case)]
pub fn GetWindowsAccountDomainSid(sid: &Sid) -> io::Result<LocalBox<Sid>> {
    // 24 bytes is a typical size on x64
    // Will reallocate if larger size is needed
    let mut len: u32 = 24;
    let mut buffer;

    loop {
        buffer = vec![0; len as usize];

        let result = unsafe {
            windows_sys::Win32::Security::GetWindowsAccountDomainSid(
                sid as *const _ as *mut _,
                buffer.as_mut_ptr() as *mut _,
                &mut len,
            )
        };

        if result != 0 {
            // Success
            break;
        }

        let error = io::Error::last_os_error();

        if error.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            // Try again; len is set to the correct value by the API call
            continue;
        }

        return Err(error);
    }

    let sid_ref: &Sid = unsafe { &*(buffer.as_ptr() as *const _) };

    wrappers::CopySid(sid_ref)
}

#[cfg(test)]
mod test {
    use windows_sys::Win32::Foundation::ERROR_NON_ACCOUNT_SID;

    use super::*;

    use crate::utilities;

    #[test]
    fn current_process_has_domain() {
        assert!(GetWindowsAccountDomainSid(&utilities::current_process_sid().unwrap()).is_ok());
    }

    #[test]
    fn well_known_sid_has_no_domain() {
        assert_eq!(
            GetWindowsAccountDomainSid(
                &Sid::well_known_sid(windows_sys::Win32::Security::WinWorldSid).unwrap()
            )
            .unwrap_err()
            .raw_os_error(),
            Some(ERROR_NON_ACCOUNT_SID as i32)
        );
    }
}
