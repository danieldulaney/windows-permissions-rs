use crate::{wrappers, LocalBox, Sid};
use std::io;
use winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER;

/// Wraps `GetWindowsAccountDomainSid`
#[allow(non_snake_case)]
pub fn GetWindowsAccountDomainSid(sid: &Sid) -> io::Result<LocalBox<Sid>> {
    // 24 bytes is a typical size on x64
    // Will reallocate if larger size is needed
    let mut len: u32 = 24;
    let mut buffer;

    loop {
        buffer = vec![0; len as usize];

        let result = unsafe {
            winapi::um::securitybaseapi::GetWindowsAccountDomainSid(
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
    use super::*;

    use crate::utilities;
    use winapi::shared::winerror::ERROR_NON_ACCOUNT_SID;

    #[test]
    fn current_process_has_domain() {
        assert!(GetWindowsAccountDomainSid(&utilities::current_process_sid().unwrap()).is_ok());
    }

    #[test]
    fn well_known_sid_has_no_domain() {
        assert_eq!(
            GetWindowsAccountDomainSid(
                &Sid::well_known_sid(winapi::um::winnt::WinWorldSid).unwrap()
            )
            .unwrap_err()
            .raw_os_error(),
            Some(ERROR_NON_ACCOUNT_SID as i32)
        );
    }
}
