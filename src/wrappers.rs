pub use get_named_security_info::GetNamedSecurityInfo;
pub use lookup_account_sid::LookupAccountSid;

const BUFFER_SIZE: u32 = 256;

mod lookup_account_sid {
    use super::BUFFER_SIZE;
    use crate::utilities::os_from_buf;
    use crate::Sid;
    use std::ffi::OsString;
    use std::ptr::{null, null_mut};
    use windows_error::WindowsError;

    /// Wraps LookupAccountSidW
    ///
    /// Returns (name, domain)
    pub fn LookupAccountSid(sid: &mut Sid) -> Result<(OsString, OsString), WindowsError> {
        let mut name_size = BUFFER_SIZE;
        let mut dom_size = BUFFER_SIZE;

        loop {
            let old_name_size = name_size;
            let old_dom_size = dom_size;

            let mut name: Vec<u16> = vec![0; name_size as usize];
            let mut dom: Vec<u16> = vec![0; dom_size as usize];

            let result = unsafe {
                winapi::um::winbase::LookupAccountSidW(
                    null(),
                    sid as *mut Sid as *mut _,
                    name.as_mut_ptr(),
                    &mut name_size,
                    dom.as_mut_ptr(),
                    &mut dom_size,
                    null_mut(),
                )
            };

            if result != 0 {
                // Success: Return the filled buffers as OsStrings
                return Ok((os_from_buf(&name), os_from_buf(&dom)));
            } else if name_size != old_name_size || dom_size != old_dom_size {
                // Failed, but requests new allocation: try again
                continue;
            } else {
                // Failed, with no new allocation request
                return Err(WindowsError::from_last_err());
            }
        }
    }
}

mod get_named_security_info {
    use crate::utilities::{buf_from_os, has_bit};
    use crate::SecurityDescriptor;
    use std::ffi::OsStr;
    use std::ptr::null_mut;
    use winapi::shared::winerror::ERROR_SUCCESS;
    use winapi::um::winnt::{self, PACL, PSECURITY_DESCRIPTOR, PSID};
    use windows_error::WindowsError;

    /// Wraps GetNamedSecurityInfoW
    #[allow(non_snake_case)]
    pub fn GetNamedSecurityInfo(
        name: &OsStr,
        obj_type: u32,
        sec_info: u32,
    ) -> Result<SecurityDescriptor, WindowsError> {
        let name = buf_from_os(name);

        let mut owner: PSID = null_mut();
        let mut group: PSID = null_mut();
        let mut dacl: PACL = null_mut();
        let mut sacl: PACL = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();

        let result: WindowsError = unsafe {
            winapi::um::aclapi::GetNamedSecurityInfoW(
                name.as_ptr(),
                obj_type,
                sec_info,
                &mut owner,
                &mut group,
                &mut dacl,
                &mut sacl,
                &mut sd,
            )
        }
        .into();

        if result != ERROR_SUCCESS {
            return Err(result);
        }

        let owner = if has_bit(sec_info, winnt::OWNER_SECURITY_INFORMATION) {
            owner
        } else {
            null_mut()
        };

        let group = if has_bit(sec_info, winnt::GROUP_SECURITY_INFORMATION) {
            group
        } else {
            null_mut()
        };

        let dacl = if has_bit(sec_info, winnt::DACL_SECURITY_INFORMATION) {
            dacl
        } else {
            null_mut()
        };

        let sacl = if has_bit(sec_info, winnt::SACL_SECURITY_INFORMATION) {
            sacl
        } else {
            null_mut()
        };

        Ok(unsafe { SecurityDescriptor::from_raw(sd, owner, group, dacl, sacl) })
    }
}
