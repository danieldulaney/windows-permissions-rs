use crate::constants::{SeObjectType, SecurityInformation};
use crate::{wrappers, Acl, Sid};
use std::ffi::{OsStr, OsString};
use std::io;
use std::ptr::NonNull;
use std::str::FromStr;
use winapi::ctypes::c_void;

#[derive(Debug)]
pub struct SecurityDescriptor {
    inner: NonNull<c_void>,
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe { winapi::um::winbase::LocalFree(self.inner.as_ptr() as *mut _) };
    }
}

impl SecurityDescriptor {
    /// Construct a security descriptor from raw parts
    ///
    /// ## Assumptions
    ///
    /// - `sd` points to a valid security descriptor and should be freed with
    ///   `LocalFree`
    pub unsafe fn owned_from_nonnull(ptr: NonNull<c_void>) -> SecurityDescriptor {
        Self { inner: ptr }
    }

    pub fn validate(&self) -> Result<(), io::Error> {
        if let Some(o) = self.owner() {
            wrappers::IsValidSid(o)?;
        }

        if let Some(g) = self.group() {
            wrappers::IsValidSid(g)?;
        }

        Ok(())
    }

    pub fn as_ptr(&self) -> *mut c_void {
        self.inner.as_ptr() as *mut _
    }

    /// Get the `SecurityDescriptor` for a file at a given path
    ///
    /// This is a direct call to `wrappers::GetNamedSecurityInfo` with some
    /// default parameters. For more options (such as fetching a partial
    /// descriptor, or getting descriptors for other objects), call that method
    /// directly.
    pub fn lookup_file<S: AsRef<OsStr> + ?Sized>(
        path: &S,
    ) -> Result<SecurityDescriptor, io::Error> {
        wrappers::GetNamedSecurityInfo(
            path.as_ref(),
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::Owner | SecurityInformation::Group,
        )
    }

    /// Get the Security Descriptor Definition Language (SDDL) string
    /// corresponding to this `SecurityDescriptor`
    ///
    /// This function attempts to get the entire SDDL string using
    /// `SecurityInformation::all()`. To get a portion of the SDDL, use
    /// `wrappers::ConvertSecurityDescriptorToStringSecurityDescriptor`
    /// directly.
    pub fn as_sddl(&self) -> io::Result<OsString> {
        wrappers::ConvertSecurityDescriptorToStringSecurityDescriptor(
            self,
            SecurityInformation::all(),
        )
    }

    /// Get the owner SID if it exists
    pub fn owner(&self) -> Option<&Sid> {
        unimplemented!()
    }

    /// Get the group SID if it exists
    pub fn group(&self) -> Option<&Sid> {
        unimplemented!()
    }

    /// Get the DACL if it exists
    pub fn dacl(&self) -> Option<&Acl> {
        unimplemented!()
    }

    /// Get the SACL if it exists
    pub fn sacl(&self) -> Option<&Acl> {
        unimplemented!()
    }
}

impl FromStr for SecurityDescriptor {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        wrappers::ConvertStringSecurityDescriptorToSecurityDescriptor(s)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static SDDL_TEST_CASES: &[(&str, &str, &str)] = &[
        ("", "", ""),
        ("O:AOG:DA", "AO", "DA"),
    ];

    fn sddl_test_cases() -> io::Result<impl Iterator<Item=(String, Option<Sid>, Option<Sid>)>> {
        let parse_if_there = |s: &str| {
            if s.is_empty() {
                None
            } else {
                dbg!(s);
                Some(s.parse().unwrap())
            }
        };

        Ok(SDDL_TEST_CASES.iter()
            .map(move |(sddl, own, grp)| {
                (sddl.to_string(), parse_if_there(own), parse_if_there(grp))
            }))
    }

    #[test]
    fn sddl_round_trip() -> io::Result<()>{
        Ok(())
    }
}
