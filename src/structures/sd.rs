use crate::constants::{SeObjectType, SecurityInformation};
use crate::{wrappers, Acl, Sid};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::ops::Deref;
use std::ptr::NonNull;
use std::str::FromStr;
use winapi::ctypes::c_void;
use winapi::um::winnt::SECURITY_DESCRIPTOR;

pub struct SecurityDescriptor {
    _inner: SECURITY_DESCRIPTOR,
}

pub struct LocallyOwnedSecurityDescriptor {
    ptr: NonNull<c_void>,
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unreachable!("SecurityDescriptor should only be borrowed, not owned")
    }
}

impl Drop for LocallyOwnedSecurityDescriptor {
    fn drop(&mut self) {
        debug_assert!(wrappers::IsValidSecurityDescriptor(&self));
        unsafe { winapi::um::winbase::LocalFree(self.ptr.as_ptr() as *mut _) };
    }
}

impl LocallyOwnedSecurityDescriptor {
    /// Construct a security descriptor from raw parts
    ///
    /// ## Assumptions
    ///
    /// - `sd` points to a valid security descriptor and should be freed with
    ///   `LocalFree`
    pub unsafe fn owned_from_nonnull(ptr: NonNull<c_void>) -> LocallyOwnedSecurityDescriptor {
        let sd = Self { ptr };
        debug_assert!(wrappers::IsValidSecurityDescriptor(&sd));
        sd
    }

    /// Get a pointer to the underlying security descriptor
    pub fn as_ptr(&self) -> *mut c_void {
        self.ptr.as_ptr() as *mut _
    }

    /// Get the security descriptor for a file at a given path
    ///
    /// This is a direct call to `wrappers::GetNamedSecurityInfo` with some
    /// default parameters. For more options (such as fetching a partial
    /// descriptor, or getting descriptors for other objects), call that method
    /// directly.
    pub fn lookup_file<S: AsRef<OsStr> + ?Sized>(
        path: &S,
    ) -> Result<LocallyOwnedSecurityDescriptor, io::Error> {
        wrappers::GetNamedSecurityInfo(
            path.as_ref(),
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::Owner | SecurityInformation::Group,
        )
    }
}

impl SecurityDescriptor {
    pub unsafe fn ref_from_nonnull<'s>(ptr: NonNull<c_void>) -> &'s Self {
        let sd_ref = std::mem::transmute::<NonNull<c_void>, &Self>(ptr);
        debug_assert!(wrappers::IsValidSecurityDescriptor(sd_ref));
        sd_ref
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
        wrappers::GetSecurityDescriptorOwner(self)
            .expect("Valid SecurityDescriptor failed to get owner")
    }

    /// Get the group SID if it exists
    pub fn group(&self) -> Option<&Sid> {
        wrappers::GetSecurityDescriptorGroup(self)
            .expect("Valid SecurityDescriptor failed to get group")
    }

    /// Get the DACL if it exists
    pub fn dacl(&self) -> Option<&Acl> {
        wrappers::GetSecurityDescriptorDacl(self)
            .expect("Valid SecurityDescriptor failed to get dacl")
    }

    /// Get the SACL if it exists
    pub fn sacl(&self) -> Option<&Acl> {
        wrappers::GetSecurityDescriptorSacl(self)
            .expect("Valid SecurityDescriptor failed to get sacl")
    }
}

impl fmt::Debug for SecurityDescriptor {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_map()
            .entry(&"sddl", &self.as_sddl().unwrap())
            .finish()
    }
}

impl fmt::Debug for LocallyOwnedSecurityDescriptor {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.deref().fmt(fmt)
    }
}

impl FromStr for LocallyOwnedSecurityDescriptor {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        wrappers::ConvertStringSecurityDescriptorToSecurityDescriptor(s)
    }
}

impl Deref for LocallyOwnedSecurityDescriptor {
    type Target = SecurityDescriptor;

    fn deref(&self) -> &Self::Target {
        unsafe { SecurityDescriptor::ref_from_nonnull(self.ptr) }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::LocallyOwnedSid;

    static SDDL_TEST_CASES: &[(&str, &str, &str)] = &[
        ("", "", ""),
        ("O:AOG:SY", "AO", "SY"),
        ("O:SU", "SU", ""),
        ("G:SI", "", "SI"),
        ("O:AOG:SYD:S:", "AO", "SY"),
    ];

    fn assert_option_eq(lhs: Option<&Sid>, rhs: Option<&LocallyOwnedSid>) {
        match (lhs, rhs) {
            (None, None) => (),
            (Some(_), None) => panic!("Assertion failed: {:?} == {:?}", lhs, rhs),
            (None, Some(_)) => panic!("Assertion failed: {:?} == {:?}", lhs, rhs),
            (Some(l), Some(r)) => assert_eq!(l, r),
        }
    }

    fn sddl_test_cases(
    ) -> impl Iterator<Item = (String, Option<LocallyOwnedSid>, Option<LocallyOwnedSid>)> {
        let parse_if_there = |s: &str| {
            if s.is_empty() {
                None
            } else {
                Some(s.parse().unwrap())
            }
        };

        SDDL_TEST_CASES.iter().map(move |(sddl, own, grp)| {
            (sddl.to_string(), parse_if_there(own), parse_if_there(grp))
        })
    }

    #[test]
    fn sddl_get_sids() -> io::Result<()> {
        for (sddl, owner, group) in sddl_test_cases() {
            let sd: LocallyOwnedSecurityDescriptor = sddl.parse()?;

            assert_option_eq(sd.owner(), owner.as_ref());
            assert_option_eq(sd.group(), group.as_ref());
        }

        Ok(())
    }

    #[test]
    fn sddl_round_trip() -> io::Result<()> {
        for (sddl, _, _) in sddl_test_cases() {
            let sd: LocallyOwnedSecurityDescriptor = sddl.parse()?;
            let sddl2 = sd.as_sddl()?;

            assert_eq!(OsStr::new(&sddl), &sddl2);
        }

        Ok(())
    }

    #[test]
    fn sddl_missing_acls() -> io::Result<()> {
        let sd: LocallyOwnedSecurityDescriptor = "O:LAG:AO".parse()?;
        assert!(sd.dacl().is_none());
        assert!(sd.sacl().is_none());

        let sd: LocallyOwnedSecurityDescriptor = "O:LAG:AOD:".parse()?;
        assert!(sd.dacl().is_some());
        assert!(sd.sacl().is_none());

        let sd: LocallyOwnedSecurityDescriptor = "O:LAG:AOS:".parse()?;
        assert!(sd.dacl().is_none());
        assert!(sd.sacl().is_some());

        let sd: LocallyOwnedSecurityDescriptor = "O:LAG:AOD:S:".parse()?;
        assert!(sd.dacl().is_some());
        assert!(sd.sacl().is_some());

        Ok(())
    }
}
