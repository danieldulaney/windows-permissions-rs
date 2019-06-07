use crate::{constants, wrappers, Ace, Trustee};
use std::fmt;
use std::io;
use winapi::shared::winerror::ERROR_INVALID_PARAMETER;
use winapi::um::winnt::ACL;

/// An access control list (ACL).
#[repr(C)]
pub struct Acl {
    _opaque: [u8; 0],
}

impl Acl {
    fn internal_type_reference(&self) -> &ACL {
        unsafe { &*(self as *const _ as *const _) }
    }

    /// Determine what rights the given `Trustee` has under this ACL
    ///
    /// ```
    /// use windows_permissions::{LocalBox, Trustee, Sid, SecurityDescriptor};
    /// use windows_permissions::constants::AccessRights;
    ///
    /// // Allow a particular user FA (File All) and give all users FR (File Read)
    /// let sd = "D:(A;;FA;;;S-1-5-20-12345)(A;;FR;;;WD)"
    ///     .parse::<LocalBox<SecurityDescriptor>>().unwrap();
    /// let acl = sd.dacl().unwrap();
    ///
    /// let sid1: LocalBox<Sid> = "S-1-5-20-12345".parse().unwrap();
    /// let sid2: LocalBox<Sid> = "WD".parse().unwrap();
    ///
    /// let trustee1: Trustee = sid1.as_ref().into();
    /// let trustee2: Trustee = sid2.as_ref().into();
    ///
    /// assert_eq!(acl.effective_rights(&trustee1).unwrap(), AccessRights::FileAllAccess);
    /// assert_eq!(acl.effective_rights(&trustee2).unwrap(), AccessRights::FileGenericRead);
    /// ```
    pub fn effective_rights(&self, trustee: &Trustee) -> io::Result<constants::AccessRights> {
        wrappers::GetEffectiveRightsFromAcl(self, trustee)
    }

    /// Determine the number of ACEs in this ACL
    ///
    /// ```
    /// use windows_permissions::{LocalBox, SecurityDescriptor};
    ///
    /// let sd = "D:(A;;GA;;;S-1-5-20-12345)(A;;GR;;;WD)"
    ///     .parse::<LocalBox<SecurityDescriptor>>().unwrap();
    ///
    /// assert_eq!(sd.dacl().unwrap().len(), 2);
    /// ```
    pub fn len(&self) -> u32 {
        wrappers::GetAclInformationSize(self)
            .expect("GetAclInformation failed on valid ACL")
            .AceCount
    }

    /// Get an ACE by index
    ///
    /// Returns `None` if there are too few ACEs to satisfy the request.
    ///
    /// ```
    /// use windows_permissions::{LocalBox, Sid, SecurityDescriptor};
    /// use windows_permissions::constants::{AceType::*, AccessRights};
    ///
    /// let sd = "D:(A;;GA;;;S-1-5-20-12345)(A;;GR;;;WD)"
    ///     .parse::<LocalBox<SecurityDescriptor>>().unwrap();
    /// let acl = sd.dacl().unwrap();
    ///
    /// let sid1: LocalBox<Sid> = "S-1-5-20-12345".parse().unwrap();
    /// let sid2: LocalBox<Sid> = "WD".parse().unwrap();
    ///
    /// assert_eq!(acl.get_ace(0).unwrap().ace_type(), ACCESS_ALLOWED_ACE_TYPE);
    /// assert_eq!(acl.get_ace(0).unwrap().mask(), AccessRights::GenericAll);
    /// assert_eq!(acl.get_ace(0).unwrap().sid(), Some(&*sid1));
    ///
    /// assert_eq!(acl.get_ace(1).unwrap().ace_type(), ACCESS_ALLOWED_ACE_TYPE);
    /// assert_eq!(acl.get_ace(1).unwrap().mask(), AccessRights::GenericRead);
    /// assert_eq!(acl.get_ace(1).unwrap().sid(), Some(&*sid2));
    ///
    /// assert!(acl.get_ace(2).is_none());
    /// ```
    pub fn get_ace(&self, index: u32) -> Option<&Ace> {
        match wrappers::GetAce(self, index) {
            Ok(ace) => Some(ace),
            Err(ref e) if e.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) => None,
            other_err => {
                other_err.expect("GetAce returned error on valid Ace");
                unreachable!() // Because other_err will always fail the expect
            }
        }
    }

    /// Get the ACL's revision level
    ///
    /// ```
    /// use windows_permissions::{LocalBox, SecurityDescriptor, Acl};
    /// use windows_permissions::constants::AclRevision::*;
    ///
    /// let simple_acl_sd: LocalBox<SecurityDescriptor> = "D:(A;;;;;WD)".parse().unwrap();
    /// let complex_acl_sd: LocalBox<SecurityDescriptor> = "D:(OA;;;294be2fb-d1ca-4aa2-aa06-ab98a8b5556d;;WD)".parse().unwrap();
    ///
    /// assert_eq!(simple_acl_sd.dacl().unwrap().revision_level(), ACL_REVISION);
    /// assert_eq!(complex_acl_sd.dacl().unwrap().revision_level(), ACL_REVISION_DS);
    /// ```
    pub fn revision_level(&self) -> constants::AclRevision {
        constants::AclRevision::from_raw(self.internal_type_reference().AclRevision)
            .expect("Unknown revision level")
    }
}

impl fmt::Debug for Acl {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut map = fmt.debug_map();
        map.entry(&"len", &self.len());
        map.finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::constants::AceType;
    use crate::{LocalBox, SecurityDescriptor};

    #[test]
    fn get_len() -> io::Result<()> {
        let limit = 100;

        for dacl_count in 0..limit {
            let sacl_count = limit - dacl_count - 1;

            // Looks like "D:(A;;;;;WD)(A;;;;;WD)(...)S:(AU;;;;;WD)(...)"
            // A (SDDL_ACCESS_ALLOWED) isn't valid for SACLs, AU (SDDL_AUDIT) is valid
            let mut sddl_string = String::new();
            sddl_string.push_str("D:");
            sddl_string.push_str(&"(A;;;;;WD)".repeat(dacl_count));
            sddl_string.push_str("S:");
            sddl_string.push_str(&"(AU;;;;;WD)".repeat(sacl_count));

            let sd: LocalBox<SecurityDescriptor> = sddl_string.parse()?;

            assert_eq!(sd.dacl().unwrap().len(), dacl_count as u32);
            assert_eq!(sd.sacl().unwrap().len(), sacl_count as u32);
        }

        Ok(())
    }

    #[test]
    fn get_from_sddl() -> io::Result<()> {
        let mut sddl = "D:".to_string();
        let limit = 10;

        for i in 0..limit {
            sddl.push_str(&format!("(A;;;;;S-1-5-{})", i));
        }

        let sd: LocalBox<SecurityDescriptor> = sddl.parse()?;
        let dacl = sd.dacl().unwrap();

        // Try to get each one
        for i in 0..limit {
            let ace = dacl.get_ace(i).unwrap();
            assert_eq!(ace.ace_type(), AceType::ACCESS_ALLOWED_ACE_TYPE);
        }

        // Off the end
        assert!(dacl.get_ace(limit).is_none());

        Ok(())
    }
}
