use crate::constants::{SeObjectType::SE_UNKNOWN_OBJECT_TYPE, SecurityInformation};
use crate::{wrappers, Acl, LocalBox, SecurityDescriptor, Sid};
use std::ffi::OsStr;
use std::io;
use std::os::windows::io::AsRawHandle;

pub trait WindowsSecure {
    /// Get a security descriptor for the object
    fn security_descriptor(
        &self,
        sec_info: SecurityInformation,
    ) -> io::Result<LocalBox<SecurityDescriptor>>;

    /// Set the object's owner
    fn set_owner(&mut self, owner: &Sid) -> io::Result<()>;

    /// Set the object's group
    fn set_group(&mut self, group: &Sid) -> io::Result<()>;

    /// Set the object's DACL
    fn set_dacl(&mut self, dacl: &Acl) -> io::Result<()>;

    /// Set the object's SACL
    fn set_sacl(&mut self, sacl: &Acl) -> io::Result<()>;

    /// Set multiple security options at once
    ///
    /// Some securable objects may be able to set multiple security options at
    /// the same time with less overhead. The default implementation just calls
    /// each of the other functions one at a time.
    ///
    /// This does not guarantee an atomic update. It is possible that only some
    /// of the options will be updated.
    fn set_multiple(
        &mut self,
        owner: Option<&Sid>,
        group: Option<&Sid>,
        dacl: Option<&Acl>,
        sacl: Option<&Acl>,
    ) -> io::Result<()> {
        if let Some(o) = owner {
            self.set_owner(o)?
        }

        if let Some(g) = group {
            self.set_group(g)?
        }

        if let Some(d) = dacl {
            self.set_dacl(d)?
        }

        if let Some(s) = sacl {
            self.set_sacl(s)?
        }

        Ok(())
    }

    fn set_security_descriptor(&mut self, sd: &SecurityDescriptor) -> io::Result<()> {
        self.set_multiple(sd.owner(), sd.group(), sd.dacl(), sd.sacl())
    }
}

impl<T> WindowsSecure for T
where
    T: AsRawHandle,
{
    fn security_descriptor(
        &self,
        sec_info: SecurityInformation,
    ) -> io::Result<LocalBox<SecurityDescriptor>> {
        wrappers::GetSecurityInfo(self, SE_UNKNOWN_OBJECT_TYPE, sec_info)
    }

    fn set_owner(&mut self, owner: &Sid) -> io::Result<()> {
        wrappers::SetSecurityInfo(
            self,
            SE_UNKNOWN_OBJECT_TYPE,
            SecurityInformation::Owner,
            Some(owner),
            None,
            None,
            None,
        )
    }

    fn set_group(&mut self, group: &Sid) -> io::Result<()> {
        wrappers::SetSecurityInfo(
            self,
            SE_UNKNOWN_OBJECT_TYPE,
            SecurityInformation::Group,
            None,
            Some(group),
            None,
            None,
        )
    }

    fn set_dacl(&mut self, dacl: &Acl) -> io::Result<()> {
        wrappers::SetSecurityInfo(
            self,
            SE_UNKNOWN_OBJECT_TYPE,
            SecurityInformation::Dacl,
            None,
            None,
            Some(dacl),
            None,
        )
    }

    fn set_sacl(&mut self, sacl: &Acl) -> io::Result<()> {
        wrappers::SetSecurityInfo(
            self,
            SE_UNKNOWN_OBJECT_TYPE,
            SecurityInformation::Sacl,
            None,
            None,
            None,
            Some(sacl),
        )
    }

    fn set_multiple(
        &mut self,
        owner: Option<&Sid>,
        group: Option<&Sid>,
        dacl: Option<&Acl>,
        sacl: Option<&Acl>,
    ) -> io::Result<()> {
        let sec_info = owner
            .map(|_| SecurityInformation::Owner)
            .unwrap_or(SecurityInformation::empty())
            | group
                .map(|_| SecurityInformation::Group)
                .unwrap_or(SecurityInformation::empty())
            | group
                .map(|_| SecurityInformation::Dacl)
                .unwrap_or(SecurityInformation::empty())
            | group
                .map(|_| SecurityInformation::Sacl)
                .unwrap_or(SecurityInformation::empty());

        wrappers::SetSecurityInfo(
            self,
            SE_UNKNOWN_OBJECT_TYPE,
            sec_info,
            owner,
            group,
            dacl,
            sacl,
        )
    }
}

impl WindowsSecure for OsStr {
    fn security_descriptor(
        &self,
        sec_info: SecurityInformation,
    ) -> io::Result<LocalBox<SecurityDescriptor>> {
        wrappers::GetNamedSecurityInfo(&self, SE_UNKNOWN_OBJECT_TYPE, sec_info)
    }

    fn set_owner(&mut self, owner: &Sid) -> io::Result<()> {
        wrappers::SetNamedSecurityInfo(
            self,
            SE_UNKNOWN_OBJECT_TYPE,
            SecurityInformation::Owner,
            Some(owner),
            None,
            None,
            None,
        )
    }

    fn set_group(&mut self, group: &Sid) -> io::Result<()> {
        wrappers::SetNamedSecurityInfo(
            self,
            SE_UNKNOWN_OBJECT_TYPE,
            SecurityInformation::Group,
            None,
            Some(group),
            None,
            None,
        )
    }

    fn set_dacl(&mut self, dacl: &Acl) -> io::Result<()> {
        wrappers::SetNamedSecurityInfo(
            self,
            SE_UNKNOWN_OBJECT_TYPE,
            SecurityInformation::Dacl,
            None,
            None,
            Some(dacl),
            None,
        )
    }

    fn set_sacl(&mut self, sacl: &Acl) -> io::Result<()> {
        wrappers::SetNamedSecurityInfo(
            self,
            SE_UNKNOWN_OBJECT_TYPE,
            SecurityInformation::Sacl,
            None,
            None,
            None,
            Some(sacl),
        )
    }

    fn set_multiple(
        &mut self,
        owner: Option<&Sid>,
        group: Option<&Sid>,
        dacl: Option<&Acl>,
        sacl: Option<&Acl>,
    ) -> io::Result<()> {
        let sec_info = owner
            .map(|_| SecurityInformation::Owner)
            .unwrap_or(SecurityInformation::empty())
            | group
                .map(|_| SecurityInformation::Group)
                .unwrap_or(SecurityInformation::empty())
            | dacl
                .map(|_| SecurityInformation::Dacl)
                .unwrap_or(SecurityInformation::empty())
            | sacl
                .map(|_| SecurityInformation::Sacl)
                .unwrap_or(SecurityInformation::empty());

        wrappers::SetNamedSecurityInfo(
            self,
            SE_UNKNOWN_OBJECT_TYPE,
            sec_info,
            owner,
            group,
            dacl,
            sacl,
        )
    }
}
