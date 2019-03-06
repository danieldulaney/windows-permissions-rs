use std::ptr::NonNull;
use winapi::ctypes::c_void;
use winapi::um::winnt::{ACL, PACL, PSECURITY_DESCRIPTOR, PSID, SECURITY_DESCRIPTOR};

use crate::{Acl, Sid};

pub struct SecurityDescriptor {
    sd: NonNull<SECURITY_DESCRIPTOR>,
    owner: Option<NonNull<c_void>>,
    group: Option<NonNull<c_void>>,
    dacl: Option<NonNull<ACL>>,
    sacl: Option<NonNull<ACL>>,
}

impl SecurityDescriptor {
    /// Construct a security descriptor from raw parts
    ///
    /// ## Assumptions
    ///
    /// - `sd` points to a valid buffer and should be deallocated with
    ///   `LocalFree`
    /// - All of the other pointers are either null or point at something
    ///   in the `sd` buffer
    /// - The two `PSID` arguments point to valid SID structures and the
    ///   two `ACL` arguments point to valid ACL structures
    ///
    /// ## Panics
    ///
    /// Panics if `sd` is null.
    pub unsafe fn from_raw(
        sd: PSECURITY_DESCRIPTOR,
        owner: PSID,
        group: PSID,
        dacl: PACL,
        sacl: PACL,
    ) -> SecurityDescriptor {
        SecurityDescriptor {
            sd: NonNull::new(sd as *mut SECURITY_DESCRIPTOR)
                .expect("SecurityDescriptor::from_raw called with null sd pointer"),
            owner: NonNull::new(owner),
            group: NonNull::new(group),
            dacl: NonNull::new(dacl),
            sacl: NonNull::new(sacl),
        }
    }

    /// Get the owner SID if it exists
    pub fn owner(&self) -> Option<&Sid> {
        // Assumptions:
        // - self.owner lives as long as self
        self.owner
            .clone()
            .map(|p| unsafe { Sid::ref_from_nonnull(&p) })
    }

    /// Get the group SID if it exists
    pub fn group(&self) -> Option<&Sid> {
        // Assumptions:
        // - self.group lives as long as self
        self.group
            .clone()
            .map(|p| unsafe { Sid::ref_from_nonnull(&p) })
    }

    /// Get the DACL if it exists
    pub fn dacl(&self) -> Option<&Acl> {
        self.dacl
            .clone()
            .map(|p| unsafe { Acl::ref_from_nonnull(&p) })
    }

    /// Get the SACL if it exists
    pub fn sacl(&self) -> Option<&Acl> {
        self.sacl
            .clone()
            .map(|p| unsafe { Acl::ref_from_nonnull(&p) })
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        let result = unsafe { winapi::um::winbase::LocalFree(self.sd.as_ptr() as *mut _) };
        assert!(result.is_null());
    }
}
