use crate::{constants, wrappers, Trustee};
use std::fmt;
use std::io;
use std::mem;
use std::ptr::NonNull;
use winapi::um::winnt::ACL;

#[repr(C)]
pub struct Acl {
    inner: ACL,
}

impl Drop for Acl {
    fn drop(&mut self) {
        unreachable!("Acl should only be borrowed")
    }
}

impl Acl {
    /// Get a reference from an ACL pointer.
    ///
    /// ## Requirements
    ///
    /// - `ptr` must point to a valid ACL structure
    /// - The ACL header must be followed by the correct number of ACEs
    /// - The entire structure must remain alive at least as long as `'s`
    pub unsafe fn ref_from_nonnull<'s>(ptr: NonNull<ACL>) -> &'s Acl {
        let acl_ref: &Acl = mem::transmute(ptr);
        debug_assert!(wrappers::IsValidAcl(acl_ref));
        acl_ref
    }

    /// Get a pointer to the underlying ACL structure
    pub fn as_ptr(&self) -> *const ACL {
        &self.inner
    }

    /// Determine what rights the given `Trustee` has under this ACL
    pub fn effective_rights(
        &self,
        trustee: &Trustee,
    ) -> Result<constants::AccessRights, io::Error> {
        wrappers::GetEffectiveRightsFromAcl(self, trustee)
    }

    /// Determine the number of ACEs in this ACL
    pub fn len(&self) -> u32 {
        wrappers::GetAclInformationSize(self)
            .expect("GetAclInformation failed on valid ACL")
            .AceCount
    }
}

impl fmt::Debug for Acl {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_map().finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::SecurityDescriptor;

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

            let sd: SecurityDescriptor = sddl_string.parse()?;

            assert_eq!(sd.dacl().unwrap().len(), dacl_count as u32);
            assert_eq!(sd.sacl().unwrap().len(), sacl_count as u32);
        }

        Ok(())
    }
}
