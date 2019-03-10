use crate::{constants, wrappers, Trustee};
use std::io;
use std::mem;
use std::ptr::{null, NonNull};
use winapi::um::winnt::{ACL, PACL};

#[derive(Debug)]
pub struct Acl {
    inner: Option<NonNull<ACL>>,
}

impl Acl {
    pub unsafe fn ref_from_ptr<'s>(ptr: *const PACL) -> &'s Acl {
        let acl_ref: &Acl = mem::transmute(ptr);
        debug_assert!(wrappers::IsValidAcl(acl_ref));
        acl_ref
    }

    pub fn as_ptr(&self) -> *const ACL {
        match self.inner {
            None => null(),
            Some(p) => p.as_ptr(),
        }
    }

    pub fn is_null(&self) -> bool {
        self.inner.is_none()
    }

    pub fn effective_rights(
        &self,
        trustee: &Trustee,
    ) -> Result<constants::AccessRights, io::Error> {
        wrappers::GetEffectiveRightsFromAcl(self, trustee)
    }

    pub fn len(&self) -> u32 {
        unimplemented!();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::SecurityDescriptor;

    #[test]
    fn build_with_sddl() -> io::Result<()> {
        let empty_sd: SecurityDescriptor = "".parse()?;

        Ok(())
    }
}
