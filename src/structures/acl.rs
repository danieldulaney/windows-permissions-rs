use std::mem;
use std::ptr::NonNull;
use winapi::um::winnt::ACL;

pub struct Acl {
    inner: ACL,
}

impl Acl {
    pub unsafe fn ref_from_nonnull<'s>(ptr: &NonNull<ACL>) -> &'s Acl {
        mem::transmute(ptr)
    }

    pub fn as_ptr(&self) -> *const ACL {
        &self.inner
    }
}
