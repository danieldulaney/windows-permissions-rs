use crate::Sid;
use std::ffi::OsStr;
use std::marker::PhantomData;
use winapi::um::accctrl::TRUSTEE_W;

/// An entity that can be added to an ACL.
///
/// Trustees can identify their subject (usually an account or a group) using a
/// string or a `Sid`. Which type of trustee
#[repr(C)]
pub struct Trustee<'s> {
    inner: TRUSTEE_W,
    _phantom: PhantomData<TrusteeSubject<'s>>,
}

pub enum TrusteeSubject<'s> {
    Name(&'s OsStr),
    Sid(&'s Sid),
}

impl<'s> Trustee<'s> {
    /// Get a pointer to the underlying buffer
    pub fn as_ptr(&self) -> *const TRUSTEE_W {
        &self.inner
    }

    pub fn as_mut_ptr(&mut self) -> *mut TRUSTEE_W {
        &mut self.inner
    }

    /// Allocate space for a TRUSTEE_W with the given lifetime. All fields will
    /// be set to zero.
    pub unsafe fn allocate<S>(_lifetime: &'s S) -> Self {
        Self {
            inner: std::mem::zeroed(),
            _phantom: PhantomData,
        }
    }
}
