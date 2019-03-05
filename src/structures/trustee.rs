use crate::constants::TrusteeForm;
use crate::wrappers;
use crate::Sid;
use std::ffi::OsStr;
use std::marker::PhantomData;
use std::mem;
use winapi::ctypes::c_void;
use winapi::um::accctrl::TRUSTEE_W;

/// An entity that can be added to an ACL.
///
/// Trustees can identify their subject (usually an account or a group) using a
/// string or a `Sid`.
#[repr(C)]
pub struct Trustee<'s> {
    inner: TRUSTEE_W,
    _phantom: PhantomData<TrusteeSubject<'s>>,
}

/// The contents of a Trustee
///
/// `Sid` is easy: This Trustee holds a reference to the Sid it was created
/// with.
///
/// `Name` holds a WTF-16-encoded name. It can be converted into an `OsStr`
/// using `utilities::buf_to_os`.
///
/// `Bad` means that `trusteeForm` is explicitly set to `TRUSTEE_BAD_FORM`
pub enum TrusteeSubject<'s> {
    Name(&'s [u16]),
    Sid(&'s Sid),
    ObjectsAndSid(*const c_void),
    ObjectsAndName(*const c_void),
    Bad,
}

impl<'s> Trustee<'s> {
    /// Get a pointer to the underlying buffer
    pub fn as_ptr(&self) -> *const TRUSTEE_W {
        &self.inner
    }

    /// Get a mutable pointer to the underlying buffer
    pub fn as_mut_ptr(&mut self) -> *mut TRUSTEE_W {
        &mut self.inner
    }

    /// Allocate space for a TRUSTEE_W with the given lifetime
    ///
    /// All fields will
    /// be set to zero. The parameter is not used, it just sets the lifetime
    /// parameter on the `Trustee`.
    pub unsafe fn allocate<S: ?Sized>(_lifetime: &'s S) -> Self {
        Self {
            inner: std::mem::zeroed(),
            _phantom: PhantomData,
        }
    }

    pub fn from_sid(sid: &'s Sid) -> Self {
        wrappers::BuildTrusteeWithSid(sid)
    }

    pub fn from_name(name: &OsStr) -> Trustee<'static> {
        wrappers::BuildTrusteeWithNameOsStr(name)
    }

    /// Get the `TrusteeSubject` of a `Trustee`
    ///
    /// ## Panics
    ///
    /// Panics if the `trusteeForm` in the underlying object is an unrecognized
    /// value. To get the value, use `wrappers::GetTrusteeForm` directly.
    pub fn get_subject(&self) -> TrusteeSubject<'s> {
        let form = wrappers::GetTrusteeForm(&self)
            .unwrap_or_else(|f| panic!("Trustee had unrecognized form: {:x}", f));

        let ptr = self.inner.ptstrName;

        unsafe {
            match form {
                TrusteeForm::TRUSTEE_IS_SID => TrusteeSubject::Sid(mem::transmute(ptr)),
                _ => unimplemented!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn create_and_retrieve_sid() {
        for (sid, _, _) in Sid::test_sids() {}
    }
}
