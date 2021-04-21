use crate::constants::TrusteeForm;
use crate::utilities;
use crate::wrappers;
use crate::Sid;
use std::ffi::OsStr;
use std::fmt;
use std::marker::PhantomData;
use std::ptr::NonNull;
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

/// The contents of a Trustee.
#[derive(Debug)]
pub enum TrusteeSubject<'s> {
    /// This trustee holds a zero-terminated WTF-16-encoded name. This can be
    /// converted into an [`OsString`](`std::ffi::OsString`) using
    /// [`utilities::os_from_buf`].
    Name(&'s [u16]),

    /// This trustee holds a reference to the Sid it was created with.
    Sid(&'s Sid),

    /// An opaque pointer to objects and SID.
    ObjectsAndSid(*const c_void),

    /// An opaque pointer to objects and name.
    ObjectsAndName(*const c_void),

    /// `Bad` means that `trusteeForm` is explicitly set to `TRUSTEE_BAD_FORM`
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

    /// Allocate space for a Trustee
    pub unsafe fn allocate() -> Self {
        Self {
            inner: std::mem::zeroed(),
            _phantom: PhantomData,
        }
    }

    /// Get the `TrusteeSubject` of a `Trustee`
    ///
    /// ## Panics
    ///
    /// Panics if the `trusteeForm` in the underlying object is an unrecognized
    /// value. To get the value, use `wrappers::GetTrusteeForm` directly.
    ///
    /// Also panics if the pointer value is null.
    pub fn get_subject(&self) -> TrusteeSubject<'s> {
        let form = wrappers::GetTrusteeForm(&self)
            .unwrap_or_else(|f| panic!("Trustee had unrecognized form: {:x}", f));

        let ptr = self.inner.ptstrName as *mut _;

        match form {
            TrusteeForm::TRUSTEE_IS_SID => {
                let ptr =
                    NonNull::new(ptr).expect("Null SID pointer on Trustee with TRUSTEE_IS_SID");

                unsafe { TrusteeSubject::Sid(&*ptr.as_ptr()) }
            }
            TrusteeForm::TRUSTEE_IS_NAME => {
                let ptr =
                    NonNull::new(ptr).expect("Null name pointer on Trustee with TRUSTEE_IS_NAME");

                unsafe {
                    let nul_pos = utilities::search_buffer(&0x00, ptr.as_ptr() as *const u16);
                    TrusteeSubject::Name(std::slice::from_raw_parts(
                        ptr.as_ptr() as *const u16,
                        nul_pos + 1,
                    ))
                }
            }
            TrusteeForm::TRUSTEE_IS_OBJECTS_AND_SID => {
                TrusteeSubject::ObjectsAndSid(ptr as *const _)
            }
            TrusteeForm::TRUSTEE_IS_OBJECTS_AND_NAME => {
                TrusteeSubject::ObjectsAndName(ptr as *const _)
            }
            TrusteeForm::TRUSTEE_BAD_FORM => TrusteeSubject::Bad,
        }
    }
}

impl<'s> From<&'s Sid> for Trustee<'s> {
    fn from(sid: &'s Sid) -> Self {
        wrappers::BuildTrusteeWithSid(sid)
    }
}

impl From<&OsStr> for Trustee<'static> {
    fn from(name: &OsStr) -> Self {
        wrappers::BuildTrusteeWithNameOsStr(name)
    }
}

impl<'s> fmt::Debug for Trustee<'s> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_map().finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRUSTEE_NAMES: &[&'static str] = &["test_name", r"domain\username", "a_unicode_char: 💩"];

    #[test]
    fn create_and_retrieve_sid_trustee() {
        use std::ops::Deref;

        for (sid, _, _) in Sid::test_sids() {
            let trustee: Trustee = sid.as_ref().into();

            match trustee.get_subject() {
                TrusteeSubject::Sid(s) => assert_eq!(s, sid.deref()),
                _ => panic!("Expected to get back a TrusteeSubject::Sid"),
            }
        }
    }

    #[test]
    fn create_and_retrieve_name_trustee() {
        for name in TRUSTEE_NAMES {
            let trustee: Trustee = OsStr::new(name).into();
            let buffer = utilities::buf_from_os(OsStr::new(name));

            match trustee.get_subject() {
                TrusteeSubject::Name(n) => assert_eq!(n, buffer.as_slice()),
                _ => panic!("Expected to get back a TrusteeSubject::Name"),
            }
        }
    }
}
