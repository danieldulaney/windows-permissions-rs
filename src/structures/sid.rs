use crate::wrappers;
use std::fmt;
use std::io;
use std::ops::Deref;
use std::ptr::NonNull;
use std::str::FromStr;
use winapi::ctypes::c_void;
use winapi::um::winnt::SID;

/// A reference to a SID
#[repr(C)]
pub struct Sid {
    _inner: SID,
}

/// A SID allocated by the Windows API that should be freed with `LocalFree`
pub struct LocallyOwnedSid {
    ptr: NonNull<c_void>,
}

impl Drop for Sid {
    fn drop(&mut self) {
        unreachable!("Sid should only be borrowed, not owned")
    }
}

impl Drop for LocallyOwnedSid {
    fn drop(&mut self) {
        debug_assert!(wrappers::IsValidSid(&self));
        unsafe { winapi::um::winbase::LocalFree(self.ptr.as_ptr()) };
    }
}

impl Sid {
    /// Get `&Sid` from a `NonNull`
    ///
    /// The resulting reference lives as long as the given lifetime.
    ///
    /// ## Requirements
    ///
    /// - `ptr` points to a valid SID
    /// - No mutable references exist to the SID
    /// - `ptr` remains valid at least as long as `'s`
    /// - The backing memory is free'd using some other alias
    ///
    /// It's worth
    /// noting that a SID does not have a static size -- the size of the
    /// SID, and therefore the memory area covered by these requirements,
    /// will depend on the contents of that memory area. Therefore, it is
    /// strongly encouraged that `ref_from_nonnull` is only called with
    /// pointers returned by WinAPI calls.
    pub unsafe fn ref_from_nonnull<'s>(ptr: NonNull<c_void>) -> &'s Sid {
        let sid_ref = std::mem::transmute::<NonNull<c_void>, &Sid>(ptr);
        debug_assert!(wrappers::IsValidSid(sid_ref));
        sid_ref
    }

    /// Get the number of sub-authorities in the SID
    pub fn sub_authority_count(&self) -> u8 {
        wrappers::GetSidSubAuthorityCount(self)
    }

    /// Get the ID authority in the SID
    pub fn id_authority(&self) -> &[u8; 6] {
        wrappers::GetSidIdentifierAuthority(self)
    }

    /// Get a sub-authority in the SID if it is available
    ///
    /// Returns `None` if the SID has too few sub-authorities.
    pub fn sub_authority(&self, index: u8) -> Option<u32> {
        wrappers::GetSidSubAuthorityChecked(self, index)
    }

    /// Generate a list of the sub-authorities in the SID
    ///
    /// Changes in the returned `Vec` are not reflected in the SID
    pub fn sub_authorities(&self) -> Vec<u32> {
        let mut vec = Vec::with_capacity(self.sub_authority_count() as usize);

        for index in 0..self.sub_authority_count() {
            vec.push(self.sub_authority(index).expect("Already checked count"));
        }

        vec
    }
}

#[cfg(test)]
impl Sid {
    /// Return an iterator that yields a whole bunch of SIDs you can test
    /// against, along with the things that got fed into `Sid::new` for each
    ///
    /// Only built on `cfg(test)`.
    pub fn test_sids() -> impl Iterator<Item = (LocallyOwnedSid, [u8; 6], &'static [u32])> {
        extern crate itertools;
        use itertools::Itertools;

        const ID_AUTHS: &[[u8; 6]] = &[
            [0, 0, 0, 0, 0, 0],
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            [0xba, 0xd5, 0x1d, 0xba, 0xd5, 0x1d],
            [0xc0, 0x00, 0x15, 0x1d, 0xab, 0xcd],
        ];

        const SUB_AUTHS: &[[u32; 8]] = &[
            [0, 0, 0, 0, 0, 0, 0, 0],
            [
                0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                0xffffffff,
            ],
            [1, 2, 3, 4, 5, 6, 7, 8],
        ];

        ID_AUTHS
            .iter()
            .cartesian_product(SUB_AUTHS)
            .cartesian_product(1..=8)
            .map(|((id, sa), sa_len)| {
                let chopped_sa = &sa[..sa_len];
                (
                    LocallyOwnedSid::new(id.clone(), chopped_sa).unwrap(),
                    id.clone(),
                    chopped_sa,
                )
            })
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_map()
            .entry(&"string_sid", &self.to_string())
            .entry(&"id_auth", &self.id_authority())
            .entry(&"sub_auth_count", &self.sub_authority_count())
            .entry(&"sub_auths", &self.sub_authorities())
            .finish()
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "{}",
            wrappers::ConvertSidToStringSid(&self)
                .expect("Passed a safe Sid to ConvertSidToStringSid but got an error")
                .to_string_lossy()
        )
    }
}

impl LocallyOwnedSid {
    /// Get a `LocallyOwnedSid` from a `NonNull`
    ///
    /// ## Requirements
    ///
    /// The `NonNull` pointer *must* have been allocated with
    /// a Windows API call. When the resulting `LocallyOwnedSid` is dropped, it
    /// will be dropped with `LocalFree`.
    pub unsafe fn owned_from_nonnull(ptr: NonNull<c_void>) -> Self {
        // Future maintainers:
        // This function contains no unsafe code, but it requires that
        // callers fulfil an un-checked promise that is relied on by other
        // actually unsafe code. Do not remove the unsafe marker without
        // fully understanding the implications.
        let sid = Self { ptr };
        debug_assert!(wrappers::IsValidSid(&sid));
        sid
    }

    /// Get a pointer to the underlying SID structure
    ///
    /// Use this when interacting with FFI libraries that want SID
    /// pointers. Taking a reference to the `Sid` struct won't work.
    pub fn as_ptr(&self) -> *const c_void {
        self.ptr.as_ptr()
    }

    /// Create a new `Sid`
    ///
    /// `id_auth` will be the identifier authority, `sub_auths` will be the
    /// sub-authorities. There must be between 1 and 8 sub-authorities.
    pub fn new(id_auth: [u8; 6], sub_auths: &[u32]) -> io::Result<Self> {
        let sid = wrappers::AllocateAndInitializeSid(id_auth, sub_auths)?;
        debug_assert!(wrappers::IsValidSid(&sid));
        Ok(sid)
    }
}

impl Deref for LocallyOwnedSid {
    type Target = Sid;

    fn deref(&self) -> &Self::Target {
        unsafe { Sid::ref_from_nonnull(self.ptr) }
    }
}

impl FromStr for LocallyOwnedSid {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        wrappers::ConvertStringSidToSid(s)
    }
}

impl fmt::Debug for LocallyOwnedSid {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_map()
            .entry(&"pointer", &self.ptr)
            .entry(&"string_sid", &self.to_string())
            .finish()
    }
}

macro_rules! impl_partial_eq {
    ($lhs:ty, $rhs:ty) => {
        impl PartialEq<$rhs> for $lhs {
            fn eq(&self, other: &$rhs) -> bool {
                wrappers::EqualSid(self, other)
            }
        }
    };
}

impl_partial_eq!(Sid, Sid);
impl_partial_eq!(Sid, LocallyOwnedSid);
impl_partial_eq!(LocallyOwnedSid, Sid);
impl_partial_eq!(LocallyOwnedSid, LocallyOwnedSid);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn create_and_read_sids() {
        for (sid, id_auth, sub_auths) in Sid::test_sids() {
            assert_eq!(*sid.id_authority(), id_auth);
            assert_eq!(sid.sub_authority_count() as usize, sub_auths.len());

            for i in 0..sub_auths.len() {
                assert_eq!(sid.sub_authority(i as u8), Some(sub_auths[i]));
            }
        }
    }
}
