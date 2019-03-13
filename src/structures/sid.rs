use crate::wrappers;
use std::fmt;
use std::io;
use std::ptr::NonNull;
use std::str::FromStr;
use winapi::ctypes::c_void;

#[allow(non_snake_case)]
pub struct Sid(NonNull<c_void>);

impl Drop for Sid {
    fn drop(&mut self) {
        debug_assert!(wrappers::IsValidSid(&self));
        unsafe { winapi::um::winbase::LocalFree(self.0.as_ptr()) };
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
    pub unsafe fn ref_from_nonnull<'s>(ptr: *const NonNull<c_void>) -> &'s Sid {
        let sid_ref = std::mem::transmute::<*const NonNull<c_void>, &Sid>(ptr);
        debug_assert!(wrappers::IsValidSid(sid_ref));
        sid_ref
    }

    /// Get a `Sid` from a `NonNull`
    ///
    /// ## Requirements
    ///
    /// The `NonNull` pointer *must* have been allocated with
    /// a Windows API call. When the resulting `Sid` is dropped, it
    /// will be dropped with `LocalFree`.
    pub unsafe fn owned_from_nonnull(ptr: NonNull<c_void>) -> Sid {
        // Future maintainers:
        // This function contains no unsafe code, but it requires that
        // callers fulfil an un-checked promise that is relied on by other
        // actually unsafe code. Do not remove the unsafe marker without
        // fully understanding the implications.
        let sid = Sid(ptr);
        debug_assert!(wrappers::IsValidSid(&sid));
        sid
    }

    /// Create a new `Sid`
    ///
    /// `id_auth` will be the identifier authority, `sub_auths` will be the
    /// sub-authorities. There must be between 1 and 8 sub-authorities.
    pub fn new(id_auth: [u8; 6], sub_auths: &[u32]) -> Result<Sid, io::Error> {
        let sid = wrappers::AllocateAndInitializeSid(id_auth, sub_auths)?;
        debug_assert!(wrappers::IsValidSid(&sid));
        Ok(sid)
    }

    /// Get a pointer to the underlying SID structure
    ///
    /// Use this when interacting with FFI libraries that want SID
    /// pointers. Taking a reference to the `Sid` struct won't work.
    pub fn as_ptr(&self) -> *const c_void {
        self.0.as_ptr()
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
    pub fn test_sids() -> impl Iterator<Item = (Sid, [u8; 6], &'static [u32])> {
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
                    Sid::new(id.clone(), chopped_sa).unwrap(),
                    id.clone(),
                    chopped_sa,
                )
            })
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_map()
            .entry(&"pointer", &self.as_ptr())
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

impl PartialEq for Sid {
    fn eq(&self, other: &Sid) -> bool {
        wrappers::EqualSid(self, other)
    }
}

impl Clone for Sid {
    fn clone(&self) -> Sid {
        wrappers::CopySid(self).expect("wrappers::CopySid failed (FILE AN ISSUE!)")
    }
}

impl FromStr for Sid {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        wrappers::ConvertStringSidToSid(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_ref_to_self() {
        for (sid, _, _) in Sid::test_sids() {
            let ptr = NonNull::new(sid.as_ptr() as *mut c_void).unwrap();

            let sid_ref = unsafe { Sid::ref_from_nonnull(&ptr) };

            assert_eq!(&sid, sid_ref);
        }
    }
}
