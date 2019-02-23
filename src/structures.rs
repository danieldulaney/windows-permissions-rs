pub use sd::SecurityDescriptor;
pub use sid::Sid;

mod sid {
    use crate::wrappers;
    use std::fmt;
    use std::ptr::NonNull;
    use winapi::ctypes::c_void;

    #[allow(non_snake_case)]
    pub struct Sid(NonNull<c_void>);

    impl Drop for Sid {
        fn drop(&mut self) {
            unsafe { winapi::um::winbase::LocalFree(self.0.as_ptr()) };
        }
    }

    impl Sid {
        /// Get `&Sid` from a `NonNull`
        ///
        /// The `_lifetime` parameter indicates the lifetime of the reference.
        ///
        /// ## Requirements
        ///
        /// - `ptr` points to a valid SID
        /// - `_lifetime` lives at least as long as `ptr`
        /// - No mutable references exist to the SID
        ///
        /// The easiest way to ensure that this is accurate is by ensuring that
        /// `ptr` points to a valid SID somewhere in `_lifetime`. It's worth
        /// noting that a SID does not have a static size -- the size of the
        /// SID, and therefore the memory area covered by these requirements,
        /// will depend on the contents of that memory area. Therefore, it is
        /// strongly encouraged that `ref_from_nonnull` is only called with
        /// pointers returned by WinAPI calls.
        pub unsafe fn ref_from_nonnull<T>(ptr: NonNull<c_void>, _lifetime: &T) -> &Sid {
            std::mem::transmute(ptr)
        }

        /// Get a `Sid` from a `NonNull`
        ///
        /// ## Requirements
        ///
        /// The `NonNull` pointer *must* have been allocated with
        /// `AllocateAndInitializeSid`. When the resulting `Sid` is dropped, it
        /// will be dropped with `LocalFree`.
        pub unsafe fn owned_from_nonnull(ptr: NonNull<c_void>) -> Sid {
            // Future maintainers:
            // This function contains no unsafe code, but it requires that
            // callers fulfil an un-checked promise that is relied on by other
            // actually unsafe code. Do not remove the unsafe marker without
            // fully understanding the implications.
            Sid(ptr)
        }

        /// Create a new `Sid` with the given number of SubAuthorities
        ///
        /// By default the SID will have all identifier authorities and
        /// subauthorities set to 0.
        ///
        /// ## Panics
        ///
        /// Panics if the underlying call to `AllocateAndInitializeSid` fails.
        /// This can happen if the system is out of memory.
        pub fn new(auth_count: u8) -> Sid {
            let auths = vec![0; auth_count as usize];
            let id_auth: [u8; 6] = [0, 0, 0, 0, 0, 0];

            match wrappers::AllocateAndInitializeSid(id_auth, &auths) {
                Ok(s) => s,
                Err(e) => panic!("Could not allocate SID, {}", e),
            }
        }

        /// Get a pointer to the underlying SID structure
        pub fn as_ptr(&self) -> *const c_void {
            self.0.as_ptr()
        }

        /// Get the size of the SID in bytes
        pub fn size(&self) -> usize {
            unimplemented!();
            //wrappers::GetLengthSid(&self);
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
        pub fn sub_authority(&self, index: u8) {}
    }

    impl fmt::Debug for Sid {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            fmt.debug_map()
                .entry(&"sub_auth_count", &self.sub_authority_count())
                .entry(&"id_auth", &self.id_authority())
                //.entry(&"sub_auth", &self.sub_authorities())
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
}

mod sd {
    use std::ptr::NonNull;
    use winapi::ctypes::c_void;
    use winapi::um::winnt::{ACL, PACL, PSECURITY_DESCRIPTOR, PSID, SECURITY_DESCRIPTOR, SID};

    use super::sid::Sid;

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
                .map(|p| unsafe { Sid::ref_from_nonnull(p, self) })
        }

        /// Get the group SID if it exists
        pub fn group(&self) -> Option<&Sid> {
            // Assumptions:
            // - self.group lives as long as self
            self.group
                .clone()
                .map(|p| unsafe { Sid::ref_from_nonnull(p, self) })
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            let result = unsafe { winapi::um::winbase::LocalFree(self.sd.as_ptr() as *mut _) };
            assert!(result.is_null());
        }
    }
}
