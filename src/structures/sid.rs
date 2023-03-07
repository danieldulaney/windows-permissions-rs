use crate::{wrappers, LocalBox};
use std::fmt;
use std::hash::Hash;
use std::io;
use std::str::FromStr;

/// A SID (Security Identifier) that can be used with Windows API calls.
#[repr(C)]
pub struct Sid {
    _opaque: [u8; 0],
}

impl Sid {
    /// Create a new SID from raw parts
    ///
    /// ```
    /// use windows_permissions::Sid;
    ///
    /// let sid_8 = Sid::new([1, 2, 3, 4, 5, 6], &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    ///
    /// assert_eq!(sid_8.id_authority(), &[1, 2, 3, 4, 5, 6]);
    /// assert_eq!(sid_8.sub_authority_count(), 8);
    /// assert_eq!(sid_8.sub_authorities(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    /// ```
    ///
    /// No more than 8 sub-authorities can be made using this function. If more
    /// are needed, you can parse SDDL or use a wrapper function directly.
    ///
    /// ```
    /// use windows_permissions::Sid;
    ///
    /// assert!(Sid::new([1, 2, 3, 4, 5, 6], &[1, 2, 3, 4, 5, 6, 7, 8]).is_ok());
    /// assert!(Sid::new([1, 2, 3, 4, 5, 6], &[1, 2, 3, 4, 5, 6, 7, 8, 9]).is_err());
    /// ```
    ///
    pub fn new(id_auth: [u8; 6], sub_auths: &[u32]) -> io::Result<LocalBox<Sid>> {
        wrappers::AllocateAndInitializeSid(id_auth, sub_auths)
    }

    /// Create a new well-known SID
    ///
    /// This is equivalent to calling [`wrappers::CreateWellKnownSid`] with
    /// `None` as the domain.
    ///
    /// ```
    /// use windows_permissions::{Sid, LocalBox};
    /// use windows_sys::Win32::Security::WinWorldSid;
    ///
    /// let win_world_sid = Sid::well_known_sid(WinWorldSid).unwrap();
    /// let another_sid = "S-1-1-0".parse().unwrap();
    ///
    /// assert_eq!(win_world_sid, another_sid);
    /// ```
    pub fn well_known_sid(well_known_sid_type: i32) -> io::Result<LocalBox<Sid>> {
        wrappers::CreateWellKnownSid(well_known_sid_type, None)
    }

    /// Get the number of sub-authorities in the SID
    ///
    /// ```
    /// use windows_permissions::{Sid, LocalBox};
    ///
    /// let sid1: LocalBox<Sid> = "S-1-5-1".parse().unwrap();
    /// let sid2: LocalBox<Sid> = "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15".parse().unwrap();
    ///
    /// assert_eq!(sid1.sub_authority_count(), 1);
    /// assert_eq!(sid2.sub_authority_count(), 15);
    /// ```
    pub fn sub_authority_count(&self) -> u8 {
        wrappers::GetSidSubAuthorityCount(self)
    }

    /// Get the ID authority of the SID
    ///
    /// ```
    /// use windows_permissions::{Sid, LocalBox};
    ///
    /// let sid1: LocalBox<Sid> = "S-1-5-12-62341".parse().unwrap();
    /// let sid2: LocalBox<Sid> = "S-1-211111900160837-1".parse().unwrap();
    ///
    /// assert_eq!(sid1.id_authority(), &[0, 0, 0, 0, 0, 5]);
    /// assert_eq!(sid2.id_authority(), &[0xC0, 0x01, 0x51, 0xD1, 0x23, 0x45]);
    /// ```
    pub fn id_authority(&self) -> &[u8; 6] {
        wrappers::GetSidIdentifierAuthority(self)
    }

    /// Get a sub-authority of the SID if it is available
    ///
    /// Returns `None` if the SID has too few sub-authorities.
    ///
    /// ```
    /// use windows_permissions::{Sid, LocalBox};
    ///
    /// let sid: LocalBox<Sid> = "S-1-5-12-62341".parse().unwrap();
    ///
    /// assert_eq!(sid.sub_authority(0), Some(12));
    /// assert_eq!(sid.sub_authority(1), Some(62341));
    /// assert_eq!(sid.sub_authority(2), None);
    /// ```
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

    /// Get the numeric value of an ID authority
    ///
    /// ```
    /// use windows_permissions::Sid;
    ///
    /// assert_eq!(
    ///     Sid::id_auth_to_number([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]),
    ///     0x123456789ABCu64
    /// );
    /// ```
    pub fn id_auth_to_number(id_auth: [u8; 6]) -> u64 {
        id_auth[5] as u64
            | (id_auth[4] as u64) << 8
            | (id_auth[3] as u64) << 16
            | (id_auth[2] as u64) << 24
            | (id_auth[1] as u64) << 32
            | (id_auth[0] as u64) << 40
    }
}

#[cfg(test)]
impl Sid {
    /// Return an iterator that yields a whole bunch of SIDs you can test
    /// against, along with the things that got fed into `Sid::new` for each
    ///
    /// Only built on `cfg(test)`.
    pub fn test_sids() -> impl Iterator<Item = (LocalBox<Sid>, [u8; 6], &'static [u32])> {
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

impl Hash for Sid {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id_authority().hash(state);
        for index in 0..self.sub_authority_count() {
            self.sub_authority(index)
                .expect("Already checked count")
                .hash(state);
        }
    }
}

impl FromStr for LocalBox<Sid> {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        wrappers::ConvertStringSidToSid(s)
    }
}

impl Eq for Sid {}
impl PartialEq for Sid {
    fn eq(&self, other: &Sid) -> bool {
        wrappers::EqualSid(self, other)
    }
}

impl Clone for LocalBox<Sid> {
    fn clone(&self) -> Self {
        wrappers::CopySid(self)
            // internally, CopySid is just memmove with a length check.
            // This cannot panic unless allocation fails.
            .expect("Failed to clone SID")
    }
}

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
