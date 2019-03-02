//! Direct wrappers over WinAPI calls
//!
//! Generally, it's better to use the other methods in this crate. However, it
//! can sometimes be useful to drop straight down into the raw WinAPI calls.
//! These functions wrap the unsafe calls in safe objects, and are used to
//! implement the other functionality in this crate.

// Implementation note
//
// This file only contains integration tests. New wrappers should be added as
// additional sub-modules. If they can be tested in isolation, include that
// test code in those sub-modules. However, tests that require multiple
// wrapped calls should be placed here.

mod allocate_and_initialize_sid;
mod convert_sid_to_string_sid;
mod convert_string_sid_to_sid;
mod create_well_known_sid;
mod equal_sid;
mod get_named_security_info;
mod get_sid_identifier_authority;
mod get_sid_length_required;
mod get_sid_sub_authority;
mod get_sid_sub_authority_count;
mod is_valid_sid;
mod lookup_account_sid;

pub use allocate_and_initialize_sid::AllocateAndInitializeSid;
pub use convert_sid_to_string_sid::ConvertSidToStringSid;
pub use convert_string_sid_to_sid::ConvertStringSidToSid;
pub use create_well_known_sid::CreateWellKnownSid;
pub use equal_sid::EqualSid;
pub use get_named_security_info::GetNamedSecurityInfo;
pub use get_sid_identifier_authority::GetSidIdentifierAuthority;
pub use get_sid_length_required::GetSidLengthRequired;
pub use get_sid_sub_authority::{
    GetSidSubAuthority, GetSidSubAuthorityChecked, GetSidSubAuthorityCheckedMut,
    GetSidSubAuthorityMut,
};
pub use get_sid_sub_authority_count::GetSidSubAuthorityCount;
pub use is_valid_sid::IsValidSid;
pub use lookup_account_sid::LookupAccountSid;

#[cfg(test)]
mod test {
    use super::*;

    use std::ffi::OsString;
    use winapi::um::winnt::{WinCapabilityMusicLibrarySid, WinLocalSid, WinWorldSid};

    #[test]
    fn construct_and_read_sids() {
        let id_auth = [0xBAu8, 0xD5, 0x1D, 0xBA, 0xD5, 0x1D];
        let sub_auths_full = [20u32, 19, 18, 17, 16, 15, 14, 13];

        for length in 1..=sub_auths_full.len() {
            let sub_auths = &sub_auths_full[..length];

            let sid = AllocateAndInitializeSid(id_auth.clone(), &sub_auths).unwrap();

            assert_eq!(&id_auth, GetSidIdentifierAuthority(&sid));
            assert_eq!(sub_auths.len() as u8, GetSidSubAuthorityCount(&sid));

            for index in 0..sub_auths.len() {
                assert_eq!(
                    Some(sub_auths[index]),
                    GetSidSubAuthorityChecked(&sid, index as u8)
                );
            }
        }
    }

    #[test]
    fn modify_sid() {
        let id_auth = [0u8; 6];

        let sid1 = AllocateAndInitializeSid(id_auth.clone(), &[1]).unwrap();
        let mut sid2 = AllocateAndInitializeSid(id_auth.clone(), &[2]).unwrap();
        let mut sid3 =
            AllocateAndInitializeSid(id_auth.clone(), &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();

        *GetSidSubAuthorityCheckedMut(&mut sid2, 0).unwrap() = 1;

        assert!(EqualSid(&sid1, &sid2));
        assert_eq!(GetSidSubAuthorityChecked(&sid1, 1), None);

        assert_eq!(GetSidSubAuthorityChecked(&sid3, 7).unwrap(), 8);
        *GetSidSubAuthorityCheckedMut(&mut sid3, 7).unwrap() = 10;
        assert_eq!(GetSidSubAuthorityChecked(&sid3, 7).unwrap(), 10);
    }

    #[test]
    fn constructed_sids_string_roundtrip() {
        let id_auth = [0xBAu8, 0xD5, 0x1D, 0xBA, 0xD5, 0x1D];
        let sub_auths_full = [0u32, 1, 2, 3, 4, 5, 6, 7];

        for length in 1..=sub_auths_full.len() {
            let sub_auths = &sub_auths_full[..length];

            let sid = AllocateAndInitializeSid(id_auth.clone(), &sub_auths).unwrap();
            let string_sid = ConvertSidToStringSid(&sid).unwrap();

            let sid_rt = ConvertStringSidToSid(&string_sid);

            let sid_rt = sid_rt.unwrap();

            assert!(EqualSid(&sid, &sid_rt));
        }
    }

    #[test]
    fn constructed_sids_are_valid() {
        let id_auth = [0x00u8, 0x00, 0x0C, 0x00, 0x15, 0x1D];
        let sub_auths_full = [0u32, 1, 2, 3, 4, 5, 6, 7];

        for length in 1..=sub_auths_full.len() {
            let sub_auths = &sub_auths_full[..length];

            let sid = AllocateAndInitializeSid(id_auth.clone(), &sub_auths).unwrap();

            assert!(IsValidSid(&sid).is_ok());
        }
    }

    #[test]
    fn well_known_sids_are_equal() {
        let world_sid_1 = CreateWellKnownSid(WinWorldSid, None).unwrap();
        let world_sid_2 = CreateWellKnownSid(WinWorldSid, None).unwrap();
        let local_sid_1 = CreateWellKnownSid(WinLocalSid, None).unwrap();
        let local_sid_2 = CreateWellKnownSid(WinLocalSid, None).unwrap();

        assert!(EqualSid(&world_sid_1, &world_sid_2));
        assert!(EqualSid(&local_sid_1, &local_sid_2));
        assert!(!EqualSid(&world_sid_1, &local_sid_2));
        assert!(!EqualSid(&local_sid_1, &world_sid_2));
    }

    #[test]
    fn well_known_sids_stringify() {
        let world_sid = CreateWellKnownSid(WinWorldSid, None).unwrap();
        let local_sid = CreateWellKnownSid(WinLocalSid, None).unwrap();
        let fancy_sid = CreateWellKnownSid(WinCapabilityMusicLibrarySid, None).unwrap();

        assert_eq!(
            ConvertSidToStringSid(&world_sid).unwrap(),
            OsString::from("S-1-1-0")
        );
        assert_eq!(
            ConvertSidToStringSid(&local_sid).unwrap(),
            OsString::from("S-1-2-0")
        );
        assert_eq!(
            ConvertSidToStringSid(&fancy_sid).unwrap(),
            OsString::from("S-1-15-3-6")
        );
    }
}
