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
pub use get_sid_sub_authority::{GetSidSubAuthority, GetSidSubAuthorityChecked};
pub use get_sid_sub_authority_count::GetSidSubAuthorityCount;
pub use is_valid_sid::IsValidSid;
pub use lookup_account_sid::LookupAccountSid;

#[cfg(test)]
mod test {
    use super::*;

    use std::ffi::{OsStr, OsString};
    use std::path::Path;
    use winapi::um::accctrl::SE_FILE_OBJECT;
    use winapi::um::winnt::{self, WinCapabilityMusicLibrarySid, WinLocalSid, WinWorldSid};

    const SEC_INFO: u32 = winnt::OWNER_SECURITY_INFORMATION
        | winnt::GROUP_SECURITY_INFORMATION
        | winnt::DACL_SECURITY_INFORMATION;

    #[test]
    fn construct_and_read_sids() {
        let id_auth: [u8; 6] = [1, 2, 3, 4, 5, 6];
        let sub_auths_full = [20u32, 19, 18, 17, 16, 15, 14, 13];

        for length in 0..=sub_auths_full.len() {
            dbg!(length);

            let sub_auths = &sub_auths_full[..length];

            let sid = AllocateAndInitializeSid(id_auth.clone(), &sub_auths[..]).unwrap();

            assert_eq!(&id_auth, GetSidIdentifierAuthority(&sid));
            assert_eq!(sub_auths.len() as u8, GetSidSubAuthorityCount(&sid));

            for index in 0..sub_auths.len() {
                dbg!(index);
                assert_eq!(
                    Some(sub_auths[index]),
                    GetSidSubAuthorityChecked(&sid, index as u8)
                );
            }
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
