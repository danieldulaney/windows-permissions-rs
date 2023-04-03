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

mod add_ace;
mod allocate_and_initialize_sid;
mod build_trustee_with_name;
mod build_trustee_with_sid;
mod convert_security_descriptor_to_string_security_descriptor;
mod convert_sid_to_string_sid;
mod convert_string_security_descriptor_to_security_descriptor;
mod convert_string_sid_to_sid;
mod copy_sid;
mod create_well_known_sid;
mod equal_sid;
mod get_ace;
mod get_acl_information;
mod get_effective_rights_from_acl;
mod get_named_security_info;
mod get_security_descriptor_dacl_sacl;
mod get_security_descriptor_owner_group;
mod get_security_info;
mod get_sid_identifier_authority;
mod get_sid_length_required;
mod get_sid_sub_authority;
mod get_sid_sub_authority_count;
mod get_trustee_form;
mod get_trustee_name;
mod get_windows_account_domain_sid;
mod is_valid_acl;
mod is_valid_security_descriptor;
mod is_valid_sid;
mod lookup_account_name;
mod lookup_account_sid;
mod set_named_security_info;
mod set_security_info;

pub use add_ace::AddAce;
pub use allocate_and_initialize_sid::AllocateAndInitializeSid;
pub use build_trustee_with_name::{BuildTrusteeWithName, BuildTrusteeWithNameOsStr};
pub use build_trustee_with_sid::BuildTrusteeWithSid;
pub use convert_security_descriptor_to_string_security_descriptor::ConvertSecurityDescriptorToStringSecurityDescriptor;
pub use convert_sid_to_string_sid::ConvertSidToStringSid;
pub use convert_string_security_descriptor_to_security_descriptor::ConvertStringSecurityDescriptorToSecurityDescriptor;
pub use convert_string_sid_to_sid::ConvertStringSidToSid;
pub use copy_sid::CopySid;
pub use create_well_known_sid::CreateWellKnownSid;
pub use equal_sid::EqualSid;
pub use get_ace::GetAce;
pub use get_acl_information::GetAclInformationSize;
pub use get_effective_rights_from_acl::GetEffectiveRightsFromAcl;
pub use get_named_security_info::GetNamedSecurityInfo;
pub use get_security_descriptor_dacl_sacl::{GetSecurityDescriptorDacl, GetSecurityDescriptorSacl};
pub use get_security_descriptor_owner_group::{
    GetSecurityDescriptorGroup, GetSecurityDescriptorOwner,
};
pub use get_security_info::GetSecurityInfo;
pub use get_sid_identifier_authority::GetSidIdentifierAuthority;
pub use get_sid_length_required::GetSidLengthRequired;
pub use get_sid_sub_authority::{GetSidSubAuthority, GetSidSubAuthorityChecked};
pub use get_sid_sub_authority_count::GetSidSubAuthorityCount;
pub use get_trustee_form::GetTrusteeForm;
pub use get_trustee_name::GetTrusteeName;
pub use get_windows_account_domain_sid::GetWindowsAccountDomainSid;
pub use is_valid_acl::IsValidAcl;
pub use is_valid_security_descriptor::IsValidSecurityDescriptor;
pub use is_valid_sid::IsValidSid;
pub use lookup_account_name::LookupAccountName;
pub use lookup_account_sid::LookupAccountSid;
pub use set_named_security_info::SetNamedSecurityInfo;
pub use set_security_info::SetSecurityInfo;

#[cfg(test)]
mod test {
    use windows_sys::Win32::Security::{WinCapabilityMusicLibrarySid, WinLocalSid, WinWorldSid};

    use super::*;

    use crate::Sid;
    use std::ffi::OsString;

    #[test]
    fn construct_and_read_sids() {
        for (sid, id, sa) in Sid::test_sids() {
            assert_eq!(&id, GetSidIdentifierAuthority(&sid));
            assert_eq!(sa.len() as u8, GetSidSubAuthorityCount(&sid));

            for index in 0..sa.len() {
                assert_eq!(
                    Some(sa[index]),
                    GetSidSubAuthorityChecked(&sid, index as u8),
                );
            }

            assert_eq!(None, GetSidSubAuthorityChecked(&sid, sa.len() as u8));
        }
    }

    #[test]
    fn constructed_sids_string_roundtrip() {
        for (sid, _, _) in Sid::test_sids() {
            let string_sid = ConvertSidToStringSid(&sid).unwrap();

            let sid_rt = ConvertStringSidToSid(&string_sid).unwrap();

            assert!(EqualSid(&sid, &sid_rt));
        }
    }

    #[test]
    fn sids_copy() {
        for (sid, _, _) in Sid::test_sids() {
            let copied = CopySid(&sid).unwrap();

            if !EqualSid(&sid, &copied) {
                dbg!(&sid);
                dbg!(&copied);
            }

            assert!(EqualSid(&sid, &copied));
        }
    }

    #[test]
    fn constructed_sids_are_valid() {
        for (sid, _, _) in Sid::test_sids() {
            assert!(IsValidSid(&sid));
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
