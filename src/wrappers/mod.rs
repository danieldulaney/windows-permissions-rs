//! Direct wrappers over WinAPI calls
//!
//! Generally, it's better to use the other methods in this crate. However, it
//! can sometimes be useful to drop straight down into the raw WinAPI calls.
//! These functions wrap the unsafe calls in safe objects, and are used to
//! implement the other functionality in this crate.

mod create_well_known_sid;
mod equal_sid;
mod get_named_security_info;
mod lookup_account_sid;
mod convert_sid_to_string_sid;

pub use create_well_known_sid::CreateWellKnownSid;
pub use equal_sid::EqualSid;
pub use get_named_security_info::GetNamedSecurityInfo;
pub use lookup_account_sid::LookupAccountSid;
pub use convert_sid_to_string_sid::ConvertSidToStringSid;

#[cfg(test)]
mod test {
    use super::*;

    use std::path::Path;
    use std::ffi::OsString;
    use winapi::um::winnt::{self, WinLocalSid, WinWorldSid};
    use winapi::um::accctrl::SE_FILE_OBJECT;

    const SEC_INFO: u32 = winnt::OWNER_SECURITY_INFORMATION
        | winnt::GROUP_SECURITY_INFORMATION
        | winnt::DACL_SECURITY_INFORMATION;

    #[test]
    fn well_known_sids_are_equal() {
        let world_sid_1 = CreateWellKnownSid(WinWorldSid).unwrap();
        let world_sid_2 = CreateWellKnownSid(WinWorldSid).unwrap();
        let local_sid_1 = CreateWellKnownSid(WinLocalSid).unwrap();
        let local_sid_2 = CreateWellKnownSid(WinLocalSid).unwrap();

        assert!(EqualSid(&world_sid_1, &world_sid_2));
        assert!(EqualSid(&local_sid_1, &local_sid_2));
        assert!(!EqualSid(&world_sid_1, &local_sid_2));
        assert!(!EqualSid(&local_sid_1, &world_sid_2));
    }

    #[test]
    fn well_known_sids_stringify() {
        let world_sid = CreateWellKnownSid(WinWorldSid).unwrap();
        let local_sid = CreateWellKnownSid(WinLocalSid).unwrap();

        assert_eq!(ConvertSidToStringSid(&world_sid), Ok(OsString::from("S-1-1-0")));
        assert_eq!(ConvertSidToStringSid(&local_sid), Ok(OsString::from("S-1-2-0")));
    }

    #[test]
    fn cargo_toml_is_owned() {
        let cargo_toml_path =
            Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("Cargo.toml");

        let sd = GetNamedSecurityInfo(cargo_toml_path.as_os_str(), SE_FILE_OBJECT, SEC_INFO).unwrap();

        assert!(sd.owner().is_some());
        assert!(sd.group().is_some());
    }
}
