use windows_sys::Win32::Security::{self, ACE_HEADER};

use crate::constants::{AccessRights, AceFlags, AceType};
use crate::Sid;
use std::fmt;
use std::mem;
use std::ptr::NonNull;

/// An access control list.
///
/// See [MSDN](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header)
/// for layout details, or [ACCESS_ALLOWED_ACE on MSDN](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_ace)
/// for an example.
#[repr(C)]
pub struct Ace {
    header: ACE_HEADER,
}

impl Drop for Ace {
    fn drop(&mut self) {
        unreachable!("Ace should only be borrowed")
    }
}

impl Ace {
    /// Get a reference from an ACE pointer.
    ///
    /// # Safety
    ///
    /// - `ptr` must point to a valid ACE structure
    /// - The ACE header must be followed by the correct ACE structure
    /// - The entire structure must remain alive at least as long as `'s`
    pub unsafe fn ref_from_nonnull<'s>(ptr: NonNull<ACE_HEADER>) -> &'s Self {
        mem::transmute(ptr)
    }

    /// Determine the type of ACE
    pub fn ace_type(&self) -> AceType {
        AceType::from_raw(self.header.AceType as u32).expect("ACE had invalid header byte")
    }

    /// Get the option flags set on the ACE
    pub fn flags(&self) -> AceFlags {
        debug_assert!(AceFlags::from_bits(self.header.AceFlags).is_some());
        AceFlags::from_bits_truncate(self.header.AceFlags)
    }

    /// Get the access mask if it is available for this ACE type
    pub fn mask(&self) -> AccessRights {
        macro_rules! mask_mapping {
            ($slf:ident ; $($t:ident => $b:ty),*) => {{
                match $slf.ace_type() {
                    $(
                    AceType::$t => AccessRights::from_bits_truncate(
                        (*(&$slf.header as *const _ as *mut $b)).Mask,
                    ),
                    )*
                }
            }}
        }

        unsafe {
            mask_mapping! {self;
                ACCESS_ALLOWED_ACE_TYPE => Security::ACCESS_ALLOWED_ACE,
                ACCESS_ALLOWED_CALLBACK_ACE_TYPE => Security::ACCESS_ALLOWED_CALLBACK_ACE,
                ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => Security::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
                ACCESS_ALLOWED_OBJECT_ACE_TYPE => Security::ACCESS_ALLOWED_OBJECT_ACE,
                ACCESS_DENIED_ACE_TYPE => Security::ACCESS_DENIED_ACE,
                ACCESS_DENIED_CALLBACK_ACE_TYPE => Security::ACCESS_DENIED_ACE,
                ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => Security::ACCESS_DENIED_CALLBACK_OBJECT_ACE,
                ACCESS_DENIED_OBJECT_ACE_TYPE => Security::ACCESS_DENIED_OBJECT_ACE,
                SYSTEM_AUDIT_ACE_TYPE => Security::SYSTEM_AUDIT_ACE,
                SYSTEM_AUDIT_CALLBACK_ACE_TYPE => Security::SYSTEM_AUDIT_CALLBACK_ACE,
                SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE => Security::SYSTEM_AUDIT_CALLBACK_ACE,
                SYSTEM_AUDIT_OBJECT_ACE_TYPE => Security::SYSTEM_AUDIT_OBJECT_ACE,
                SYSTEM_MANDATORY_LABEL_ACE_TYPE => Security::SYSTEM_MANDATORY_LABEL_ACE,
                SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE => Security::SYSTEM_RESOURCE_ATTRIBUTE_ACE,
                SYSTEM_SCOPED_POLICY_ID_ACE_TYPE => Security::SYSTEM_SCOPED_POLICY_ID_ACE
            }
        }
    }

    /// Get the SID if it is available for this ACE type
    pub fn sid(&self) -> Option<&Sid> {
        use windows_sys::Win32::Security::{
            ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT,
        };

        macro_rules! get_sid {
            ($slf:ident ; $ace_type:ty ; $sid_field:ident ) => {
                Some(
                    &*(&(*(&$slf.header as *const ACE_HEADER as *const $ace_type)).$sid_field
                        as *const _ as *const Sid),
                )
            };
            ($slf:ident ; $ace_type:ty) => {
                get_sid!($slf ; $ace_type ; SidStart)
            };
            ($slf:ident ; $ace_type:ty ; $field_none:ident , $field_one:ident, $field_both:ident) => {{
                let flags = (*(&$slf.header as *const ACE_HEADER as *const $ace_type)).Flags;
                let obj_pres = flags & ACE_OBJECT_TYPE_PRESENT != 0;
                let inh_pres = flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0;
                match (obj_pres, inh_pres) {
                    (false, false) => get_sid!($slf ; $ace_type ; $field_none),
                    (true,  false) => get_sid!($slf ; $ace_type ; $field_one),
                    (false, true ) => get_sid!($slf ; $ace_type ; $field_one),
                    (true,  true ) => get_sid!($slf ; $ace_type ; $field_both),
                }}
            };
        }

        unsafe {
            match self.ace_type() {
                AceType::ACCESS_ALLOWED_ACE_TYPE => get_sid!(self; Security::ACCESS_ALLOWED_ACE),
                AceType::ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {
                    get_sid!(self; Security::ACCESS_ALLOWED_CALLBACK_ACE)
                }
                AceType::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                    get_sid!(self; Security::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE;
                    ObjectType, InheritedObjectType, SidStart)
                }
                AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE => {
                    get_sid!(self; Security::ACCESS_ALLOWED_OBJECT_ACE;
                    ObjectType, InheritedObjectType, SidStart)
                }
                AceType::ACCESS_DENIED_ACE_TYPE => get_sid!(self; Security::ACCESS_DENIED_ACE),
                AceType::ACCESS_DENIED_CALLBACK_ACE_TYPE => {
                    get_sid!(self; Security::ACCESS_DENIED_ACE)
                }
                AceType::ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => {
                    get_sid!(self; Security::ACCESS_DENIED_CALLBACK_OBJECT_ACE;
                    ObjectType, InheritedObjectType, SidStart)
                }
                AceType::ACCESS_DENIED_OBJECT_ACE_TYPE => {
                    get_sid!(self; Security::ACCESS_DENIED_OBJECT_ACE;
                    ObjectType, InheritedObjectType, SidStart)
                }
                AceType::SYSTEM_AUDIT_ACE_TYPE => get_sid!(self; Security::SYSTEM_AUDIT_ACE),
                AceType::SYSTEM_AUDIT_CALLBACK_ACE_TYPE => {
                    get_sid!(self; Security::SYSTEM_AUDIT_CALLBACK_ACE)
                }
                AceType::SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE => {
                    get_sid!(self; Security::SYSTEM_AUDIT_CALLBACK_ACE; SidStart)
                }
                AceType::SYSTEM_AUDIT_OBJECT_ACE_TYPE => {
                    get_sid!(self; Security::SYSTEM_AUDIT_OBJECT_ACE;
                    ObjectType, InheritedObjectType, SidStart)
                }
                AceType::SYSTEM_MANDATORY_LABEL_ACE_TYPE => {
                    get_sid!(self; Security::SYSTEM_MANDATORY_LABEL_ACE)
                }
                AceType::SYSTEM_SCOPED_POLICY_ID_ACE_TYPE => {
                    get_sid!(self; Security::SYSTEM_SCOPED_POLICY_ID_ACE)
                }
                AceType::SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE => None, // TODO: Resource attributes are more complex
            }
        }
    }
}

impl fmt::Debug for Ace {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut map = fmt.debug_map();
        map.entry(&"ace_type", &self.ace_type());
        map.entry(&"flags", &self.flags());
        map.finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{wrappers, LocalBox, SecurityDescriptor};

    enum DaclSacl {
        Dacl,
        Sacl,
    }

    use DaclSacl::{Dacl, Sacl};

    #[test]
    fn mandatory_label() {
        let access_rights = [
            ("NR", AccessRights::MandatoryLabelNoReadUp),
            ("NW", AccessRights::MandatoryLabelNoWriteUp),
            ("NX", AccessRights::MandatoryLabelNoExecuteUp),
        ];

        let test_setups = [
            ("(ML;;", ";;;LW)", Security::WinLowLabelSid),
            ("(ML;;", ";;;ME)", Security::WinMediumLabelSid),
            ("(ML;;", ";;;HI)", Security::WinHighLabelSid),
        ];

        for (sddl1, sddl2, sid_type) in test_setups.iter() {
            for (mask_sddl, mask_value) in access_rights.iter() {
                let sd: LocalBox<SecurityDescriptor> = format!("S:{}{}{}", sddl1, mask_sddl, sddl2)
                    .parse()
                    .unwrap();

                let ace = sd.sacl().unwrap().get_ace(0).unwrap();

                assert_eq!(ace.ace_type(), AceType::SYSTEM_MANDATORY_LABEL_ACE_TYPE);
                assert_eq!(ace.mask(), *mask_value);
                assert_eq!(
                    ace.sid().unwrap(),
                    &*wrappers::CreateWellKnownSid(*sid_type, None).unwrap()
                );
            }
        }
    }

    #[test]
    fn resource_attribute() {
        // These are weird enough that they get their own tests
        let sd: LocalBox<SecurityDescriptor> =
            r#"S:(RA;;;;;WD;("Secrecy",TU,0,3))"#.parse().unwrap();
        let ace = sd.sacl().unwrap().get_ace(0).unwrap();

        assert_eq!(ace.mask(), AccessRights::empty());
        assert_eq!(ace.sid(), None);
    }

    #[test]
    fn standard_ace() {
        use crate::constants::AccessRights;
        use crate::constants::AceType::*;

        let access_rights = [
            ("", AccessRights::empty()),
            ("GA", AccessRights::GenericAll),
            ("GR", AccessRights::GenericRead),
            ("GW", AccessRights::GenericWrite),
            ("GX", AccessRights::GenericExecute),
            ("RC", AccessRights::ReadControl),
            ("SD", AccessRights::Delete),
            ("WD", AccessRights::WriteDac),
            ("WO", AccessRights::WriteOwner),
            ("FA", AccessRights::FileAllAccess),
            ("FR", AccessRights::FileGenericRead),
            ("FW", AccessRights::FileGenericWrite),
            ("FX", AccessRights::FileGenericExecute),
            ("KA", AccessRights::KeyAllAccess),
            ("KR", AccessRights::KeyRead),
            ("KW", AccessRights::KeyWrite),
            ("KX", AccessRights::KeyExecute),
            (
                "GRGWRCSDWD",
                AccessRights::GenericRead
                    | AccessRights::GenericWrite
                    | AccessRights::ReadControl
                    | AccessRights::Delete
                    | AccessRights::WriteDac,
            ),
        ];

        // In order: (SDDL ACE, expected type, acl to use)
        //
        // The GUIDs are required because Windows automatically replaces object-
        // based ACEs with their non-object counterparts when no GUID is
        // specified. The GUID here is randomly generated, and doesn't refer
        // to anything in particular.
        //
        // ACEs with "CALLBACK" in their type take a conditional function.
        // "(TRUE)" is a valid (if useless) parameter.
        //
        // RA requires an extra parameter defining a resource attribute.
        //
        // TODO: I couldn't get SP to work on my machine.
        let test_cases = [
            ("(A;;", ";;;", ")", ACCESS_ALLOWED_ACE_TYPE, Dacl),
            ("(D;;", ";;;", ")", ACCESS_DENIED_ACE_TYPE, Dacl),
            ("(AU;;", ";;;", ")", SYSTEM_AUDIT_ACE_TYPE, Sacl),
            (
                "(XU;;",
                ";;;",
                ";(TRUE))",
                SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
                Sacl,
            ),
            (
                "(XA;;",
                ";;;",
                ";(TRUE))",
                ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
                Dacl,
            ),
            (
                "(XD;;",
                ";;;",
                ";(TRUE))",
                ACCESS_DENIED_CALLBACK_ACE_TYPE,
                Dacl,
            ),
            (
                "(OA;;",
                ";c434c045-9b91-4504-a2a0-aea9e781ec69;;",
                ")",
                ACCESS_ALLOWED_OBJECT_ACE_TYPE,
                Dacl,
            ),
            (
                "(OD;;",
                ";c434c045-9b91-4504-a2a0-aea9e781ec69;;",
                ")",
                ACCESS_DENIED_OBJECT_ACE_TYPE,
                Dacl,
            ),
            (
                "(OU;;",
                ";c434c045-9b91-4504-a2a0-aea9e781ec69;;",
                ")",
                SYSTEM_AUDIT_OBJECT_ACE_TYPE,
                Sacl,
            ),
            (
                "(ZA;;",
                ";c434c045-9b91-4504-a2a0-aea9e781ec69;;",
                ";(TRUE))",
                ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
                Dacl,
            ),
        ];

        for (base_sddl_1, base_sddl_2, base_sddl_3, ace_type, which_acl) in test_cases.iter() {
            for (access_rights_sddl, access_rights_value) in access_rights.iter() {
                for (sid, _, _) in Sid::test_sids() {
                    let mut sddl_string = String::new();
                    sddl_string.push_str(base_sddl_1);
                    sddl_string.push_str(access_rights_sddl);
                    sddl_string.push_str(base_sddl_2);
                    sddl_string.push_str(&sid.to_string());
                    sddl_string.push_str(base_sddl_3);

                    //eprintln!("Testing {} yields {:?}, {:?}", sddl_string, ace_type, access_rights_value);

                    dbg!(&sddl_string);

                    let sd: LocalBox<SecurityDescriptor> = match which_acl {
                        Dacl => format!("D:{}", sddl_string),
                        Sacl => format!("S:{}", sddl_string),
                    }
                    .parse()
                    .unwrap();

                    let acl = match which_acl {
                        Dacl => sd.dacl(),
                        Sacl => sd.sacl(),
                    }
                    .unwrap();

                    assert_eq!(acl.len(), 1);

                    let ace = acl.get_ace(0).unwrap();

                    assert_eq!(ace.ace_type(), *ace_type);
                    assert_eq!(ace.sid(), Some(&*sid));
                    assert_eq!(ace.mask(), *access_rights_value);
                }
            }
        }
    }

    #[test]
    fn get_flags_dacl() {
        let test_cases = [
            ("", AceFlags::empty(), Dacl),
            ("", AceFlags::empty(), Sacl),
            ("CI", AceFlags::ContainerInherit, Dacl),
            ("OI", AceFlags::ObjectInherit, Dacl),
            ("NP", AceFlags::NoPropagateInherit, Dacl),
            ("IO", AceFlags::InheritOnly, Dacl),
            ("ID", AceFlags::Inherited, Dacl),
            ("SA", AceFlags::SuccessfulAccess, Sacl),
            ("FA", AceFlags::FailedAccess, Sacl),
            (
                "CIOINPIOID",
                AceFlags::ContainerInherit
                    | AceFlags::ObjectInherit
                    | AceFlags::NoPropagateInherit
                    | AceFlags::InheritOnly
                    | AceFlags::Inherited,
                Dacl,
            ),
            (
                "SAFA",
                AceFlags::SuccessfulAccess | AceFlags::FailedAccess,
                Sacl,
            ),
        ];

        for (sddl, flag, which_acl) in test_cases.iter() {
            eprintln!("Testing {} yields {:?}", sddl, flag);

            let sd: LocalBox<SecurityDescriptor> = match which_acl {
                Dacl => format!("D:(A;{};;;;WD)", sddl),
                Sacl => format!("S:(AU;{};;;;WD)", sddl),
            }
            .parse()
            .unwrap();

            let acl = match which_acl {
                Dacl => sd.dacl(),
                Sacl => sd.sacl(),
            }
            .unwrap();

            assert_eq!(acl.get_ace(0).unwrap().flags(), *flag);
        }
    }
}
