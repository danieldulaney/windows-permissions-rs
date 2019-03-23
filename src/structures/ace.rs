use crate::constants::{AceFlags, AceType};
use std::fmt;
use std::mem;
use std::ptr::NonNull;
use winapi::um::winnt::ACE_HEADER;

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
    /// ## Requirements
    ///
    /// - `ptr` must point to a valid ACE structure
    /// - The ACE header must be followed by the correct ACE structure
    /// - The entire structure must remain alive at least as long as `'s`
    pub unsafe fn ref_from_nonnull<'s>(ptr: NonNull<ACE_HEADER>) -> &'s Self {
        mem::transmute(ptr)
    }

    /// Determine the type of ACE
    pub fn ace_type(&self) -> AceType {
        AceType::from_raw(self.header.AceType).expect("ACE had invalid header byte")
    }

    /// Get the option flags set on the ACE
    pub fn flags(&self) -> AceFlags {
        debug_assert!(AceFlags::from_bits(self.header.AceFlags).is_some());
        AceFlags::from_bits_truncate(self.header.AceFlags)
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
    use crate::{LocalBox, SecurityDescriptor};

    enum DaclSacl {
        Dacl,
        Sacl,
    }

    use DaclSacl::{Dacl, Sacl};

    #[test]
    fn get_type() {
        use crate::constants::AceType::*;

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
            ("(A;;;;;WD)", ACCESS_ALLOWED_ACE_TYPE, Dacl),
            ("(D;;;;;WD)", ACCESS_DENIED_ACE_TYPE, Dacl),
            ("(AU;;;;;WD)", SYSTEM_AUDIT_ACE_TYPE, Sacl),
            ("(XU;;;;;WD;(TRUE))", SYSTEM_AUDIT_CALLBACK_ACE_TYPE, Sacl),
            ("(XA;;;;;WD;(TRUE))", ACCESS_ALLOWED_CALLBACK_ACE_TYPE, Dacl),
            ("(XD;;;;;WD;(TRUE))", ACCESS_DENIED_CALLBACK_ACE_TYPE, Dacl),
            (
                "(OA;;;c434c045-9b91-4504-a2a0-aea9e781ec69;;WD)",
                ACCESS_ALLOWED_OBJECT_ACE_TYPE,
                Dacl,
            ),
            (
                "(OD;;;c434c045-9b91-4504-a2a0-aea9e781ec69;;WD)",
                ACCESS_DENIED_OBJECT_ACE_TYPE,
                Dacl,
            ),
            (
                "(OU;;;c434c045-9b91-4504-a2a0-aea9e781ec69;;WD)",
                SYSTEM_AUDIT_OBJECT_ACE_TYPE,
                Sacl,
            ),
            (
                "(ZA;;;c434c045-9b91-4504-a2a0-aea9e781ec69;;WD;(TRUE))",
                ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
                Dacl,
            ),
            (
                r#"(RA;;;;;WD;("Secrecy",TU,0,3))"#,
                SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
                Sacl,
            ),
            ("(ML;;;;;HI)", SYSTEM_MANDATORY_LABEL_ACE_TYPE, Sacl),
            //("(SP;;;;;WD)", SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, Sacl),
        ];

        for (sddl_string, ace_type, which_acl) in test_cases.iter() {
            eprintln!("Testing {} yields {:?}", sddl_string, ace_type);

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
