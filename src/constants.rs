use winapi::um::accctrl::*;

/// Create an enum from a list of constants. Generated enums get a method
/// `from_raw` that allows them to be converted from a value.
macro_rules! constant_enum {
    ( $name:ident; $int:ident; $( $item:ident),* ) => {
        #[derive(Debug, PartialEq)]
        #[allow(non_camel_case_types)]
        #[repr(C)]
        pub enum $name {

        $(
            $item = $item as isize,
        )*

        }

        impl $name {
            pub fn from_raw(raw: $int) -> Option<Self> {
                match raw {
                    $( $item => Some($name::$item), )*
                    _ => None,
                }
            }
        }
    }
}

constant_enum!(TrusteeForm; u32;
               TRUSTEE_IS_SID,
               TRUSTEE_IS_NAME,
               TRUSTEE_BAD_FORM,
               TRUSTEE_IS_OBJECTS_AND_SID,
               TRUSTEE_IS_OBJECTS_AND_NAME);

constant_enum!(TrusteeType; u32;
              TRUSTEE_IS_UNKNOWN,
              TRUSTEE_IS_USER,
              TRUSTEE_IS_GROUP,
              TRUSTEE_IS_DOMAIN,
              TRUSTEE_IS_ALIAS,
              TRUSTEE_IS_WELL_KNOWN_GROUP,
              TRUSTEE_IS_DELETED,
              TRUSTEE_IS_INVALID,
              TRUSTEE_IS_COMPUTER);

constant_enum!(MultipleTrusteeOperation; u32;
               NO_MULTIPLE_TRUSTEE,
               TRUSTEE_IS_IMPERSONATE);

#[cfg(test)]
mod test {
    const A: u8 = 5;
    const B: u8 = 10;
    const C: u8 = 15;
    const INVALID: u8 = 100;

    constant_enum!(TestEnum; u8; A, B, C);

    #[test]
    fn constant_enum_works() {
        let enum_a = TestEnum::A;
        let enum_b = TestEnum::B;
        let enum_c = TestEnum::C;

        assert_eq!(None, TestEnum::from_raw(INVALID));
        assert_eq!(enum_a, TestEnum::from_raw(A).unwrap());
        assert_eq!(enum_b, TestEnum::from_raw(B).unwrap());
        assert_eq!(enum_c, TestEnum::from_raw(C).unwrap());
    }
}
