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

pub use create_well_known_sid::CreateWellKnownSid;
pub use equal_sid::EqualSid;
pub use get_named_security_info::GetNamedSecurityInfo;
pub use lookup_account_sid::LookupAccountSid;
