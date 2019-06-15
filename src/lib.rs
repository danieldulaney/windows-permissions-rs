#[macro_use]
extern crate bitflags;
extern crate winapi;

#[cfg(target_os = "windows")]
pub mod constants;
#[cfg(target_os = "windows")]
pub mod localheap;
#[cfg(target_os = "windows")]
pub mod structures;
#[cfg(target_os = "windows")]
pub mod utilities;
#[cfg(target_os = "windows")]
pub mod wrappers;

#[cfg(target_os = "windows")]
mod windows_secure;

#[cfg(target_os = "windows")]
pub use localheap::LocalBox;
#[cfg(target_os = "windows")]
pub use structures::{Ace, Acl, SecurityDescriptor, Sid, Trustee};
#[cfg(target_os = "windows")]
pub use windows_secure::WindowsSecure;
