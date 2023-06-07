//! # Windows permissions
//!
//! Safe Rust bindings to Windows permissions APIs.
//!
//! ## Overview
//!
//! This crate provides safe Rust wrappers over several Windows permissions concepts,
//! including:
//!
//! - SID (Security Identifier)
//! - ACL (Access Control List)
//! - ACE (Access Control Entry)
//! - SD (Security Descriptor)
//!
//! There are two kinds of abstractions:
//!
//! - The primary Windows data structures are available and can be used directly.
//! - In the `wrappers` crate, there are safe versions of the Windows API functions.
//!   Any Windows API function not implemented should be reported as an issue.
//!
//! ## Contributing
//!
//! PRs are happily accepted! In general, `unsafe` code should be confined to the
//! [`wrappers`] module -- the rest of this crate should be implemented
//! safely based on that code.
//!
//! Help wanted:
//!
//! - Make [`wrappers`] more complete with additional Windows API functions
//! - Add new data structures that cover more of the permissions APIs

#![deny(missing_docs)]

#[macro_use]
extern crate bitflags;
extern crate windows_sys;

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
