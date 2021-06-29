# Windows permissions

Safe Rust bindings to Windows permissions APIs.

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]

[crates-badge]: https://img.shields.io/crates/v/windows-permissions
[crates-url]: https://crates.io/crates/windows-permissions
[docs-badge]: https://docs.rs/windows-permissions/badge.svg
[docs-url]: https://docs.rs/windows-permissions

## Overview

This crate provides safe Rust wrappers over several Windows permissions concepts,
including:

- SID (Security Identifier)
- ACL (Access Control List)
- ACE (Access Control Entry)
- SD (Security Descriptor)

There are two kinds of abstractions:

- The primary Windows data structures are available and can be used directly.
- In the `wrappers` crate, there are safe versions of the Windows API functions.
  Any Windows API function not implemented should be reported as an issue.

## Contributing

PRs are happily accepted! In general, `unsafe` code should be confined to the
`wrappers` module -- the rest of this crate should be implemented 
safely based on that code.

Help wanted:

- Make `wrappers` more complete with additional Windows API functions
- Add new data structures that cover more of the permissions APIs
