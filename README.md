# Windows permissions

This crate provides safe Rust wrappers over several Windows permissions concepts,
including:
- SID (Security Identifier)
- ACL (Access Control List)
- ACE (Access Control Entry)
- SD (Security Descriptor)

There are two kinds of abstractions: First, the `wrappers` crate provides (near)
zero-cost abstractions that map directly to WinAPI function calls, but providing
safe Rust guarantees. These attempt to fully cover the entire API surface, so
that any activity can be performed.

Additionally, more "rustic" APIs are provided on each data structure.

## Contributing

PRs are happily accepted! In general, `unsafe` code should be confined to the
`wrappers` module -- the rest of this crate methods should be implemented in
safe ways based on that code. Additionally, please include tests for any
functionality you add.
