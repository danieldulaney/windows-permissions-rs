extern crate winapi;

pub mod structures;
pub mod utilities;
mod wrappers;

pub use structures::{SecurityDescriptor, Sid};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
