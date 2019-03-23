use crate::constants::LocalAllocFlags;
use std::cmp::PartialEq;
use std::fmt;
use std::io;
use std::ops::Deref;
use std::ptr::{null_mut, NonNull};

/// Windows has several different options for allocation
pub struct LocalBox<T> {
    ptr: NonNull<T>,
}

impl<T> LocalBox<T> {
    /// Get a `LocalBox` from a `NonNull`
    ///
    /// ## Requirements
    ///
    /// - The `NonNull` pointer *must* have been allocated with
    /// a Windows API call. When the resulting `NonNull<T>` is dropped, it
    /// will be dropped with `LocalFree`
    /// - The buffer pointed to by the pointer must be a valid `T`
    pub unsafe fn from_raw(ptr: NonNull<T>) -> Self {
        // Future maintainers:
        // This function contains no unsafe code, but it requires that
        // callers fulfil an un-checked promise that is relied on by other
        // actually unsafe code. Do not remove the unsafe marker without
        // fully understanding the implications.
        Self { ptr }
    }

    /// Allocate memory with `LocalAlloc`
    ///
    /// If the allocation fails, returns the error code.
    ///
    /// ## Safety
    ///
    /// The contents of the memory are not guaranteed to be a valid `T`. The
    /// contents will either be zeroed or uninitialized depending on the `zeroed`
    /// parameter.
    ///
    /// Additionally, `size` should be large enough to contain a `T`.
    pub unsafe fn try_allocate(zeroed: bool, size: usize) -> io::Result<Self> {
        let flags = match zeroed {
            true => LocalAllocFlags::Fixed | LocalAllocFlags::ZeroInit,
            false => LocalAllocFlags::Fixed,
        };

        let ptr = winapi::um::winbase::LocalAlloc(flags.bits(), size);

        Ok(Self {
            ptr: NonNull::new(ptr as *mut _).ok_or_else(|| io::Error::last_os_error())?,
        })
    }

    /// Get a pointer to the underlying data structure
    ///
    /// Use this when interacting with FFI libraries that want pointers.
    pub fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }
}

impl<T> Drop for LocalBox<T> {
    fn drop(&mut self) {
        let result = unsafe { winapi::um::winbase::LocalFree(self.as_ptr() as *mut _) };
        debug_assert_eq!(result, null_mut());
    }
}

impl<T> Deref for LocalBox<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { std::mem::transmute::<NonNull<T>, &T>(self.ptr) }
    }
}

impl<T: fmt::Display> fmt::Display for LocalBox<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.deref().fmt(fmt)
    }
}

impl<T: fmt::Debug> fmt::Debug for LocalBox<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.deref().fmt(fmt)
    }
}

impl<T, U> PartialEq<LocalBox<U>> for LocalBox<T>
where
    T: PartialEq<U>,
{
    fn eq(&self, other: &LocalBox<U>) -> bool {
        self.deref().eq(other.deref())
    }
}
