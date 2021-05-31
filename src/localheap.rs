//! A specialized [`Box`] variation for items stored on the local heap.

use crate::constants::LocalAllocFlags;
use std::borrow::{Borrow, BorrowMut};
use std::cmp::PartialEq;
use std::fmt;
use std::hash::Hash;
use std::io;
use std::ops::{Deref, DerefMut};
use std::ptr::{null_mut, NonNull};

/// A smart pointer to an object on the local heap.
///
/// Windows has several different options for allocation, and the local heap is
/// no longer recommended. However, several of the
/// WinAPI calls in this crate use the local heap, allocating with `LocalAlloc`
/// and freeing with `LocalFree`. This type encapsulates that behavior,
/// representing objects that reside on the local heap.
///
/// It is primarily created using `unsafe` code in the `wrappers` crate when
/// the WinAPI allocates a data structure for the program (using `from_raw`).
///
/// However, allocations can be manually made with `allocate` or `try_allocate`.
/// For example:
///
/// ```
/// use std::mem::size_of;
/// use windows_permissions::LocalBox;
///
/// let mut local_ptr1: LocalBox<u32> = unsafe { LocalBox::allocate() };
///
/// let mut local_ptr2: LocalBox<u32> = unsafe {
///     LocalBox::try_allocate(true, size_of::<u32>()).unwrap()
/// };
///
/// *local_ptr1 = 5u32;
/// *local_ptr2 = 5u32;
/// assert_eq!(local_ptr1, local_ptr2);
/// ```
///
/// For details, see [MSDN](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localalloc#parameters).
///
/// ## Exotically-sized types
///
/// This struct has not been tested with exotically-sized types. Use with
/// extreme caution.
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

    /// Allocate enough zeroed memory to hold a `T` with `LocalAlloc`
    ///
    /// The memory will always come back zeroed, which has a modest performance
    /// penalty but can reduce the impact of buffer overruns.
    ///
    /// ## Panics
    ///
    /// Panics if the underlying `LocalAlloc` call fails.
    ///
    /// ## Safety
    ///
    /// The allocated memory is zeroed, which may not be a valid representation
    /// of a `T`.
    pub unsafe fn allocate() -> Self {
        Self::try_allocate(true, std::mem::size_of::<T>())
            .expect("LocalAlloc failed to allocate memory")
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

impl<T> AsRef<T> for LocalBox<T> {
    fn as_ref(&self) -> &T {
        &*self
    }
}

impl<T> Deref for LocalBox<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> DerefMut for LocalBox<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.ptr.as_mut() }
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

impl<T> Hash for LocalBox<T>
where
    T: Hash
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.deref().hash(state)
    }
}

impl<T> Borrow<T> for LocalBox<T> {
    fn borrow(&self) -> &T {
        self.deref()
    }
}

impl<T> BorrowMut<T> for LocalBox<T> {
    fn borrow_mut(&mut self) -> &mut T {
        self.deref_mut()
    }
}

impl<T> Eq for LocalBox<T> where T: Eq {}
impl<T, U> PartialEq<LocalBox<U>> for LocalBox<T>
where
    T: PartialEq<U>,
{
    fn eq(&self, other: &LocalBox<U>) -> bool {
        self.deref().eq(other.deref())
    }
}

// Safety: LocalAlloc/LocalFree are wrapper functions that call the
// corresponding heap functions (HeapAlloc/HeapFree) using a handle to the
// process default heap. The HeapAlloc documentation states "Serialization
// ensures mutual exclusion when two or more threads attempt to simultaneously
// allocate or free blocks from the same heap." Serialization may be disabled
// with the HEAP_NO_SERIALIZE flag, but its documentation states "This value
// should not be specified when accessing the process's default heap." because
// the system may arbitrarily create threads that accesses that heap. Hence, it
// is safe to assume that LocalAlloc/LocalFree are serialized, and so LocalBox
// are safe to share across threads.
unsafe impl<U: Send> Send for LocalBox<U> {}
unsafe impl<U: Sync> Sync for LocalBox<U> {}