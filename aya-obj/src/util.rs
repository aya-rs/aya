use core::{ptr, slice};
#[cfg(feature = "std")]
pub(crate) use std::collections::HashMap;
#[cfg(feature = "std")]
pub(crate) use std::collections::HashSet;

#[cfg(not(feature = "std"))]
pub(crate) use hashbrown::HashMap;
#[cfg(not(feature = "std"))]
pub(crate) use hashbrown::HashSet;

/// Converts a <T> to a byte slice.
pub(crate) const unsafe fn bytes_of<T>(val: &T) -> &[u8] {
    unsafe { slice::from_raw_parts(ptr::from_ref(val).cast(), size_of_val(val)) }
}
