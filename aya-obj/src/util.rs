use core::{mem, slice};

/// bytes_of converts a <T> to a byte slice
pub(crate) unsafe fn bytes_of<T>(val: &T) -> &[u8] {
    let size = mem::size_of::<T>();
    slice::from_raw_parts(slice::from_ref(val).as_ptr().cast(), size)
}
