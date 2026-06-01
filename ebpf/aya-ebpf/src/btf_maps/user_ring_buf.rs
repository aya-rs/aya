use core::ops::ControlFlow;

use crate::{
    btf_maps::btf_map_def,
    maps::user_ring_buf::{UserRingBufEntry, drain},
};

btf_map_def!(
    /// A BTF-compatible BPF user ring buffer map.
    ///
    /// User ring buffers have a special `value_size` field set to 0.
    ///
    /// The minimum kernel version required to use this feature is 6.1.
    pub struct UserRingBuf<T; const MAX_ENTRIES: usize, const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_USER_RINGBUF,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: (),
    value_type: T,
    value_size: *const [i32; 0] = ::core::ptr::null(),
);

impl<T, const MAX_ENTRIES: usize, const FLAGS: usize> UserRingBuf<T, MAX_ENTRIES, FLAGS> {
    /// Drains the samples published by user space, running `callback` over each one.
    ///
    /// See [`UserRingBuf::drain`](crate::maps::UserRingBuf::drain) for the full contract.
    pub fn drain<F>(&self, callback: F, flags: u64) -> Result<u32, i32>
    where
        F: Fn(UserRingBufEntry<'_>) -> ControlFlow<()>,
    {
        drain(self.as_ptr().cast(), callback, flags)
    }
}
