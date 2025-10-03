use core::ptr;

use crate::{
    btf_maps::btf_map_def,
    helpers::{bpf_ringbuf_output, bpf_ringbuf_reserve},
    maps::ring_buf::{RingBufBytes, RingBufEntry},
};

btf_map_def!(
    /// A BTF-compatible BPF ring buffer map.
    ///
    /// `T` records the event type in BTF. Aya and Cilium set the map's value
    /// size to zero when loading it, as required by the kernel.
    pub struct RingBuf<T; const MAX_ENTRIES: usize, const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_RINGBUF,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: (),
    value_type: T,
);

impl<T, const MAX_ENTRIES: usize, const FLAGS: usize> RingBuf<T, MAX_ENTRIES, FLAGS> {
    /// Reserve a dynamically sized byte buffer in the ring buffer.
    ///
    /// Returns `None` if the ring buffer is full.
    ///
    /// Note that using this method requires care; the verifier does not allow truly dynamic
    /// allocation sizes. In other words, it is incumbent upon users of this function to convince
    /// the verifier that `size` is a compile-time constant. Good luck!
    pub fn reserve_bytes(&self, size: usize, flags: u64) -> Option<RingBufBytes<'_>> {
        let ptr = unsafe { bpf_ringbuf_reserve(self.as_ptr(), size as u64, flags) }.cast::<u8>();
        unsafe { RingBufBytes::from_raw(ptr, size) }
    }

    /// Reserve memory in the ring buffer that can fit the map's `T`.
    ///
    /// Returns `None` if the ring buffer is full.
    ///
    /// See [`Self::reserve_untyped`] for the alignment padding convention.
    pub fn reserve(&self, flags: u64) -> Option<RingBufEntry<T>>
    where
        T: 'static,
    {
        self.reserve_untyped::<T>(flags)
    }

    /// Reserve memory in the ring buffer that can fit `U`.
    ///
    /// Returns `None` if the ring buffer is full.
    ///
    /// Types aligned to more than eight bytes reserve extra space for alignment.
    /// The userspace reader must skip this padding; use
    /// [`RingBufItem::as_value`](https://docs.rs/aya/latest/aya/maps/ring_buf/struct.RingBufItem.html#method.as_value).
    /// That method checks that the alignment does not exceed the system page size,
    /// so the kernel and userspace mappings agree on the payload's offset.
    /// Padding bytes have unspecified contents. Alignments above eight bytes
    /// require `CAP_PERFMON` (or `CAP_SYS_ADMIN`) when loading the program,
    /// because the verifier must allow extracting address bits.
    pub fn reserve_untyped<U: 'static>(&self, flags: u64) -> Option<RingBufEntry<U>> {
        RingBufEntry::reserve(self.as_ptr(), flags)
    }

    /// Copy `data` to the ring buffer output using the map's `T`.
    pub fn output(&self, data: &T, flags: u64) -> Result<(), i32> {
        self.output_untyped::<T>(data, flags)
    }

    /// Copy `data` to the ring buffer output.
    ///
    /// Consider using [`reserve`] and [`submit`] if `T` is statically sized and you want to save a
    /// copy from either a map buffer or the stack.
    ///
    /// Unlike [`reserve`], this function can handle dynamically sized types (which is hard to
    /// create in eBPF but still possible, e.g. by slicing an array).
    ///
    /// This method copies bytes without adding alignment padding, even for types
    /// aligned to more than eight bytes. Read those records as unaligned data.
    ///
    /// [`reserve`]: RingBuf::reserve
    /// [`submit`]: RingBufEntry::submit
    pub fn output_untyped<U: ?Sized>(&self, data: &U, flags: u64) -> Result<(), i32> {
        let ret = unsafe {
            bpf_ringbuf_output(
                self.as_ptr(),
                ptr::from_ref(data).cast_mut().cast(),
                size_of_val(data) as u64,
                flags,
            )
        };
        if ret < 0 { Err(ret as i32) } else { Ok(()) }
    }
}
