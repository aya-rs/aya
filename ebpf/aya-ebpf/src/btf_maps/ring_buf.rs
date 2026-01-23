use core::{borrow::Borrow, mem, mem::MaybeUninit, ptr};

#[cfg(generic_const_exprs)]
use crate::const_assert::{Assert, IsTrue};
use crate::{
    btf_maps::btf_map_def,
    helpers::{bpf_ringbuf_output, bpf_ringbuf_reserve},
    maps::ring_buf::{RingBufBytes, RingBufEntry},
};

btf_map_def!(
    /// A BTF-compatible BPF ring buffer map.
    ///
    /// Ring buffers have a special `value_size` field set to 0.
    pub struct RingBuf<T, const M: usize, const F: usize>,
    map_type: BPF_MAP_TYPE_RINGBUF,
    key: (),
    value_size: *const [i32; 0],
);

impl<T, const M: usize, const F: usize> RingBuf<T, M, F> {
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
    #[cfg(generic_const_exprs)]
    pub fn reserve(&self, flags: u64) -> Option<RingBufEntry<T>>
    where
        T: 'static,
        Assert<{ 8 % mem::align_of::<T>() == 0 }>: IsTrue,
    {
        self.reserve_untyped::<T>(flags)
    }

    /// Reserve memory in the ring buffer that can fit the map's `T`.
    ///
    /// Returns `None` if the ring buffer is full.
    ///
    /// The kernel will reserve memory at an 8-bytes aligned boundary, so `mem::align_of<U>()` must
    /// be equal or smaller than 8. If you use this with a `U` that isn't properly aligned, this
    /// function will be compiled to a panic; depending on your panic_handler, this may make
    /// the eBPF program fail to load, or it may make it have undefined behavior.
    #[cfg(not(generic_const_exprs))]
    pub fn reserve(&self, flags: u64) -> Option<RingBufEntry<T>>
    where
        T: 'static,
    {
        self.reserve_untyped::<T>(flags)
    }

    /// Reserve memory in the ring buffer that can fit `U`.
    ///
    /// Returns `None` if the ring buffer is full.
    #[cfg(generic_const_exprs)]
    pub fn reserve_untyped<U: 'static>(&self, flags: u64) -> Option<RingBufEntry<U>>
    where
        Assert<{ 8 % mem::align_of::<U>() == 0 }>: IsTrue,
    {
        self.reserve_impl::<U>(flags)
    }

    /// Reserve memory in the ring buffer that can fit `U`.
    ///
    /// Returns `None` if the ring buffer is full.
    #[cfg(not(generic_const_exprs))]
    pub fn reserve_untyped<U: 'static>(&self, flags: u64) -> Option<RingBufEntry<U>> {
        assert_eq!(8 % mem::align_of::<U>(), 0);
        self.reserve_impl::<U>(flags)
    }

    fn reserve_impl<U: 'static>(&self, flags: u64) -> Option<RingBufEntry<U>> {
        let ptr = unsafe { bpf_ringbuf_reserve(self.as_ptr(), mem::size_of::<U>() as u64, flags) }
            .cast::<MaybeUninit<U>>();
        unsafe { RingBufEntry::from_raw(ptr) }
    }

    /// Copy `data` to the ring buffer output using the map's `T`.
    pub fn output(&self, data: impl Borrow<T>, flags: u64) -> Result<(), i64> {
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
    /// Note: `T` must be aligned to no more than 8 bytes; it's not possible to fulfill larger
    /// alignment requests. If you use this with a `T` that isn't properly aligned, this function will
    /// be compiled to a panic and silently make your eBPF program fail to load.
    /// See [here](https://github.com/torvalds/linux/blob/3f01e9fed/kernel/bpf/ringbuf.c#L418).
    ///
    /// [`reserve`]: RingBuf::reserve
    /// [`submit`]: RingBufEntry::submit
    pub fn output_untyped<U: ?Sized>(&self, data: impl Borrow<U>, flags: u64) -> Result<(), i64> {
        let data = data.borrow();
        assert_eq!(8 % mem::align_of_val(data), 0);
        let ret = unsafe {
            bpf_ringbuf_output(
                self.as_ptr(),
                ptr::from_ref(data).cast_mut().cast(),
                mem::size_of_val(data) as u64,
                flags,
            )
        };
        if ret < 0 { Err(ret) } else { Ok(()) }
    }
}
