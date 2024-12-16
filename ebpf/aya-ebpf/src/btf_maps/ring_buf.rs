use core::{
    cell::UnsafeCell,
    mem::{self, MaybeUninit},
};

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_RINGBUF,
    btf_maps::AyaBtfMapMarker,
    helpers::{bpf_ringbuf_output, bpf_ringbuf_query, bpf_ringbuf_reserve},
    maps::ring_buf::RingBufEntry,
};

#[cfg(generic_const_exprs)]
mod const_assert {
    pub struct Assert<const COND: bool> {}

    pub trait IsTrue {}

    impl IsTrue for Assert<true> {}
}
#[cfg(generic_const_exprs)]
use const_assert::{Assert, IsTrue};

#[allow(dead_code)]
pub struct RingBufDef<const S: usize, const F: usize = 0> {
    r#type: *const [i32; BPF_MAP_TYPE_RINGBUF as usize],
    max_entries: *const [i32; S],

    // Anonymize the struct.
    _anon: AyaBtfMapMarker,
}

#[repr(transparent)]
pub struct RingBuf<const S: usize, const F: usize = 0>(UnsafeCell<RingBufDef<S, F>>);

unsafe impl<const S: usize, const F: usize> Sync for RingBuf<S, F> {}

impl<const S: usize, const F: usize> RingBuf<S, F> {
    /// Declare an eBPF ring buffer.
    ///
    /// The linux kernel requires that `byte_size` be a power-of-2 multiple of the page size. The
    /// loading program may coerce the size when loading the map.
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(RingBufDef {
            r#type: &[0i32; BPF_MAP_TYPE_RINGBUF as usize],
            max_entries: &[0i32; S],
            _anon: AyaBtfMapMarker::new(),
        }))
    }

    /// Reserve memory in the ring buffer that can fit `T`.
    ///
    /// Returns `None` if the ring buffer is full.
    #[cfg(generic_const_exprs)]
    pub fn reserve<T: 'static>(&self, flags: u64) -> Option<RingBufEntry<T>>
    where
        Assert<{ 8 % mem::align_of::<T>() == 0 }>: IsTrue,
    {
        self.reserve_impl(flags)
    }

    /// Reserve memory in the ring buffer that can fit `T`.
    ///
    /// Returns `None` if the ring buffer is full.
    ///
    /// The kernel will reserve memory at an 8-bytes aligned boundary, so `mem::align_of<T>()` must
    /// be equal or smaller than 8. If you use this with a `T` that isn't properly aligned, this
    /// function will be compiled to a panic; depending on your panic_handler, this may make
    /// the eBPF program fail to load, or it may make it have undefined behavior.
    #[cfg(not(generic_const_exprs))]
    pub fn reserve<T: 'static>(&self, flags: u64) -> Option<RingBufEntry<T>> {
        assert_eq!(8 % mem::align_of::<T>(), 0);
        self.reserve_impl(flags)
    }

    fn reserve_impl<T: 'static>(&self, flags: u64) -> Option<RingBufEntry<T>> {
        let ptr =
            unsafe { bpf_ringbuf_reserve(self.0.get() as *mut _, mem::size_of::<T>() as _, flags) }
                as *mut MaybeUninit<T>;
        unsafe { ptr.as_mut() }.map(|ptr| RingBufEntry::new(ptr))
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
    pub fn output<T: ?Sized>(&self, data: &T, flags: u64) -> Result<(), i64> {
        assert_eq!(8 % mem::align_of_val(data), 0);
        let ret = unsafe {
            bpf_ringbuf_output(
                self.0.get() as *mut _,
                data as *const _ as *mut _,
                mem::size_of_val(data) as _,
                flags,
            )
        };
        if ret < 0 { Err(ret) } else { Ok(()) }
    }

    /// Query various information about the ring buffer.
    ///
    /// Consult `bpf_ringbuf_query` documentation for a list of allowed flags.
    pub fn query(&self, flags: u64) -> u64 {
        unsafe { bpf_ringbuf_query(self.0.get() as *mut _, flags) }
    }
}
