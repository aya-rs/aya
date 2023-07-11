use core::{
    cell::UnsafeCell,
    mem,
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_RINGBUF},
    helpers::{
        bpf_ringbuf_discard, bpf_ringbuf_output, bpf_ringbuf_query, bpf_ringbuf_reserve,
        bpf_ringbuf_submit,
    },
    maps::PinningType,
};

#[repr(transparent)]
pub struct RingBuf {
    def: UnsafeCell<bpf_map_def>,
}

unsafe impl Sync for RingBuf {}

/// A ring buffer entry, returned from [`RingBuf::reserve`].
///
/// You must [`submit`] or [`discard`] this entry before it gets dropped.
///
/// [`submit`]: RingBufEntry::submit
/// [`discard`]: RingBufEntry::discard
#[must_use = "BPF verifier requires ring buffer entries to be either submitted or discarded"]
pub struct RingBufEntry<T: 'static>(&'static mut MaybeUninit<T>);

impl<T> Deref for RingBufEntry<T> {
    type Target = MaybeUninit<T>;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<T> DerefMut for RingBufEntry<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

impl<T> RingBufEntry<T> {
    /// Discard this ring buffer entry. The entry will be skipped by the userspace reader.
    pub fn discard(self, flags: u64) {
        unsafe { bpf_ringbuf_discard(self.0.as_mut_ptr() as *mut _, flags) };
    }

    /// Commit this ring buffer entry. The entry will be made visible to the userspace reader.
    pub fn submit(self, flags: u64) {
        unsafe { bpf_ringbuf_submit(self.0.as_mut_ptr() as *mut _, flags) };
    }
}

impl RingBuf {
    /// Declare a BPF ring buffer.
    ///
    /// If `byte_size` is not a power-of-2 multiple of the page size, libbpf and aya will
    /// coerced it to the next largest valid size when the program is loaded. This is a
    /// requirement of the underlying kernel ring buffer implementation.
    pub const fn with_byte_size(byte_size: u32, flags: u32) -> Self {
        Self::new(byte_size, flags, PinningType::None)
    }

    /// Declare a pinned BPF ring buffer.
    ///
    /// If `byte_size` is not a power-of-2 multiple of the page size, libbpf and aya will
    /// coerced it to the next largest valid size when the program is loaded. This is a
    /// requirement of the underlying kernel ring buffer implementation.
    pub const fn pinned(byte_size: u32, flags: u32) -> Self {
        Self::new(byte_size, flags, PinningType::ByName)
    }

    const fn new(byte_size: u32, flags: u32, pinning_type: PinningType) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_RINGBUF,
                key_size: 0,
                value_size: 0,
                max_entries: byte_size,
                map_flags: flags,
                id: 0,
                pinning: pinning_type as u32,
            }),
        }
    }

    /// Reserve memory in the ring buffer that can fit `T`.
    ///
    /// Returns `None` if the ring buffer is full.
    #[cfg(feature = "const_assert")]
    pub fn reserve<T: 'static>(&self, flags: u64) -> Option<RingBufEntry<T>>
    where
        Assert<{ 8 % core::mem::align_of::<T>() == 0 }>: IsTrue,
    {
        self.reserve_impl(flags)
    }

    /// Reserve memory in the ring buffer that can fit `T`.
    ///
    /// Returns `None` if the ring buffer is full.
    ///
    /// Note: `T` must be aligned to no more than 8 bytes it's not possible to fulfill larger
    /// alignment requests. If you use this with a `T` that isn't properly aligned, this function will
    /// be compiled to a panic and silently make your eBPF program fail to load.
    #[cfg(not(feature = "const_assert"))]
    pub fn reserve<T: 'static>(&self, flags: u64) -> Option<RingBufEntry<T>> {
        assert!(8 % core::mem::align_of::<T>() == 0);
        self.reserve_impl(flags)
    }

    fn reserve_impl<T: 'static>(&self, flags: u64) -> Option<RingBufEntry<T>> {
        let ptr = unsafe {
            bpf_ringbuf_reserve(self.def.get() as *mut _, mem::size_of::<T>() as _, flags)
                as *mut MaybeUninit<T>
        };
        match ptr.is_null() {
            true => None,
            false => Some(RingBufEntry(unsafe { &mut *ptr })),
        }
    }

    /// Copy `data` to the ring buffer output.
    ///
    /// Consider using [`reserve`] and [`submit`] if `T` is statically sized and you want to save a
    /// copy from either a map buffer or the stack.
    ///
    /// Unlike [`reserve`], this function can handle dynamically sized types (which is hard to
    /// create in eBPF but still possible, e.g. by slicing an array).
    ///
    /// [`reserve`]: RingBuf::reserve
    /// [`submit`]: RingBufEntry::submit
    #[cfg(feature = "const_assert")]
    pub fn output<T: ?Sized>(&self, data: &T, flags: u64) -> Result<(), i64>
    where
        Assert<{ 8 % core::mem::align_of::<&T>() == 0 }>: IsTrue,
    {
        assert!(8 % core::mem::align_of::<&T>() == 0);
        self.output_impl(data, flags)
    }

    /// Copy `data` to the ring buffer output.
    ///
    /// Consider using [`reserve`] and [`submit`] if `T` is statically sized and you want to save a
    /// copy from either a map buffer or the stack.
    ///
    /// Unlike [`reserve`], this function can handle dynamically sized types (which is hard to
    /// create in eBPF but still possible, e.g. by slicing an array).
    ///
    /// Note: `T` must be aligned to no more than 8 bytes it's not possible to fulfill larger
    /// alignment requests. If you use this with a `T` that isn't properly aligned, this function will
    /// be compiled to a panic and silently make your eBPF program fail to load.
    ///
    /// [`reserve`]: RingBuf::reserve
    /// [`submit`]: RingBufEntry::submit
    #[cfg(not(feature = "const_assert"))]
    pub fn output<T: ?Sized>(&self, data: &T, flags: u64) -> Result<(), i64> {
        assert!(8 % core::mem::align_of::<&T>() == 0);
        self.output_impl(data, flags)
    }

    fn output_impl<T: ?Sized>(&self, data: &T, flags: u64) -> Result<(), i64> {
        // See `reserve` for alignment requirements.
        assert!(8 % mem::align_of_val(data) == 0);

        let ret = unsafe {
            bpf_ringbuf_output(
                self.def.get() as *mut _,
                data as *const _ as *mut _,
                mem::size_of_val(data) as _,
                flags,
            )
        };
        if ret < 0 {
            Err(ret)
        } else {
            Ok(())
        }
    }

    /// Query various information about the ring buffer.
    ///
    /// Consult `bpf_ringbuf_query` documentation for a list of allowed flags.
    pub fn query(&self, flags: u64) -> u64 {
        unsafe { bpf_ringbuf_query(self.def.get() as *mut _, flags) }
    }
}

#[cfg(feature = "const_assert")]
pub struct Assert<const COND: bool> {}
#[cfg(feature = "const_assert")]
pub trait IsTrue {}
#[cfg(feature = "const_assert")]
impl IsTrue for Assert<true> {}
