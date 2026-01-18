use core::{
    borrow::Borrow,
    cell::UnsafeCell,
    mem,
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};

#[cfg(generic_const_exprs)]
use crate::const_assert::{Assert, IsTrue};
use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_RINGBUF},
    helpers::{
        bpf_ringbuf_discard, bpf_ringbuf_output, bpf_ringbuf_query, bpf_ringbuf_reserve,
        bpf_ringbuf_submit,
    },
    maps::{InnerMap, PinningType},
};

#[repr(transparent)]
pub struct RingBuf {
    def: UnsafeCell<bpf_map_def>,
}

unsafe impl Sync for RingBuf {}
impl super::private::Sealed for RingBuf {}
unsafe impl InnerMap for RingBuf {}

/// A ring buffer entry, returned from [`RingBuf::reserve_bytes`].
///
/// You must [`submit`] or [`discard`] this entry before it gets dropped.
///
/// [`submit`]: RingBufBytes::submit
/// [`discard`]: RingBufBytes::discard
#[must_use = "eBPF verifier requires ring buffer entries to be either submitted or discarded"]
pub struct RingBufBytes<'a>(&'a mut [u8]);

impl Deref for RingBufBytes<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let Self(inner) = self;
        inner
    }
}

impl DerefMut for RingBufBytes<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let Self(inner) = self;
        inner
    }
}

impl RingBufBytes<'_> {
    pub(crate) unsafe fn from_raw(ptr: *mut u8, size: usize) -> Option<Self> {
        (!ptr.is_null())
            .then(|| unsafe { core::slice::from_raw_parts_mut(ptr, size) })
            .map(Self)
    }

    /// Commit this ring buffer entry. The entry will be made visible to the userspace reader.
    pub fn submit(self, flags: u64) {
        let Self(inner) = self;
        unsafe { bpf_ringbuf_submit(inner.as_mut_ptr().cast(), flags) };
    }

    /// Discard this ring buffer entry. The entry will be skipped by the userspace reader.
    pub fn discard(self, flags: u64) {
        let Self(inner) = self;
        unsafe { bpf_ringbuf_discard(inner.as_mut_ptr().cast(), flags) };
    }
}

/// A ring buffer entry, returned from [`RingBuf::reserve`].
///
/// You must [`submit`] or [`discard`] this entry before it gets dropped.
///
/// [`submit`]: RingBufEntry::submit
/// [`discard`]: RingBufEntry::discard
#[must_use = "eBPF verifier requires ring buffer entries to be either submitted or discarded"]
pub struct RingBufEntry<T: 'static>(&'static mut MaybeUninit<T>);

impl<T> Deref for RingBufEntry<T> {
    type Target = MaybeUninit<T>;

    fn deref(&self) -> &Self::Target {
        let Self(inner) = self;
        inner
    }
}

impl<T> DerefMut for RingBufEntry<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let Self(inner) = self;
        inner
    }
}

impl<T> RingBufEntry<T> {
    pub(crate) unsafe fn from_raw(ptr: *mut MaybeUninit<T>) -> Option<Self> {
        unsafe { ptr.as_mut() }.map(Self)
    }

    /// Discard this ring buffer entry. The entry will be skipped by the userspace reader.
    pub fn discard(self, flags: u64) {
        let Self(inner) = self;
        unsafe { bpf_ringbuf_discard(inner.as_mut_ptr().cast(), flags) };
    }

    /// Commit this ring buffer entry. The entry will be made visible to the userspace reader.
    pub fn submit(self, flags: u64) {
        let Self(inner) = self;
        unsafe { bpf_ringbuf_submit(inner.as_mut_ptr().cast(), flags) };
    }
}

impl RingBuf {
    /// Declare an eBPF ring buffer.
    ///
    /// The linux kernel requires that `byte_size` be a power-of-2 multiple of the page size. The
    /// loading program may coerce the size when loading the map.
    pub const fn with_byte_size(byte_size: u32, flags: u32) -> Self {
        Self::new(byte_size, flags, PinningType::None)
    }

    /// Declare a pinned eBPF ring buffer.
    ///
    /// The linux kernel requires that `byte_size` be a power-of-2 multiple of the page size. The
    /// loading program may coerce the size when loading the map.
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

    /// Reserve a dynamically sized byte buffer in the ring buffer.
    ///
    /// Returns `None` if the ring buffer is full.
    ///
    /// Note that using this method requires care; the verifier does not allow truly dynamic
    /// allocation sizes. In other words, it is incumbent upon users of this function to convince
    /// the verifier that `size` is a compile-time constant. Good luck!
    pub fn reserve_bytes(&self, size: usize, flags: u64) -> Option<RingBufBytes<'_>> {
        let ptr =
            unsafe { bpf_ringbuf_reserve(self.def.get().cast(), size as u64, flags) }.cast::<u8>();
        unsafe { RingBufBytes::from_raw(ptr, size) }
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
        let ptr = unsafe {
            bpf_ringbuf_reserve(self.def.get().cast(), mem::size_of::<T>() as u64, flags)
        }
        .cast::<MaybeUninit<T>>();
        unsafe { RingBufEntry::from_raw(ptr) }
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
    pub fn output<T: ?Sized>(&self, data: impl Borrow<T>, flags: u64) -> Result<(), i64> {
        let data = data.borrow();
        assert_eq!(8 % mem::align_of_val(data), 0);
        let ret = unsafe {
            bpf_ringbuf_output(
                self.def.get().cast(),
                core::ptr::from_ref(data).cast_mut().cast(),
                mem::size_of_val(data) as u64,
                flags,
            )
        };
        if ret < 0 { Err(ret) } else { Ok(()) }
    }

    /// Query various information about the ring buffer.
    ///
    /// Consult `bpf_ringbuf_query` documentation for a list of allowed flags.
    pub fn query(&self, flags: u64) -> u64 {
        unsafe { bpf_ringbuf_query(self.def.get().cast(), flags) }
    }
}
