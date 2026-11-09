use core::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    ptr,
};

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_RINGBUF,
    cty::c_void,
    helpers::{
        bpf_ringbuf_discard, bpf_ringbuf_output, bpf_ringbuf_query, bpf_ringbuf_reserve,
        bpf_ringbuf_submit,
    },
    maps::{MapDef, PinningType},
};

/// An eBPF ring buffer.
///
/// ```no_run
/// use aya_ebpf::maps::RingBuf;
///
/// let ring = RingBuf::with_byte_size(4096, 0);
/// if let Some(mut entry) = ring.reserve::<u32>(0) {
///     entry.write(42);
///     entry.submit(0);
/// }
/// ```
#[repr(transparent)]
pub struct RingBuf {
    def: MapDef,
}

impl super::private::Map for RingBuf {
    type Key = ();
    type Value = ();
}

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
        unsafe { bpf_ringbuf_submit(inner.as_mut_ptr().cast(), flags) }
    }

    /// Discard this ring buffer entry. The entry will be skipped by the userspace reader.
    pub fn discard(self, flags: u64) {
        let Self(inner) = self;
        unsafe { bpf_ringbuf_discard(inner.as_mut_ptr().cast(), flags) }
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
    pub(crate) fn reserve(map: *mut c_void, flags: u64) -> Option<Self> {
        const { assert!(align_of::<T>() <= 8) };
        let ptr = unsafe { bpf_ringbuf_reserve(map, size_of::<T>() as u64, flags) }
            .cast::<MaybeUninit<T>>();
        // SAFETY: the kernel provides an exclusive, eight-byte-aligned reservation.
        // The assertion above ensures that it is also aligned for T.
        unsafe { ptr.as_mut() }.map(Self)
    }

    /// Discard this ring buffer entry. The entry will be skipped by the userspace reader.
    pub fn discard(self, flags: u64) {
        let Self(inner) = self;
        unsafe { bpf_ringbuf_discard(inner.as_mut_ptr().cast(), flags) }
    }

    /// Commit this ring buffer entry. The entry will be made visible to the userspace reader.
    pub fn submit(self, flags: u64) {
        let Self(inner) = self;
        unsafe { bpf_ringbuf_submit(inner.as_mut_ptr().cast(), flags) }
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
            def: MapDef::new::<(), ()>(BPF_MAP_TYPE_RINGBUF, byte_size, flags, pinning_type),
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
        let ptr = unsafe { bpf_ringbuf_reserve(self.def.as_ptr().cast(), size as u64, flags) }
            .cast::<u8>();
        unsafe { RingBufBytes::from_raw(ptr, size) }
    }

    /// Reserve memory in the ring buffer that can fit `T`.
    ///
    /// Returns `None` if the ring buffer is full.
    ///
    /// The kernel guarantees eight-byte alignment. Reserving a type with a
    /// greater alignment is a compile-time error:
    ///
    /// ```compile_fail,E0080
    /// use aya_ebpf::maps::RingBuf;
    ///
    /// #[repr(align(16))]
    /// struct Event([u64; 2]);
    ///
    /// let ring = RingBuf::with_byte_size(4096, 0);
    /// let _entry = ring.reserve::<Event>(0);
    /// ```
    pub fn reserve<T: 'static>(&self, flags: u64) -> Option<RingBufEntry<T>> {
        RingBufEntry::reserve(self.def.as_ptr().cast(), flags)
    }

    /// Copy `data` to the ring buffer output.
    ///
    /// Consider using [`reserve`] and [`submit`] if `T` is statically sized and you want to save a
    /// copy from either a map buffer or the stack.
    ///
    /// Unlike [`reserve`], this function can handle dynamically sized types (which is hard to
    /// create in eBPF but still possible, e.g. by slicing an array).
    ///
    /// The kernel guarantees only eight-byte alignment for the copy in the ring
    /// buffer, regardless of the input's alignment.
    ///
    /// [`reserve`]: RingBuf::reserve
    /// [`submit`]: RingBufEntry::submit
    pub fn output<T: ?Sized>(&self, data: &T, flags: u64) -> Result<(), i32> {
        let ret = unsafe {
            bpf_ringbuf_output(
                self.def.as_ptr().cast(),
                ptr::from_ref(data).cast_mut().cast(),
                size_of_val(data) as u64,
                flags,
            )
        };
        if ret < 0 { Err(ret as i32) } else { Ok(()) }
    }

    /// Query various information about the ring buffer.
    ///
    /// Consult `bpf_ringbuf_query` documentation for a list of allowed flags.
    pub fn query(&self, flags: u64) -> u64 {
        unsafe { bpf_ringbuf_query(self.def.as_ptr().cast(), flags) }
    }
}
