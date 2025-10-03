use core::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    ptr::{self, NonNull},
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
pub struct RingBufEntry<T: 'static> {
    value: &'static mut MaybeUninit<T>,
    reservation: NonNull<c_void>,
}

// SAFETY: the original pointer refers to the same exclusively owned reservation
// as value; it does not add shared access to T.
unsafe impl<T: Send> Send for RingBufEntry<T> {}
unsafe impl<T: Sync> Sync for RingBufEntry<T> {}

impl<T> Deref for RingBufEntry<T> {
    type Target = MaybeUninit<T>;

    fn deref(&self) -> &Self::Target {
        let Self {
            value,
            reservation: _,
        } = self;
        value
    }
}

impl<T> DerefMut for RingBufEntry<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let Self {
            value,
            reservation: _,
        } = self;
        value
    }
}

impl<T> RingBufEntry<T> {
    pub(crate) fn reserve(map: *mut c_void, flags: u64) -> Option<Self> {
        let size = size_of::<T>() + align_of::<T>().saturating_sub(8);
        let reservation = NonNull::new(unsafe { bpf_ringbuf_reserve(map, size as u64, flags) })?;
        let mut value = reservation.as_ptr().cast::<u8>();
        if align_of::<T>() > 8 {
            cfg_select! {
                target_arch = "bpf" => {
                    let address: usize;
                    // MOV32 turns the pointer into a scalar for the verifier,
                    // permitting the mask below. Rust alignments are at most
                    // 2^29, so the low 32 address bits suffice.
                    // https://github.com/torvalds/linux/blob/bcf876870/kernel/bpf/verifier.c#L6073-L6088
                    // https://github.com/rust-lang/rust/blob/a22b02eae/compiler/rustc_abi/src/lib.rs#L1134-L1144
                    unsafe {
                        core::arch::asm!(
                            "w0 = w1",
                            in("r1") value.addr(),
                            out("r0") address,
                            options(pure, nomem, nostack),
                        );
                    }
                }
                _ => {
                    let address = value.addr();
                }
            }
            // The kernel already guarantees eight-byte alignment. Keeping the
            // bottom three bits clear also makes that guarantee visible to the
            // verifier after adding this bounded scalar offset.
            let offset = address.wrapping_neg() & (align_of::<T>() - 8);
            value = unsafe { value.add(offset) };
        }
        // SAFETY: the reservation includes the largest possible alignment
        // padding, and value now satisfies T's alignment.
        let value = unsafe { &mut *value.cast::<MaybeUninit<T>>() };
        Some(Self { value, reservation })
    }

    /// Discard this ring buffer entry. The entry will be skipped by the userspace reader.
    pub fn discard(self, flags: u64) {
        let Self {
            value: _,
            reservation,
        } = self;
        unsafe { bpf_ringbuf_discard(reservation.as_ptr(), flags) }
    }

    /// Commit this ring buffer entry. The entry will be made visible to the userspace reader.
    pub fn submit(self, flags: u64) {
        let Self {
            value: _,
            reservation,
        } = self;
        unsafe { bpf_ringbuf_submit(reservation.as_ptr(), flags) }
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
    /// Types aligned to more than eight bytes reserve extra space for alignment.
    /// The userspace reader must skip this padding; use
    /// [`RingBufItem::as_value`](https://docs.rs/aya/latest/aya/maps/ring_buf/struct.RingBufItem.html#method.as_value).
    /// That method checks that the alignment does not exceed the system page size,
    /// so the kernel and userspace mappings agree on the payload's offset.
    /// Padding bytes have unspecified contents. Alignments above eight bytes
    /// require `CAP_PERFMON` (or `CAP_SYS_ADMIN`) when loading the program,
    /// because the verifier must allow extracting address bits.
    ///
    /// ```no_run
    /// use aya_ebpf::maps::RingBuf;
    ///
    /// #[repr(C, align(16))]
    /// struct Event([u64; 2]);
    ///
    /// let ring = RingBuf::with_byte_size(4096, 0);
    /// if let Some(mut entry) = ring.reserve::<Event>(0) {
    ///     entry.write(Event([1, 2]));
    ///     entry.submit(0);
    /// }
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
    /// This method copies bytes without adding alignment padding, even for types
    /// aligned to more than eight bytes. Read those records as unaligned data.
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
