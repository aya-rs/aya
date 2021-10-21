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
/// You must [`submit`] or [`discard`] this entry before this gets dropped.
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
    /// `max_entries` must be a power of two.
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> RingBuf {
        RingBuf {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_RINGBUF,
                key_size: 0,
                value_size: 0,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
        }
    }

    /// Declare a pinned BPF ring buffer.
    ///
    /// `max_entries` must be a power of two.
    pub const fn pinned(max_entries: u32, flags: u32) -> RingBuf {
        RingBuf {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_RINGBUF,
                key_size: 0,
                value_size: 0,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
        }
    }

    /// Reserve memory in the ring buffer that can fit `T`.
    ///
    /// Returns `None` if the ring buffer is full, or a reference to the allocated memory if the
    /// allocation succeeds.
    ///
    /// If the return value is not None, you must commit or discard the reserved entry through a
    /// call to [`RingBufEntry::submit`] or [`RingBufEntry::discard`].
    ///
    /// `T` must be aligned to 1, 2, 4 or 8 bytes; it's not possible to fulfill larger alignment
    /// requests. If you use this with a `T` that isn't properly aligned, this function will
    /// be compiled to a panic and silently make your eBPF program fail to load.
    pub fn reserve<T: 'static>(&self, flags: u64) -> Option<RingBufEntry<T>> {
        // The reserved pointer may be null, which we handle with an Option.
        // We also need to ensure that the returned pointer is of a proper sized allocation and
        // satisfies T's alignment requirements.
        // Finally, cast it to an MaybeUninit as creating a reference to uninitialized memory is UB.

        // ringbuf allocations are aligned to 8 bytes (hardcoded in kernel code).
        assert!(8 % mem::align_of::<T>() == 0);

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
    /// redundant allocation on and a copy from the stack.
    ///
    /// Unlike [`reserve`], this function can handle dynamically sized types (which is hard to
    /// create in eBPF but still possible, e.g. by slicing an array).
    ///
    /// `T` must be aligned to 1, 2, 4 or 8 bytes; it's not possible to fulfill larger alignment
    /// requests. If you use this with a `T` that isn't properly aligned, this function will
    /// be compiled to a panic and silently make your eBPF program fail to load.
    ///
    /// [`reserve`]: RingBuf::reserve
    /// [`submit`]: RingBufEntry::submit
    pub fn output<T: ?Sized>(&self, data: &T, flags: u64) -> Result<(), i64> {
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
