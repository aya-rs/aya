use core::{
    marker::PhantomData,
    mem::{self, MaybeUninit},
    ops::ControlFlow,
    ptr,
};

use aya_ebpf_cty::{c_long, c_void};

use crate::{
    bindings::{bpf_dynptr, bpf_map_type::BPF_MAP_TYPE_USER_RINGBUF},
    helpers::{bpf_dynptr_read, bpf_user_ringbuf_drain},
    maps::{MapDef, PinningType},
};

/// A ring buffer map that user space publishes into and an eBPF program drains.
///
/// `UserRingBuf` is the user-space-to-kernel counterpart of [`RingBuf`]: user space
/// reserves and submits samples into the ring, and the eBPF program consumes them by
/// calling [`UserRingBuf::drain`], which runs a callback over each pending sample.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 6.1.
///
/// [`RingBuf`]: super::RingBuf
#[repr(transparent)]
pub struct UserRingBuf {
    def: MapDef,
}

impl super::private::Map for UserRingBuf {
    type Key = ();
    type Value = ();
}

impl UserRingBuf {
    /// Declares an eBPF user ring buffer.
    ///
    /// The Linux kernel requires that `byte_size` be a power-of-2 multiple of the page
    /// size. The loading program may coerce the size when loading the map.
    pub const fn with_byte_size(byte_size: u32, flags: u32) -> Self {
        Self::new(byte_size, flags, PinningType::None)
    }

    /// Declares a pinned eBPF user ring buffer.
    ///
    /// The Linux kernel requires that `byte_size` be a power-of-2 multiple of the page
    /// size. The loading program may coerce the size when loading the map.
    pub const fn pinned(byte_size: u32, flags: u32) -> Self {
        Self::new(byte_size, flags, PinningType::ByName)
    }

    const fn new(byte_size: u32, flags: u32, pinning_type: PinningType) -> Self {
        Self {
            def: MapDef::new::<(), ()>(BPF_MAP_TYPE_USER_RINGBUF, byte_size, flags, pinning_type),
        }
    }

    /// Drains the samples published by user space, running `callback` over each one.
    ///
    /// The callback returns [`ControlFlow::Continue`] to consume the next sample, or
    /// [`ControlFlow::Break`] to stop early. It must not capture any state, because the
    /// kernel verifier requires it to be a standalone program; communicate through other
    /// maps instead.
    ///
    /// Returns the number of samples drained.
    ///
    /// # Errors
    ///
    /// Returns a negative errno on failure: `-EBUSY` if another context is already
    /// draining the ring, `-EINVAL` for invalid `flags`, or `-E2BIG` for an oversized
    /// sample.
    pub fn drain<F>(&self, callback: F, flags: u64) -> Result<u32, i32>
    where
        F: Fn(UserRingBufEntry<'_>) -> ControlFlow<()>,
    {
        drain(self.def.as_ptr(), callback, flags)
    }
}

/// A read-only sample drained from a [`UserRingBuf`].
///
/// The sample's backing memory is owned by user space, so an eBPF program may only read
/// it. The entry must not outlive the drain callback.
pub struct UserRingBufEntry<'a> {
    dynptr: *mut bpf_dynptr,
    _marker: PhantomData<&'a [u8]>,
}

impl UserRingBufEntry<'_> {
    /// Reads the sample, interpreting its bytes as `T`.
    ///
    /// Returns `None` if the sample is shorter than `size_of::<T>()`.
    ///
    /// # Safety
    ///
    /// The sample bytes are published by user space and are not validated, so the caller must
    /// ensure they form a valid bit pattern for `T`. Reading a type that has invalid bit patterns
    /// (`bool`, `char`, enums, `NonZero` integers, references, or any aggregate containing them)
    /// from untrusted bytes is undefined behavior.
    pub unsafe fn read<T>(&self) -> Option<T> {
        let mut value = MaybeUninit::<T>::uninit();
        let ret = unsafe {
            bpf_dynptr_read(
                value.as_mut_ptr().cast(),
                size_of::<T>() as u32,
                self.dynptr,
                0,
                0,
            )
        };
        // SAFETY: a return value of 0 means `size_of::<T>()` bytes were written to `value`.
        (ret == 0).then(|| unsafe { value.assume_init() })
    }
}

/// Drains a user ring buffer identified by `map`, shared by the legacy and BTF
/// [`UserRingBuf`] wrappers.
pub(crate) fn drain<F>(map: *mut c_void, _callback: F, flags: u64) -> Result<u32, i32>
where
    F: Fn(UserRingBufEntry<'_>) -> ControlFlow<()>,
{
    // The kernel requires the callback to be a standalone BPF program (ARG_PTR_TO_FUNC),
    // so it cannot capture state.
    const {
        assert!(
            size_of::<F>() == 0,
            "user ring buffer drain callback must not capture state"
        )
    };

    unsafe extern "C" fn trampoline<F>(dynptr: *mut bpf_dynptr, _ctx: *mut c_void) -> c_long
    where
        F: Fn(UserRingBufEntry<'_>) -> ControlFlow<()>,
    {
        // SAFETY: `F` is zero-sized (asserted in `drain`), so a value can be produced
        // without reading any memory.
        let callback = unsafe { mem::zeroed::<F>() };
        let entry = UserRingBufEntry {
            dynptr,
            _marker: PhantomData,
        };
        match callback(entry) {
            ControlFlow::Continue(()) => 0,
            ControlFlow::Break(()) => 1,
        }
    }

    let ret = unsafe {
        bpf_user_ringbuf_drain(
            map,
            trampoline::<F> as *const () as *mut c_void,
            ptr::null_mut(),
            flags,
        )
    };
    u32::try_from(ret).map_err(|_err| ret as i32)
}
