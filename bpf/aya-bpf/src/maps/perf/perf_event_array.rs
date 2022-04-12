use core::{cell::UnsafeCell, marker::PhantomData, mem};

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY, BPF_F_CURRENT_CPU},
    helpers::bpf_perf_event_output,
    maps::PinningType,
    BpfContext,
};

/// An array for pushing out custom event data (as a struct defined by
/// developer) to user space.
///
/// # Minimum kernel version
///
/// The minimum kernel version for this feature is 4.3.
///
/// # Examples
///
/// ```no_run
/// use aya_bpf::{macros::map, maps::PerfEventArray};
/// use aya_bpf::programs::XdpContext};
///
/// #[repr(C)]
/// #[derive(Clone, Copy)]
/// pub struct PacketLog {
///     pub ipv4_address: u32,
///     pub port: u32,
/// }
///
/// #[map]
/// static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::with_max_entries(1024, 0);
///
/// # unsafe fn try_test(ctx: &XdpContext) -> Result<i32, i32> {
/// let ipv4_address = parse_source_ipv4_address(&ctx.data);
/// let port = parse_source_port(&ctx.data);
/// let packet_log = Entry {
///    ipv4_address,
///    port,
/// };
/// EVENTS.output(ctx, &packet_log, 0);
/// # Ok(0)
/// # }
/// ```
#[repr(transparent)]
pub struct PerfEventArray<T> {
    def: UnsafeCell<bpf_map_def>,
    _t: PhantomData<T>,
}

unsafe impl<T: Sync> Sync for PerfEventArray<T> {}

impl<T> PerfEventArray<T> {
    pub const fn new(flags: u32) -> PerfEventArray<T> {
        PerfEventArray::with_max_entries(0, flags)
    }

    /// Creates an `PerfEventArray` with the maximum number of elements.
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> PerfEventArray<T> {
        PerfEventArray {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
            _t: PhantomData,
        }
    }

    /// Creates an `PerfEventArray` pinned in the BPPFS filesystem, with the
    /// maximum number of elements.
    pub const fn pinned(max_entries: u32, flags: u32) -> PerfEventArray<T> {
        PerfEventArray {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
            _t: PhantomData,
        }
    }

    /// Outputs the given event to the array.
    ///
    /// ```no_run
    /// use aya_bpf::{macros::map, maps::PerfEventArray};
    /// # use aya_bpf::programs::LsmContext;
    ///
    /// #[repr(C)]
    /// pub struct Entry {
    ///     pub some_field: u32,
    /// }
    ///
    /// #[map]
    /// static mut EVENTS: PerfEventArray<Entry> = PerfEventArray::<Entry>::with_max_entries(1024, 0);
    ///
    /// # unsafe fn try_test(ctx: &LsmContext) -> Result<i32, i32> {
    /// let entry = Entry { some_field: 42 };
    /// EVENTS.output(ctx, &entry, 0);
    /// # Ok(0)
    /// # }
    /// ```
    pub fn output<C: BpfContext>(&self, ctx: &C, data: &T, flags: u32) {
        self.output_at_index(ctx, BPF_F_CURRENT_CPU as u32, data, flags)
    }

    /// Outputs the given event to the array at the given index.
    pub fn output_at_index<C: BpfContext>(&self, ctx: &C, index: u32, data: &T, flags: u32) {
        let flags = (flags as u64) << 32 | index as u64;
        unsafe {
            bpf_perf_event_output(
                ctx.as_ptr(),
                self.def.get() as *mut _,
                flags,
                data as *const _ as *mut _,
                mem::size_of::<T>() as u64,
            );
        }
    }
}
