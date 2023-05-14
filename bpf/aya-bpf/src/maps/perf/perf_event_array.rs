use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    mem::{self, MaybeUninit},
};

use aya_bpf_bindings::{bindings::bpf_perf_event_value, helpers::bpf_perf_event_read_value};

use crate::{
    bindings::{
        bpf_map_def, bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY, BPF_F_CURRENT_CPU,
        BPF_F_INDEX_MASK,
    },
    helpers::bpf_perf_event_output,
    maps::PinningType,
    BpfContext,
};

/// A map of type `BPF_MAP_TYPE_PERF_EVENT_ARRAY`.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to read perf_event values using [PerfEventArray] is 4.15.
/// This concerns the functions [`PerfEventArray::read_current_cpu()`] and [`PerfEventArray::read_at_index()`].
///
/// # Example
///
/// ```no_run
/// #[map]
/// static mut DESCRIPTORS: PerfEventArray<i32> = PerfEventArray::with_max_entries(1, 0);
///
/// pub fn read_event() -> Result<u64, i64> {
///     let event: bpf_perf_event_value = unsafe { DESCRIPTORS.read_current_cpu() }?;
///     let value: u64 = event.counter;
///     Ok(value)
/// }
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

    pub fn output_current_cpu<C: BpfContext>(&self, ctx: &C, data: &T) -> Result<(), i64> {
        self.output(ctx, data, BPF_F_CURRENT_CPU)
    }

    pub fn output_at_index<C: BpfContext>(&self, ctx: &C, data: &T, index: u32) -> Result<(), i64> {
        self.output(ctx, data, u64::from(index) & BPF_F_INDEX_MASK)
    }

    fn output<C: BpfContext>(&self, ctx: &C, data: &T, flags: u64) -> Result<(), i64> {
        let ret = unsafe {
            bpf_perf_event_output(
                ctx.as_ptr(),
                self.def.get() as *mut _,
                flags,
                data as *const _ as *mut _,
                mem::size_of::<T>() as u64,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(ret)
        }
    }

    pub fn read_current_cpu(&self) -> Result<bpf_perf_event_value, i64> {
        self.read(BPF_F_CURRENT_CPU)
    }

    pub fn read_at_index(&self, index: u32) -> Result<bpf_perf_event_value, i64> {
        self.read(u64::from(index) & BPF_F_INDEX_MASK)
    }

    fn read(&self, flags: u64) -> Result<bpf_perf_event_value, i64> {
        let mut buf = MaybeUninit::<bpf_perf_event_value>::uninit();
        let ret = unsafe {
            // According to the Linux manual (see `man bpf-helpers`), `bpf_perf_event_read_value` is recommended over `bpf_perf_event_read`.
            bpf_perf_event_read_value(
                self.def.get() as *mut _,
                flags,
                buf.as_mut_ptr(),
                mem::size_of::<bpf_perf_event_value>() as u32,
            )
        };
        if ret == 0 {
            let value = unsafe { buf.assume_init() };
            Ok(value)
        } else {
            Err(ret)
        }
    }
}
