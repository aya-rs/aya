use core::mem::MaybeUninit;

use crate::{bindings::bpf_perf_event_value, cty::c_void, helpers::bpf_perf_event_read_value};

mod perf_event_array;
mod perf_event_byte_array;

pub use perf_event_array::PerfEventArray;
pub use perf_event_byte_array::PerfEventByteArray;

/// A perf event counter reading.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfEventValue {
    /// The raw counter value.
    pub counter: u64,
    /// Duration in nanoseconds for which the event was enabled.
    pub enabled_nanos: u64,
    /// Duration in nanoseconds for which the event was running.
    pub running_nanos: u64,
}

#[inline(always)]
pub(crate) fn read_value(map: *mut c_void, index: u32) -> Result<PerfEventValue, i32> {
    let mut value = MaybeUninit::uninit();
    let ret = unsafe {
        bpf_perf_event_read_value(
            map,
            u64::from(index),
            value.as_mut_ptr(),
            size_of::<bpf_perf_event_value>() as u32,
        )
    };
    if ret != 0 {
        return Err(ret as i32);
    }

    // SAFETY: bpf_perf_event_read_value initializes every field on success.
    let bpf_perf_event_value {
        counter,
        enabled: enabled_nanos,
        running: running_nanos,
    } = unsafe { value.assume_init() };
    Ok(PerfEventValue {
        counter,
        enabled_nanos,
        running_nanos,
    })
}
