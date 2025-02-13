use core::mem;

mod perf_event_array;
mod perf_event_byte_array;

pub use perf_event_array::PerfEventArray;
pub use perf_event_byte_array::PerfEventByteArray;

use crate::{bindings::bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY, btf_maps::AyaBtfMapMarker};

#[allow(dead_code)]
pub struct PerfEventArrayDef<const F: usize = 0> {
    r#type: *const [i32; BPF_MAP_TYPE_PERF_EVENT_ARRAY as usize],
    key_size: *const [i32; mem::size_of::<u32>()],
    value_size: *const [i32; mem::size_of::<u32>()],
    max_entries: *const [i32; 0],
    map_flags: *const [i32; F],

    // Anonymize the struct.
    _anon: AyaBtfMapMarker,
}

impl<const F: usize> PerfEventArrayDef<F> {
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            r#type: &[0i32; BPF_MAP_TYPE_PERF_EVENT_ARRAY as usize],
            key_size: &[0i32; mem::size_of::<u32>()],
            value_size: &[0i32; mem::size_of::<u32>()],
            max_entries: &[0i32; 0],
            map_flags: &[0i32; F],
            _anon: AyaBtfMapMarker::new(),
        }
    }
}
