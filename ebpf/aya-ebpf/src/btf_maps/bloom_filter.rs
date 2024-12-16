use core::{cell::UnsafeCell, ptr};

use aya_ebpf_bindings::helpers::{bpf_map_peek_elem, bpf_map_push_elem};

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_BLOOM_FILTER, btf_maps::AyaBtfMapMarker, cty::c_void,
};

#[allow(dead_code)]
pub struct BloomFilterDef<T, const M: usize, const H: usize = 5, const F: usize = 0> {
    r#type: *const [i32; BPF_MAP_TYPE_BLOOM_FILTER as usize],
    value: *const T,
    max_entries: *const [i32; M],
    map_extra: *const [i32; H],
    map_flags: *const [i32; F],

    // Anonymize the struct.
    _anon: AyaBtfMapMarker,
}

#[repr(transparent)]
pub struct BloomFilter<T, const M: usize, const H: usize = 5, const F: usize = 0>(
    UnsafeCell<BloomFilterDef<T, M, H, F>>,
);

impl<T, const M: usize, const H: usize, const F: usize> BloomFilter<T, M, H, F> {
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        BloomFilter(UnsafeCell::new(BloomFilterDef {
            r#type: &[0i32; BPF_MAP_TYPE_BLOOM_FILTER as usize] as *const _,
            value: ptr::null(),
            max_entries: &[0i32; M] as *const _,
            map_extra: &[0i32; H] as *const _,
            map_flags: &[0i32; F] as *const _,
            _anon: AyaBtfMapMarker::new(),
        }))
    }

    #[inline]
    pub fn contains(&mut self, value: &T) -> Result<(), i64> {
        let ret = unsafe {
            bpf_map_peek_elem(
                &mut self.0.get() as *mut _ as *mut _,
                value as *const _ as *mut c_void,
            )
        };
        (ret == 0).then_some(()).ok_or(ret)
    }

    #[inline]
    pub fn insert(&mut self, value: &T, flags: u64) -> Result<(), i64> {
        let ret = unsafe {
            bpf_map_push_elem(
                &mut self.0.get() as *mut _ as *mut _,
                value as *const _ as *const _,
                flags,
            )
        };
        (ret == 0).then_some(()).ok_or(ret)
    }
}
