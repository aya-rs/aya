use core::{borrow::Borrow, marker::PhantomData, ptr};

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_BLOOM_FILTER,
    helpers::{bpf_map_peek_elem, bpf_map_push_elem},
    maps::{MapDef, PinningType},
};

#[repr(transparent)]
pub struct BloomFilter<T> {
    def: MapDef,
    _t: PhantomData<T>,
}

impl<T> BloomFilter<T> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self::new(max_entries, flags, PinningType::None)
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self::new(max_entries, flags, PinningType::ByName)
    }

    const fn new(max_entries: u32, flags: u32, pinning: PinningType) -> Self {
        Self {
            def: MapDef::new::<(), T>(BPF_MAP_TYPE_BLOOM_FILTER, max_entries, flags, pinning),
            _t: PhantomData,
        }
    }

    #[inline]
    pub fn contains(&mut self, value: impl Borrow<T>) -> Result<(), i64> {
        let ret = unsafe {
            bpf_map_peek_elem(
                self.def.as_ptr().cast(),
                ptr::from_ref(value.borrow()).cast_mut().cast(),
            )
        };
        (ret == 0).then_some(()).ok_or(ret)
    }

    #[inline]
    pub fn insert(&mut self, value: impl Borrow<T>, flags: u64) -> Result<(), i64> {
        let ret = unsafe {
            bpf_map_push_elem(
                self.def.as_ptr().cast(),
                ptr::from_ref(value.borrow()).cast(),
                flags,
            )
        };
        (ret == 0).then_some(()).ok_or(ret)
    }
}
