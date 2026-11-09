use core::{marker::PhantomData, ptr};

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

impl<T> super::private::Map for BloomFilter<T> {
    type Key = ();
    type Value = T;
}

impl<T> BloomFilter<T> {
    map_constructors!((), T, BPF_MAP_TYPE_BLOOM_FILTER, phantom _t);

    #[inline]
    pub fn contains(&self, value: &T) -> Result<(), i32> {
        let ret = unsafe {
            bpf_map_peek_elem(
                self.def.as_ptr().cast(),
                ptr::from_ref(value).cast_mut().cast(),
            )
        };
        (ret == 0).then_some(()).ok_or(ret as i32)
    }

    #[inline]
    pub fn insert(&self, value: &T, flags: u64) -> Result<(), i32> {
        let ret = unsafe {
            bpf_map_push_elem(self.def.as_ptr().cast(), ptr::from_ref(value).cast(), flags)
        };
        (ret == 0).then_some(()).ok_or(ret as i32)
    }
}
