use core::{marker::PhantomData, mem, ptr};

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_BLOOM_FILTER},
    helpers::{bpf_map_peek_elem, bpf_map_push_elem},
    maps::PinningType,
};

#[repr(transparent)]
pub struct BloomFilter<T> {
    def: bpf_map_def,
    _t: PhantomData<T>,
}

impl<T> BloomFilter<T> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self {
            def: build_def::<T>(
                BPF_MAP_TYPE_BLOOM_FILTER,
                max_entries,
                flags,
                PinningType::None,
            ),
            _t: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self {
            def: build_def::<T>(
                BPF_MAP_TYPE_BLOOM_FILTER,
                max_entries,
                flags,
                PinningType::ByName,
            ),
            _t: PhantomData,
        }
    }

    #[inline]
    pub fn contains(&mut self, value: &T) -> Result<(), i64> {
        let ret = unsafe {
            bpf_map_peek_elem(
                ptr::from_ref(&self.def).cast_mut().cast(),
                ptr::from_ref(value).cast_mut().cast(),
            )
        };
        (ret == 0).then_some(()).ok_or(ret)
    }

    #[inline]
    pub fn insert(&mut self, value: &T, flags: u64) -> Result<(), i64> {
        let ret = unsafe {
            bpf_map_push_elem(
                ptr::from_ref(&self.def).cast_mut().cast(),
                ptr::from_ref(value).cast(),
                flags,
            )
        };
        (ret == 0).then_some(()).ok_or(ret)
    }
}

const fn build_def<T>(ty: u32, max_entries: u32, flags: u32, pin: PinningType) -> bpf_map_def {
    bpf_map_def {
        type_: ty,
        key_size: 0,
        value_size: mem::size_of::<T>() as u32,
        max_entries,
        map_flags: flags,
        id: 0,
        pinning: pin as u32,
    }
}
