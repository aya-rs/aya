use core::{cell::UnsafeCell, marker::PhantomData, mem, ptr::NonNull};

use aya_ebpf_cty::c_void;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_HASH_OF_MAPS},
    helpers::bpf_map_lookup_elem,
    maps::{InnerMap, PinningType},
};

#[repr(transparent)]
pub struct HashOfMaps<K, V> {
    def: UnsafeCell<bpf_map_def>,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<K, V: InnerMap> HashOfMaps<K, V> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> HashOfMaps<K, V> {
        HashOfMaps {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_HASH_OF_MAPS,
                key_size: mem::size_of::<K>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> HashOfMaps<K, V> {
        HashOfMaps {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_HASH_OF_MAPS,
                key_size: mem::size_of::<K>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    /// Retrieve the value associate with `key` from the map.
    /// This function is unsafe. Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not
    /// make guarantee on the atomicity of `insert` or `remove`, and any element removed from the
    /// map might get aliased by another element in the map, causing garbage to be read, or
    /// corruption in case of writes.
    #[inline]
    pub unsafe fn get(&self, key: &K) -> Option<NonNull<u32>> {
        let value = unsafe {
            bpf_map_lookup_elem(self.def.get() as *mut _, key as *const _ as *const c_void)
        };
        // FIXME: alignment
        NonNull::new(value as *mut _)
    }
}
