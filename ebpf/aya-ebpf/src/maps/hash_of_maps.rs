use core::{cell::UnsafeCell, marker::PhantomData, ptr::NonNull};

use aya_ebpf_cty::c_void;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_HASH_OF_MAPS},
    helpers::bpf_map_lookup_elem,
    maps::{InnerMap, PinningType},
};

#[repr(transparent)]
pub struct HashOfMaps<K, V> {
    def: UnsafeCell<bpf_map_def>,
    _kv: PhantomData<(K, V)>,
}

unsafe impl<K, V: InnerMap> Sync for HashOfMaps<K, V> {}

impl<K, V: InnerMap> HashOfMaps<K, V> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_HASH_OF_MAPS,
                key_size: size_of::<K>() as u32,
                value_size: size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
            _kv: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_HASH_OF_MAPS,
                key_size: size_of::<K>() as u32,
                value_size: size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
            _kv: PhantomData,
        }
    }

    /// Retrieve the inner map associated with `key` from the map.
    ///
    /// # Safety
    ///
    /// This function is unsafe. Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not
    /// make guarantee on the atomicity of `insert` or `remove`, and any element removed from the
    /// map might get aliased by another element in the map, causing garbage to be read, or
    /// corruption in case of writes.
    #[inline(always)]
    pub unsafe fn get(&self, key: &K) -> Option<&V> {
        // FIXME: alignment
        unsafe { self.lookup(key).map(|p| p.as_ref()) }
    }

    #[inline(always)]
    unsafe fn lookup(&self, key: &K) -> Option<NonNull<V>> {
        let ptr = unsafe {
            bpf_map_lookup_elem(
                self.def.get().cast(),
                core::ptr::from_ref(key).cast::<c_void>(),
            )
        };
        NonNull::new(ptr.cast::<V>())
    }
}
