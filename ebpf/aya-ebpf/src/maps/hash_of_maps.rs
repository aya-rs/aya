use core::{marker::PhantomData, ptr::NonNull};

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_HASH_OF_MAPS,
    lookup,
    maps::{Map, MapDef, PinningType},
};

/// A hash map of eBPF maps.
///
/// This map type stores references to other BPF maps, indexed by arbitrary keys.
/// It enables dynamic map selection at runtime based on a hash key lookup.
///
/// # Differences from [`HashMap`](super::HashMap)
///
/// | Aspect | `HashMap` | `HashOfMaps` |
/// |--------|-----------|--------------|
/// | `value_size` | `size_of::<V>()` | `size_of::<u32>()` (inner map fd) |
/// | BPF operations | get, insert, remove | **get only** (kernel limitation) |
/// | Value type | Any `V` | Must impl `Map` |
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.12.
#[repr(transparent)]
pub struct HashOfMaps<K, V> {
    def: MapDef,
    _kv: PhantomData<(K, V)>,
}

impl<K, V: Map> HashOfMaps<K, V> {
    /// Creates a hash-of-maps with the specified maximum entries and flags.
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self::new(max_entries, flags, PinningType::None)
    }

    /// Creates a pinned hash-of-maps with the specified maximum entries and flags.
    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self::new(max_entries, flags, PinningType::ByName)
    }

    const fn new(max_entries: u32, flags: u32, pinning: PinningType) -> Self {
        Self {
            def: MapDef::new_map_of_maps::<K>(
                BPF_MAP_TYPE_HASH_OF_MAPS,
                max_entries,
                flags,
                pinning,
            ),
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
        lookup(self.def.as_ptr(), key)
    }

    // Note: insert/remove are intentionally not implemented.
    // The kernel only allows bpf_map_lookup_elem on map-of-maps from BPF programs.
    // Insert/update/delete operations are restricted to userspace via the syscall API.
}
