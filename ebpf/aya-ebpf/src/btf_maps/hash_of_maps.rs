use core::ptr::NonNull;

use aya_ebpf_cty::c_void;

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_HASH_OF_MAPS, btf_maps::AyaBtfMapMarker,
    helpers::bpf_map_lookup_elem,
};

/// A BTF-compatible BPF hash map that stores references to other maps (hash of maps).
///
/// This map type allows you to store file descriptors of other BPF maps
/// indexed by arbitrary keys, enabling dynamic map selection at runtime.
///
/// The `#[repr(C)]` struct with flat fields (`type`, `key`, `value`, etc.) defines
/// the map in BTF format. The `values` field creates a BTF relocation that binds
/// the inner map type.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.12.
///
/// # Example
///
/// ```rust,no_run
/// use aya_ebpf::{btf_maps::{Array, HashOfMaps}, macros::btf_map};
///
/// // Define the inner map template
/// #[btf_map]
/// static INNER: Array<u32, 10> = Array::new();
///
/// // Define the outer map with reference to inner map
/// #[btf_map]
/// static OUTER: HashOfMaps<u32, Array<u32, 10>, 4> = HashOfMaps::new(&INNER);
/// ```
#[repr(C)]
#[allow(dead_code)]
pub struct HashOfMaps<K, V, const M: usize, const F: usize = 0> {
    r#type: *const [i32; BPF_MAP_TYPE_HASH_OF_MAPS as usize],
    key: *const K,
    value: *const u32,
    max_entries: *const [i32; M],
    map_flags: *const [i32; F],
    /// Zero-sized array of pointers to inner map type. This field generates a BTF entry
    /// that libbpf uses to determine the inner map type for map-of-maps.
    /// libbpf expects: array[0] -> pointer -> struct (inner map def)
    values: [*const V; 0],
    // Anonymize the struct in BTF.
    _anon: AyaBtfMapMarker,
}

// SAFETY: The map definition is accessed through BPF helpers which handle synchronization.
// The struct fields are never actually accessed at runtime - they exist only for BTF metadata.
unsafe impl<K: Sync, V: Sync, const M: usize, const F: usize> Sync for HashOfMaps<K, V, M, F> {}

impl<K, V, const M: usize, const F: usize> HashOfMaps<K, V, M, F> {
    /// Creates a new `HashOfMaps` with a reference to an inner map template.
    ///
    /// The `inner` parameter should be a reference to a static map that serves
    /// as the template for inner maps. This reference generates a BTF relocation
    /// that allows libbpf to understand the inner map type.
    ///
    /// # Arguments
    ///
    /// * `inner` - Reference to the inner map template (must be `'static`)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{btf_maps::{Array, HashOfMaps}, macros::btf_map};
    ///
    /// #[btf_map]
    /// static INNER: Array<u32, 10> = Array::new();
    ///
    /// #[btf_map]
    /// static OUTER: HashOfMaps<u32, Array<u32, 10>, 4> = HashOfMaps::new(&INNER);
    /// ```
    pub const fn new(_inner: &'static V) -> Self {
        Self {
            r#type: core::ptr::null(),
            key: core::ptr::null(),
            value: core::ptr::null(),
            max_entries: core::ptr::null(),
            map_flags: core::ptr::null(),
            values: [],
            _anon: AyaBtfMapMarker::new(),
        }
    }

    /// Retrieve the inner map associated with `key` from the map.
    ///
    /// # Safety
    ///
    /// This function is unsafe because the map might not contain an entry
    /// for the given key, and the returned reference could be invalidated
    /// if the entry is removed concurrently.
    #[inline(always)]
    pub unsafe fn get(&self, key: &K) -> Option<&V> {
        // SAFETY: We only read from the map through BPF helpers.
        // The struct fields are never accessed - only the address is used.
        unsafe { self.lookup(key).map(|p| p.as_ref()) }
    }

    #[inline(always)]
    unsafe fn lookup(&self, key: &K) -> Option<NonNull<V>> {
        let ptr = unsafe {
            bpf_map_lookup_elem(
                core::ptr::from_ref(self).cast::<c_void>().cast_mut(),
                core::ptr::from_ref(key).cast::<c_void>(),
            )
        };
        NonNull::new(ptr.cast::<V>())
    }
}
