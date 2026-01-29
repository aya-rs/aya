use core::ptr::NonNull;

use crate::{btf_maps::btf_map_def, lookup};

btf_map_def!(
    /// A BTF-compatible BPF hash map that stores references to other maps (hash of maps).
    ///
    /// This map type allows you to store file descriptors of other BPF maps
    /// indexed by arbitrary keys, enabling dynamic map selection at runtime.
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
    /// // Define the outer map with explicit inner map binding
    /// #[btf_map(inner = "INNER")]
    /// static OUTER: HashOfMaps<u32, Array<u32, 10>, 4> = HashOfMaps::new();
    /// ```
    pub struct HashOfMaps<K, V; const M: usize, const F: usize = 0>,
    map_type: BPF_MAP_TYPE_HASH_OF_MAPS,
    max_entries: M,
    map_flags: F,
    key_type: K,
    value_type: u32,
    inner_map: V,
);

impl<K, V, const M: usize, const F: usize> HashOfMaps<K, V, M, F> {
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
        // SAFETY: We only read from the map through BPF helpers.
        // The struct fields are never accessed - only the address is used.
        unsafe { self.lookup(key).map(|p| p.as_ref()) }
    }

    #[inline(always)]
    unsafe fn lookup(&self, key: &K) -> Option<NonNull<V>> {
        lookup(self.as_ptr(), key)
    }
}
