use core::ptr::NonNull;

use crate::{btf_maps::btf_map_def, lookup};

btf_map_def!(
    /// A BTF-compatible BPF map that stores references to other maps (array of maps).
    ///
    /// This map type allows you to store file descriptors of other BPF maps,
    /// enabling dynamic map selection at runtime.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.12.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{btf_maps::{Array, ArrayOfMaps}, macros::btf_map};
    ///
    /// // Define the inner map template
    /// #[btf_map]
    /// static INNER: Array<u32, 10> = Array::new();
    ///
    /// // Define the outer map with explicit inner map binding
    /// #[btf_map(inner = "INNER")]
    /// static OUTER: ArrayOfMaps<Array<u32, 10>, 4> = ArrayOfMaps::new();
    /// ```
    pub struct ArrayOfMaps<V; const M: usize, const F: usize = 0>,
    map_type: BPF_MAP_TYPE_ARRAY_OF_MAPS,
    max_entries: M,
    map_flags: F,
    key_type: u32,
    value_type: u32,
    inner_map: V,
);

impl<V, const M: usize, const F: usize> ArrayOfMaps<V, M, F> {
    /// Retrieves a reference to the inner map at the given index.
    ///
    /// Returns `None` if the index is out of bounds or if no map is stored
    /// at that index.
    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<&V> {
        // SAFETY: We only read from the map through BPF helpers.
        // The struct fields are never accessed - only the address is used.
        unsafe { self.lookup(index).map(|p| p.as_ref()) }
    }

    #[inline(always)]
    unsafe fn lookup(&self, index: u32) -> Option<NonNull<V>> {
        lookup(self.as_ptr(), &index)
    }
}
