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
    /// The minimum kernel version required to use this feature is 5.7.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{btf_maps::{Array, ArrayOfMaps}, macros::btf_map};
    ///
    /// // The inner map definition is parsed from BTF at load time.
    /// #[btf_map]
    /// static OUTER: ArrayOfMaps<Array<u32, 10>, 4> = ArrayOfMaps::new();
    /// ```
    pub struct ArrayOfMaps<V; const MAX_ENTRIES: usize, const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_ARRAY_OF_MAPS,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: u32,
    value_type: u32,
    inner_map: V,
);

impl<V, const MAX_ENTRIES: usize, const FLAGS: usize> ArrayOfMaps<V, MAX_ENTRIES, FLAGS> {
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

impl<V: crate::btf_maps::SafeInnerLookup, const MAX_ENTRIES: usize, const FLAGS: usize>
    ArrayOfMaps<V, MAX_ENTRIES, FLAGS>
{
    /// Looks up a value directly in the inner map at `outer_index`.
    ///
    /// Performs both the outer and inner `bpf_map_lookup_elem` calls in a
    /// single method, producing fewer BPF instructions between the two
    /// helpers. This reduces verifier state explosion in tight loops.
    #[inline(always)]
    pub fn get_value(&self, outer_index: u32, inner_key: &V::Key) -> Option<&V::Value> {
        let inner: NonNull<V> = lookup(self.as_ptr(), &outer_index)?;
        // SAFETY: `V: SafeInnerLookup` guarantees the kernel returns a
        // reference that stays valid for the lifetime of the BPF program,
        // so the produced shared reference is sound.
        unsafe { crate::btf_maps::lookup_inner(inner, inner_key) }
    }
}

impl<V: crate::btf_maps::MapDef, const MAX_ENTRIES: usize, const FLAGS: usize>
    ArrayOfMaps<V, MAX_ENTRIES, FLAGS>
{
    /// Returns a `*mut V::Value` to the entry at `inner_key` of the inner map at
    /// `outer_index`.
    ///
    /// Like [`get_value`](Self::get_value), this combines the outer and inner
    /// `bpf_map_lookup_elem` calls in a single method. The pointer's lifetime
    /// is not enforced by Rust; it is the caller's responsibility to ensure
    /// dereferences are sound for the inner map type.
    #[inline(always)]
    pub fn get_value_ptr_mut(&self, outer_index: u32, inner_key: &V::Key) -> Option<*mut V::Value> {
        let inner: NonNull<V> = lookup(self.as_ptr(), &outer_index)?;
        crate::btf_maps::lookup_inner_ptr_mut(inner, inner_key)
    }
}
