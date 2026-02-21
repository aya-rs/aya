use core::{marker::PhantomData, ptr::NonNull};

use aya_ebpf_cty::c_void;

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS,
    lookup,
    maps::{Map, MapDef, PinningType},
};

/// An array of eBPF maps.
///
/// This map type stores references to other BPF maps, indexed by `u32` keys.
/// It enables dynamic map selection at runtime based on an array index lookup.
///
/// # Differences from [`Array`](super::Array)
///
/// | Aspect         | `Array`          | `ArrayOfMaps`                      |
/// |----------------|------------------|------------------------------------|
/// | `value_size`   | `size_of::<T>()` | `size_of::<u32>()` (inner map fd)  |
/// | BPF operations | get, set         | **get only** (kernel limitation)   |
/// | Value type     | Any `T`          | Must impl `Map`                    |
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.12.
#[repr(transparent)]
pub struct ArrayOfMaps<T: Map> {
    def: MapDef,
    _t: PhantomData<T>,
}

impl<T: Map> ArrayOfMaps<T> {
    map_constructors!(u32, u32, BPF_MAP_TYPE_ARRAY_OF_MAPS, phantom _t);

    /// Retrieves a reference to the inner map at the given index.
    ///
    /// Returns `None` if the index is out of bounds or if no map is stored at that index.
    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<&T> {
        // SAFETY: The pointer returned by the BPF helper is valid for the
        // duration of the program, and we only produce a shared reference.
        unsafe { self.lookup(index).map(|p| p.as_ref()) }
    }

    #[inline(always)]
    unsafe fn lookup(&self, index: u32) -> Option<NonNull<T>> {
        lookup(self.def.as_ptr(), &index)
    }

    /// Looks up a value directly in the inner map at `outer_index`.
    ///
    /// Performs both the outer and inner `bpf_map_lookup_elem` calls in a
    /// single method, producing fewer BPF instructions between the two
    /// helpers. This reduces verifier state explosion in tight loops.
    #[inline(always)]
    pub fn get_value(
        &self,
        outer_index: u32,
        inner_key: &<T as Map>::Key,
    ) -> Option<&<T as Map>::Value> {
        let inner: NonNull<c_void> = lookup(self.def.as_ptr(), &outer_index)?;
        // SAFETY: Both pointers are returned by BPF helpers and are valid for
        // the duration of the program. We only produce shared references.
        unsafe {
            lookup::<<T as Map>::Key, <T as Map>::Value>(inner.as_ptr(), inner_key)
                .map(|p| p.as_ref())
        }
    }

    /// Same as [`get_value`](Self::get_value) but returns a mutable pointer.
    #[inline(always)]
    pub fn get_value_ptr_mut(
        &self,
        outer_index: u32,
        inner_key: &<T as Map>::Key,
    ) -> Option<*mut <T as Map>::Value> {
        let inner: NonNull<c_void> = lookup(self.def.as_ptr(), &outer_index)?;
        lookup::<<T as Map>::Key, <T as Map>::Value>(inner.as_ptr(), inner_key).map(NonNull::as_ptr)
    }

    // Note: set is intentionally not implemented.
    // The kernel only allows bpf_map_lookup_elem on map-of-maps from BPF programs.
    // Insert/update/delete operations are restricted to userspace via the syscall API.
}
