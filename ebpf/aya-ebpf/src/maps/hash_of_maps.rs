use core::{marker::PhantomData, ptr::NonNull};

use aya_ebpf_cty::c_void;

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
/// | Aspect         | `HashMap`           | `HashOfMaps`                       |
/// |----------------|---------------------|------------------------------------|
/// | `value_size`   | `size_of::<V>()`    | `size_of::<u32>()` (inner map fd)  |
/// | BPF operations | get, insert, remove | **get only** (kernel limitation)   |
/// | Value type     | Any `V`             | Must impl `Map`                    |
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.12.
#[repr(transparent)]
pub struct HashOfMaps<K, V: Map> {
    def: MapDef,
    _kv: PhantomData<(K, V)>,
}

impl<K, V: Map> HashOfMaps<K, V> {
    map_constructors!(K, u32, BPF_MAP_TYPE_HASH_OF_MAPS, phantom _kv);

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
        // SAFETY: The pointer returned by the BPF helper is valid for the
        // duration of the program, and we only produce a shared reference.
        unsafe { self.lookup(key).map(|p| p.as_ref()) }
    }

    #[inline(always)]
    unsafe fn lookup(&self, key: &K) -> Option<NonNull<V>> {
        lookup(self.def.as_ptr(), key)
    }

    /// Looks up a value directly in the inner map associated with `outer_key`.
    ///
    /// Performs both the outer and inner `bpf_map_lookup_elem` calls in a
    /// single method, producing fewer BPF instructions between the two
    /// helpers. This reduces verifier state explosion in tight loops.
    ///
    /// # Safety
    ///
    /// This function is unsafe for the same reasons as [`get`](Self::get).
    #[inline(always)]
    pub unsafe fn get_value(
        &self,
        outer_key: &K,
        inner_key: &<V as Map>::Key,
    ) -> Option<&<V as Map>::Value> {
        let inner: NonNull<c_void> = lookup(self.def.as_ptr(), outer_key)?;
        unsafe {
            lookup::<<V as Map>::Key, <V as Map>::Value>(inner.as_ptr(), inner_key)
                .map(|p| p.as_ref())
        }
    }

    /// Same as [`get_value`](Self::get_value) but returns a mutable pointer.
    ///
    /// # Safety
    ///
    /// See [`get_value`](Self::get_value).
    #[inline(always)]
    pub unsafe fn get_value_ptr_mut(
        &self,
        outer_key: &K,
        inner_key: &<V as Map>::Key,
    ) -> Option<*mut <V as Map>::Value> {
        let inner: NonNull<c_void> = lookup(self.def.as_ptr(), outer_key)?;
        lookup::<<V as Map>::Key, <V as Map>::Value>(inner.as_ptr(), inner_key).map(NonNull::as_ptr)
    }

    // Note: insert/remove are intentionally not implemented.
    // The kernel only allows bpf_map_lookup_elem on map-of-maps from BPF programs.
    // Insert/update/delete operations are restricted to userspace via the syscall API.
}
