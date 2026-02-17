use core::ptr::NonNull;

use aya_ebpf_cty::c_void;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS},
    helpers::bpf_map_lookup_elem,
    maps::def::PinningType,
};

/// A BPF map of type `BPF_MAP_TYPE_ARRAY_OF_MAPS`.
///
/// The outer map is an array indexed by `u32`. Each entry holds a file descriptor
/// (managed by the kernel) pointing to an inner map. The inner map's schema
/// (type, key_size, value_size) is fixed at outer-map creation time via a template.
///
/// From BPF programs, `get()` returns an opaque pointer to the inner map which can
/// be passed to [`bpf_map_lookup_elem`] to read entries from that inner map.
///
/// # Layout
///
/// The struct embeds **two** `bpf_map_def` values back-to-back:
/// - `def`: the outer map definition (`BPF_MAP_TYPE_ARRAY_OF_MAPS`)
/// - `inner_def`: describes the inner map template (type, key/value sizes, max_entries)
///
/// The aya userspace loader reads both definitions from the ELF `maps` section and
/// uses `inner_def` to create a temporary inner map whose fd is passed as
/// `inner_map_fd` when creating the outer map.
///
/// # Examples
///
/// ```no_run
/// use aya_ebpf::{macros::map, maps::ArrayOfMaps};
/// use aya_ebpf::bindings::bpf_map_type::BPF_MAP_TYPE_ARRAY;
///
/// #[map]
/// static OUTER: ArrayOfMaps = ArrayOfMaps::with_max_entries(
///     16,                // outer map: up to 16 inner maps
///     BPF_MAP_TYPE_ARRAY,// inner map type
///     4,                 // inner key_size (u32)
///     12,                // inner value_size
///     1024,              // inner max_entries (template; each actual inner map may differ)
///     0,
/// );
/// ```
#[repr(C)]
pub struct ArrayOfMaps {
    def: core::cell::UnsafeCell<bpf_map_def>,
    inner_def: bpf_map_def,
}

unsafe impl Sync for ArrayOfMaps {}

impl ArrayOfMaps {
    /// Creates a new `ArrayOfMaps` with the given outer max_entries and inner map template.
    ///
    /// # Arguments
    ///
    /// * `max_entries` - Maximum number of inner maps in the outer array.
    /// * `inner_type` - The `BPF_MAP_TYPE_*` constant for inner maps (e.g., `BPF_MAP_TYPE_ARRAY`).
    /// * `inner_key_size` - Key size in bytes for inner maps.
    /// * `inner_value_size` - Value size in bytes for inner maps.
    /// * `inner_max_entries` - Template max_entries for inner maps (actual inner maps may differ).
    /// * `flags` - Map flags for the outer map.
    pub const fn with_max_entries(
        max_entries: u32,
        inner_type: u32,
        inner_key_size: u32,
        inner_value_size: u32,
        inner_max_entries: u32,
        flags: u32,
    ) -> Self {
        Self {
            def: core::cell::UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_ARRAY_OF_MAPS,
                key_size: size_of::<u32>() as u32,
                value_size: size_of::<u32>() as u32, // inner map fd
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
            inner_def: bpf_map_def {
                type_: inner_type,
                key_size: inner_key_size,
                value_size: inner_value_size,
                max_entries: inner_max_entries,
                map_flags: 0,
                id: 0,
                pinning: PinningType::None as u32,
            },
        }
    }

    /// Creates a new pinned `ArrayOfMaps`.
    pub const fn pinned(
        max_entries: u32,
        inner_type: u32,
        inner_key_size: u32,
        inner_value_size: u32,
        inner_max_entries: u32,
        flags: u32,
    ) -> Self {
        Self {
            def: core::cell::UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_ARRAY_OF_MAPS,
                key_size: size_of::<u32>() as u32,
                value_size: size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
            inner_def: bpf_map_def {
                type_: inner_type,
                key_size: inner_key_size,
                value_size: inner_value_size,
                max_entries: inner_max_entries,
                map_flags: 0,
                id: 0,
                pinning: PinningType::None as u32,
            },
        }
    }

    /// Look up the inner map at `index`.
    ///
    /// Returns an opaque pointer to the inner map. This pointer can be passed
    /// directly to [`bpf_map_lookup_elem`] as the map argument to read values
    /// from the inner map.
    ///
    /// Returns `None` if no inner map is set at `index`.
    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<*mut c_void> {
        unsafe {
            let ptr = bpf_map_lookup_elem(
                self.def.get() as *mut _,
                &index as *const _ as *const c_void,
            );
            NonNull::new(ptr).map(|p| p.as_ptr())
        }
    }
}
