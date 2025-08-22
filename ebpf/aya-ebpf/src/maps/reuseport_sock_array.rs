use core::{cell::UnsafeCell, mem};

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_REUSEPORT_SOCKARRAY},
    maps::PinningType,
};

/// An array of sockets for use with SO_REUSEPORT socket selection.
///
/// `ReusePortSockArray` is used to store sockets that participate in SO_REUSEPORT
/// groups. eBPF programs of type `BPF_PROG_TYPE_SK_REUSEPORT` can use this map
/// with the `bpf_sk_select_reuseport()` helper to select specific sockets for
/// incoming connections.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.19.
#[repr(transparent)]
pub struct ReusePortSockArray {
    def: UnsafeCell<bpf_map_def>,
}

unsafe impl Sync for ReusePortSockArray {}

impl ReusePortSockArray {
    /// Creates a new `ReusePortSockArray` with the specified maximum number of entries.
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> ReusePortSockArray {
        ReusePortSockArray {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
        }
    }

    /// Creates a new pinned `ReusePortSockArray` with the specified maximum number of entries.
    pub const fn pinned(max_entries: u32, flags: u32) -> ReusePortSockArray {
        ReusePortSockArray {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
        }
    }

    /// Returns a raw pointer to the map definition for use with helpers.
    pub fn as_ptr(&self) -> *mut ::aya_ebpf_cty::c_void {
        self.def.get() as *mut _
    }
}