//! An hashmap of network devices.

use std::{
    borrow::{Borrow, BorrowMut},
    num::NonZeroU32,
    os::fd::{AsFd, AsRawFd},
};

use aya_obj::generated::bpf_devmap_val;

use super::{XdpMapError, dev_map::DevMapValue};
use crate::{
    FEATURES,
    maps::{IterableMap, MapData, MapError, MapIter, MapKeys, check_kv_size, hash_map},
    programs::ProgramFd,
    sys::{SyscallError, bpf_map_lookup_elem},
};

/// An hashmap of network devices.
///
/// XDP programs can use this map to redirect to other network
/// devices.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.4.
///
/// # Examples
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::maps::xdp::DevMapHash;
///
/// let mut devmap = DevMapHash::try_from(bpf.map_mut("IFACES").unwrap())?;
/// // Lookups with key 2 will redirect packets to interface with index 3 (e.g. eth1)
/// devmap.insert(2, 3, None, 0);
///
/// # Ok::<(), aya::EbpfError>(())
/// ```
///
/// # See also
///
/// Kernel documentation: <https://docs.kernel.org/next/bpf/map_devmap.html>
#[doc(alias = "BPF_MAP_TYPE_DEVMAP_HASH")]
pub struct DevMapHash<T> {
    pub(crate) inner: T,
}

impl<T: Borrow<MapData>> DevMapHash<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();

        if FEATURES.devmap_prog_id() {
            check_kv_size::<u32, bpf_devmap_val>(data)?;
        } else {
            check_kv_size::<u32, u32>(data)?;
        }

        Ok(Self { inner: map })
    }

    /// Returns the target interface index and optional program for a given key.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::SyscallError`] if `bpf_map_lookup_elem` fails.
    pub fn get(&self, key: u32, flags: u64) -> Result<DevMapValue, MapError> {
        let fd = self.inner.borrow().fd().as_fd();

        let value = if FEATURES.devmap_prog_id() {
            bpf_map_lookup_elem::<_, bpf_devmap_val>(fd, &key, flags).map(|value| {
                value.map(|value| DevMapValue {
                    if_index: value.ifindex,
                    // SAFETY: map writes use fd, map reads use id.
                    // https://github.com/torvalds/linux/blob/2dde18cd1d8fac735875f2e4987f11817cc0bc2c/include/uapi/linux/bpf.h#L6228
                    prog_id: NonZeroU32::new(unsafe { value.bpf_prog.id }),
                })
            })
        } else {
            bpf_map_lookup_elem::<_, u32>(fd, &key, flags).map(|value| {
                value.map(|ifindex| DevMapValue {
                    if_index: ifindex,
                    prog_id: None,
                })
            })
        };
        value
            .map_err(|io_error| SyscallError {
                call: "bpf_map_lookup_elem",
                io_error,
            })?
            .ok_or(MapError::KeyNotFound)
    }

    /// An iterator over the elements of the devmap in arbitrary order.
    pub fn iter(&self) -> MapIter<'_, u32, DevMapValue, Self> {
        MapIter::new(self)
    }

    /// An iterator visiting all keys in arbitrary order.
    pub fn keys(&self) -> MapKeys<'_, u32> {
        MapKeys::new(self.inner.borrow())
    }
}

impl<T: BorrowMut<MapData>> DevMapHash<T> {
    /// Inserts an ifindex and optionally a chained program in the map.
    ///
    /// When redirecting using `key`, packets will be transmitted by the interface with `ifindex`.
    ///
    /// Starting from Linux kernel 5.8, another XDP program can be passed in that will be run before
    /// actual transmission. It can be used to modify the packet before transmission with NIC
    /// specific data (MAC address update, checksum computations, etc) or other purposes.
    ///
    /// The chained program must be loaded with the `BPF_XDP_DEVMAP` attach type. When using
    /// `aya-ebpf`, that means XDP programs that specify the `map = "devmap"` argument. See the
    /// kernel-space `aya_ebpf::xdp` for more information.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::SyscallError`] if `bpf_map_update_elem` fails,
    /// [`MapError::ProgIdNotSupported`] if the kernel does not support chained programs and one is
    /// provided.
    pub fn insert(
        &mut self,
        key: u32,
        target_if_index: u32,
        program: Option<&ProgramFd>,
        flags: u64,
    ) -> Result<(), XdpMapError> {
        if FEATURES.devmap_prog_id() {
            let mut value = unsafe { std::mem::zeroed::<bpf_devmap_val>() };
            value.ifindex = target_if_index;
            // Default is valid as the kernel will only consider fd > 0:
            // https://github.com/torvalds/linux/blob/2dde18cd1d8fac735875f2e4987f11817cc0bc2c/kernel/bpf/devmap.c#L866
            // https://github.com/torvalds/linux/blob/2dde18cd1d8fac735875f2e4987f11817cc0bc2c/kernel/bpf/devmap.c#L918
            value.bpf_prog.fd = program
                .map(|prog| prog.as_fd().as_raw_fd())
                .unwrap_or_default();
            hash_map::insert(self.inner.borrow_mut(), &key, &value, flags)?;
        } else {
            if program.is_some() {
                return Err(XdpMapError::ChainedProgramNotSupported);
            }
            hash_map::insert(self.inner.borrow_mut(), &key, &target_if_index, flags)?;
        }
        Ok(())
    }

    /// Removes a value from the map.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::SyscallError`] if `bpf_map_delete_elem` fails.
    pub fn remove(&mut self, key: u32) -> Result<(), MapError> {
        hash_map::remove(self.inner.borrow_mut(), &key)
    }
}

impl<T: Borrow<MapData>> IterableMap<u32, DevMapValue> for DevMapHash<T> {
    fn map(&self) -> &MapData {
        self.inner.borrow()
    }

    fn get(&self, key: &u32) -> Result<DevMapValue, MapError> {
        self.get(*key, 0)
    }
}
