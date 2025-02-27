//! An array of network devices.

use std::{
    borrow::{Borrow, BorrowMut},
    num::NonZeroU32,
    os::fd::{AsFd, AsRawFd},
};

use aya_obj::generated::bpf_devmap_val;

use super::XdpMapError;
use crate::{
    maps::{check_bounds, check_kv_size, IterableMap, MapData, MapError},
    programs::ProgramFd,
    sys::{bpf_map_lookup_elem, bpf_map_update_elem, SyscallError},
    Pod, FEATURES,
};

/// An array of network devices.
///
/// XDP programs can use this map to redirect to other network
/// devices.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.14.
///
/// # Examples
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::maps::xdp::DevMap;
///
/// let mut devmap = DevMap::try_from(bpf.map_mut("IFACES").unwrap())?;
/// // Lookups at index 2 will redirect packets to interface with index 3 (e.g. eth1)
/// devmap.set(2, 3, None, 0);
///
/// # Ok::<(), aya::EbpfError>(())
/// ```
///
/// # See also
///
/// Kernel documentation: <https://docs.kernel.org/next/bpf/map_devmap.html>
#[doc(alias = "BPF_MAP_TYPE_DEVMAP")]
pub struct DevMap<T> {
    pub(crate) inner: T,
}

impl<T: Borrow<MapData>> DevMap<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();

        if FEATURES.devmap_prog_id() {
            check_kv_size::<u32, bpf_devmap_val>(data)?;
        } else {
            check_kv_size::<u32, u32>(data)?;
        }

        Ok(Self { inner: map })
    }

    /// Returns the number of elements in the array.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn len(&self) -> u32 {
        self.inner.borrow().obj.max_entries()
    }

    /// Returns the target interface index and optional program at a given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_elem` fails.
    pub fn get(&self, index: u32, flags: u64) -> Result<DevMapValue, MapError> {
        let data = self.inner.borrow();
        check_bounds(data, index)?;
        let fd = data.fd().as_fd();

        let value = if FEATURES.devmap_prog_id() {
            bpf_map_lookup_elem::<_, bpf_devmap_val>(fd, &index, flags).map(|value| {
                value.map(|value| DevMapValue {
                    if_index: value.ifindex,
                    // SAFETY: map writes use fd, map reads use id.
                    // https://github.com/torvalds/linux/blob/2dde18cd1d8fac735875f2e4987f11817cc0bc2c/include/uapi/linux/bpf.h#L6228
                    prog_id: NonZeroU32::new(unsafe { value.bpf_prog.id }),
                })
            })
        } else {
            bpf_map_lookup_elem::<_, u32>(fd, &index, flags).map(|value| {
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

    /// An iterator over the elements of the array.
    pub fn iter(&self) -> impl Iterator<Item = Result<DevMapValue, MapError>> + '_ {
        (0..self.len()).map(move |i| self.get(i, 0))
    }
}

impl<T: BorrowMut<MapData>> DevMap<T> {
    /// Sets the target interface index at index, and optionally a chained program.
    ///
    /// When redirecting using `index`, packets will be transmitted by the interface with
    /// `target_if_index`.
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
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails, [`MapError::ProgIdNotSupported`] if the kernel does not
    /// support chained programs and one is provided.
    pub fn set(
        &mut self,
        index: u32,
        target_if_index: u32,
        program: Option<&ProgramFd>,
        flags: u64,
    ) -> Result<(), XdpMapError> {
        let data = self.inner.borrow_mut();
        check_bounds(data, index)?;
        let fd = data.fd().as_fd();

        let res = if FEATURES.devmap_prog_id() {
            let mut value = unsafe { std::mem::zeroed::<bpf_devmap_val>() };
            value.ifindex = target_if_index;
            // Default is valid as the kernel will only consider fd > 0:
            // https://github.com/torvalds/linux/blob/2dde18cd1d8fac735875f2e4987f11817cc0bc2c/kernel/bpf/devmap.c#L866
            // https://github.com/torvalds/linux/blob/2dde18cd1d8fac735875f2e4987f11817cc0bc2c/kernel/bpf/devmap.c#L918
            value.bpf_prog.fd = program
                .map(|prog| prog.as_fd().as_raw_fd())
                .unwrap_or_default();
            bpf_map_update_elem(fd, Some(&index), &value, flags)
        } else {
            if program.is_some() {
                return Err(XdpMapError::ChainedProgramNotSupported);
            }
            bpf_map_update_elem(fd, Some(&index), &target_if_index, flags)
        };

        res.map_err(|io_error| {
            MapError::from(SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            })
        })
        .map_err(Into::into)
    }
}

impl<T: Borrow<MapData>> IterableMap<u32, DevMapValue> for DevMap<T> {
    fn map(&self) -> &MapData {
        self.inner.borrow()
    }

    fn get(&self, key: &u32) -> Result<DevMapValue, MapError> {
        self.get(*key, 0)
    }
}

unsafe impl Pod for bpf_devmap_val {}

#[derive(Clone, Copy, Debug)]
/// The value of a device map.
pub struct DevMapValue {
    /// Target interface index to redirect to.
    pub if_index: u32,
    /// Chained XDP program ID.
    pub prog_id: Option<NonZeroU32>,
}
