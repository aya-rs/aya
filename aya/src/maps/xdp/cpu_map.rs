//! An array of available CPUs.

use std::{
    borrow::{Borrow, BorrowMut},
    num::NonZeroU32,
    os::fd::{AsFd, AsRawFd},
};

use aya_obj::generated::bpf_cpumap_val;

use super::XdpMapError;
use crate::{
    maps::{check_bounds, check_kv_size, IterableMap, MapData, MapError},
    programs::ProgramFd,
    sys::{bpf_map_lookup_elem, bpf_map_update_elem, SyscallError},
    Pod, FEATURES,
};

/// An array of available CPUs.
///
/// XDP programs can use this map to redirect packets to a target
/// CPU for processing.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.15.
///
/// # Examples
/// ```no_run
/// # let elf_bytes = &[];
/// use aya::maps::xdp::CpuMap;
///
/// let ncpus = aya::util::nr_cpus().unwrap() as u32;
/// let mut bpf = aya::EbpfLoader::new()
///     .set_max_entries("CPUS", ncpus)
///     .load(elf_bytes)
///     .unwrap();
/// let mut cpumap = CpuMap::try_from(bpf.map_mut("CPUS").unwrap())?;
/// let flags = 0;
/// let queue_size = 2048;
/// for i in 0..ncpus {
///     cpumap.set(i, queue_size, None, flags);
/// }
///
/// # Ok::<(), aya::EbpfError>(())
/// ```
///
/// # See also
///
/// Kernel documentation: <https://docs.kernel.org/next/bpf/map_cpumap.html>
#[doc(alias = "BPF_MAP_TYPE_CPUMAP")]
pub struct CpuMap<T> {
    pub(crate) inner: T,
}

impl<T: Borrow<MapData>> CpuMap<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();

        if FEATURES.cpumap_prog_id() {
            check_kv_size::<u32, bpf_cpumap_val>(data)?;
        } else {
            check_kv_size::<u32, u32>(data)?;
        }

        Ok(Self { inner: map })
    }

    /// Returns the number of elements in the array.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn len(&self) -> u32 {
        self.inner.borrow().def.max_entries()
    }

    /// Returns the queue size and optional program for a given CPU index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `cpu_index` is out of bounds,
    /// [`MapError::SyscallError`] if `bpf_map_lookup_elem` fails.
    pub fn get(&self, cpu_index: u32, flags: u64) -> Result<CpuMapValue, MapError> {
        let data = self.inner.borrow();
        check_bounds(data, cpu_index)?;
        let fd = data.fd().as_fd();

        let value = if FEATURES.cpumap_prog_id() {
            bpf_map_lookup_elem::<_, bpf_cpumap_val>(fd, &cpu_index, flags).map(|value| {
                value.map(|value| CpuMapValue {
                    queue_size: value.qsize,
                    // SAFETY: map writes use fd, map reads use id.
                    // https://github.com/torvalds/linux/blob/2dde18cd1d8fac735875f2e4987f11817cc0bc2c/include/uapi/linux/bpf.h#L6241
                    prog_id: NonZeroU32::new(unsafe { value.bpf_prog.id }),
                })
            })
        } else {
            bpf_map_lookup_elem::<_, u32>(fd, &cpu_index, flags).map(|value| {
                value.map(|qsize| CpuMapValue {
                    queue_size: qsize,
                    prog_id: None,
                })
            })
        };
        value
            .map_err(|(_, io_error)| SyscallError {
                call: "bpf_map_lookup_elem",
                io_error,
            })?
            .ok_or(MapError::KeyNotFound)
    }

    /// An iterator over the elements of the map.
    pub fn iter(&self) -> impl Iterator<Item = Result<CpuMapValue, MapError>> + '_ {
        (0..self.len()).map(move |i| self.get(i, 0))
    }
}

impl<T: BorrowMut<MapData>> CpuMap<T> {
    /// Sets the queue size at the given CPU index, and optionally a chained program.
    ///
    /// When sending the packet to the CPU at the given index, the kernel will queue up to
    /// `queue_size` packets before dropping them.
    ///
    /// Starting from Linux kernel 5.9, another XDP program can be passed in that will be run on the
    /// target CPU, instead of the CPU that receives the packets. This allows to perform minimal
    /// computations on CPUs that directly handle packets from a NIC's RX queues, and perform
    /// possibly heavier ones in other, less busy CPUs.
    ///
    /// The chained program must be loaded with the `BPF_XDP_CPUMAP` attach type. When using
    /// `aya-ebpf`, that means XDP programs that specify the `map = "cpumap"` argument. See the
    /// kernel-space `aya_ebpf::xdp` for more information.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails, [`XdpMapError::ChainedProgramNotSupported`] if the kernel
    /// does not support chained programs and one is provided.
    pub fn set(
        &mut self,
        cpu_index: u32,
        queue_size: u32,
        program: Option<&ProgramFd>,
        flags: u64,
    ) -> Result<(), XdpMapError> {
        let data = self.inner.borrow_mut();
        check_bounds(data, cpu_index)?;
        let fd = data.fd().as_fd();

        let res = if FEATURES.cpumap_prog_id() {
            let mut value = unsafe { std::mem::zeroed::<bpf_cpumap_val>() };
            value.qsize = queue_size;
            // Default is valid as the kernel will only consider fd > 0:
            // https://github.com/torvalds/linux/blob/2dde18cd1d8fac735875f2e4987f11817cc0bc2c/kernel/bpf/cpumap.c#L466
            value.bpf_prog.fd = program
                .map(|prog| prog.as_fd().as_raw_fd())
                .unwrap_or_default();
            bpf_map_update_elem(fd, Some(&cpu_index), &value, flags)
        } else {
            if program.is_some() {
                return Err(XdpMapError::ChainedProgramNotSupported);
            }
            bpf_map_update_elem(fd, Some(&cpu_index), &queue_size, flags)
        };

        res.map_err(|(_, io_error)| {
            MapError::from(SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            })
        })?;
        Ok(())
    }
}

impl<T: Borrow<MapData>> IterableMap<u32, CpuMapValue> for CpuMap<T> {
    fn map(&self) -> &MapData {
        self.inner.borrow()
    }

    fn get(&self, key: &u32) -> Result<CpuMapValue, MapError> {
        self.get(*key, 0)
    }
}

unsafe impl Pod for bpf_cpumap_val {}

#[derive(Clone, Copy, Debug)]
/// The value of a CPU map.
pub struct CpuMapValue {
    /// Size of the for the CPU.
    pub queue_size: u32,
    /// Chained XDP program ID.
    pub prog_id: Option<NonZeroU32>,
}
