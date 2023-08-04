//! An array of available CPUs.

use std::{
    borrow::{Borrow, BorrowMut},
    num::NonZeroU32,
    os::fd::AsRawFd,
};

use aya_obj::generated::{bpf_cpumap_val, bpf_cpumap_val__bindgen_ty_1};

use crate::{
    maps::{check_bounds, check_kv_size, IterableMap, MapData, MapError},
    sys::{bpf_map_lookup_elem, bpf_map_update_elem, SyscallError},
    Pod,
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
/// let mut bpf = aya::BpfLoader::new()
///     .set_max_entries("CPUS", aya::util::nr_cpus().unwrap() as u32)
///     .load(elf_bytes)
///     .unwrap();
/// let mut cpumap = CpuMap::try_from(bpf.map_mut("CPUS").unwrap())?;
/// let flags = 0;
/// let queue_size = 2048;
/// for i in 0u32..8u32 {
///     cpumap.set(i, queue_size, None::<i32>, flags);
/// }
///
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_CPUMAP")]
pub struct CpuMap<T> {
    inner: T,
}

impl<T: Borrow<MapData>> CpuMap<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<u32, bpf_cpumap_val>(data)?;

        Ok(Self { inner: map })
    }

    /// Returns the number of elements in the array.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn len(&self) -> u32 {
        self.inner.borrow().obj.max_entries()
    }

    /// Returns the value stored at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_elem` fails.
    pub fn get(&self, index: u32, flags: u64) -> Result<CpuMapValue, MapError> {
        let data = self.inner.borrow();
        check_bounds(data, index)?;
        let fd = data.fd;

        let value =
            bpf_map_lookup_elem(fd, &index, flags).map_err(|(_, io_error)| SyscallError {
                call: "bpf_map_lookup_elem",
                io_error,
            })?;
        let value: bpf_cpumap_val = value.ok_or(MapError::KeyNotFound)?;

        // SAFETY: map writes use fd, map reads use id.
        // https://elixir.bootlin.com/linux/v6.2/source/include/uapi/linux/bpf.h#L6149
        Ok(CpuMapValue {
            qsize: value.qsize,
            prog_id: NonZeroU32::new(unsafe { value.bpf_prog.id }),
        })
    }

    /// An iterator over the elements of the map.
    pub fn iter(&self) -> impl Iterator<Item = Result<CpuMapValue, MapError>> + '_ {
        (0..self.len()).map(move |i| self.get(i, 0))
    }
}

impl<T: BorrowMut<MapData>> CpuMap<T> {
    /// Sets the value of the element at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails.
    pub fn set(
        &mut self,
        index: u32,
        value: u32,
        program: Option<impl AsRawFd>,
        flags: u64,
    ) -> Result<(), MapError> {
        let data = self.inner.borrow_mut();
        check_bounds(data, index)?;
        let fd = data.fd;

        let value = bpf_cpumap_val {
            qsize: value,
            bpf_prog: bpf_cpumap_val__bindgen_ty_1 {
                // Default is valid as the kernel will only consider fd > 0:
                // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/bpf/cpumap.c?h=v6.4.12#n466
                fd: program.map(|prog| prog.as_raw_fd()).unwrap_or_default(),
            },
        };
        bpf_map_update_elem(fd, Some(&index), &value, flags).map_err(|(_, io_error)| {
            SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            }
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
pub struct CpuMapValue {
    pub qsize: u32,
    pub prog_id: Option<NonZeroU32>,
}
