//! An array of network devices.

use std::{
    borrow::{Borrow, BorrowMut},
    num::NonZeroU32,
    os::fd::AsRawFd,
};

use aya_obj::generated::{bpf_devmap_val, bpf_devmap_val__bindgen_ty_1};

use crate::{
    maps::{check_bounds, check_kv_size, IterableMap, MapData, MapError},
    sys::{bpf_map_lookup_elem, bpf_map_update_elem, SyscallError},
    Pod,
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
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use aya::maps::xdp::DevMap;
///
/// let mut devmap = DevMap::try_from(bpf.map_mut("IFACES").unwrap())?;
/// let source = 32u32;
/// let dest = 42u32;
/// devmap.set(source, dest, None::<i32>, 0);
///
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_DEVMAP")]
pub struct DevMap<T> {
    inner: T,
}

impl<T: Borrow<MapData>> DevMap<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<u32, bpf_devmap_val>(data)?;

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
    pub fn get(&self, index: u32, flags: u64) -> Result<DevMapValue, MapError> {
        let data = self.inner.borrow();
        check_bounds(data, index)?;
        let fd = data.fd;

        let value =
            bpf_map_lookup_elem(fd, &index, flags).map_err(|(_, io_error)| SyscallError {
                call: "bpf_map_lookup_elem",
                io_error,
            })?;
        let value: bpf_devmap_val = value.ok_or(MapError::KeyNotFound)?;

        // SAFETY: map writes use fd, map reads use id.
        // https://elixir.bootlin.com/linux/v6.2/source/include/uapi/linux/bpf.h#L6136
        Ok(DevMapValue {
            ifindex: value.ifindex,
            prog_id: NonZeroU32::new(unsafe { value.bpf_prog.id }),
        })
    }

    /// An iterator over the elements of the array.
    pub fn iter(&self) -> impl Iterator<Item = Result<DevMapValue, MapError>> + '_ {
        (0..self.len()).map(move |i| self.get(i, 0))
    }
}

impl<T: BorrowMut<MapData>> DevMap<T> {
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

        let value = bpf_devmap_val {
            ifindex: value,
            bpf_prog: bpf_devmap_val__bindgen_ty_1 {
                // Default is valid as the kernel will only consider fd > 0:
                // https://elixir.bootlin.com/linux/v6.4.12/source/kernel/bpf/devmap.c#L866
                // https://elixir.bootlin.com/linux/v6.4.12/source/kernel/bpf/devmap.c#L918
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
pub struct DevMapValue {
    pub ifindex: u32,
    pub prog_id: Option<NonZeroU32>,
}
