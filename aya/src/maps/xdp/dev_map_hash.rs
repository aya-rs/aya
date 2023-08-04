//! An hashmap of network devices.

use std::borrow::{Borrow, BorrowMut};

use crate::{
    maps::{check_kv_size, hash_map, IterableMap, MapData, MapError, MapIter, MapKeys},
    sys::{bpf_map_lookup_elem, SyscallError},
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
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use aya::maps::xdp::DevMapHash;
///
/// let mut devmap = DevMapHash::try_from(bpf.map_mut("IFACES").unwrap())?;
/// let flags = 0;
/// let ifindex = 32u32;
/// devmap.insert(ifindex, ifindex, flags);
///
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_DEVMAP_HASH")]
pub struct DevMapHash<T> {
    inner: T,
}

impl<T: Borrow<MapData>> DevMapHash<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<u32, u32>(data)?;

        Ok(Self { inner: map })
    }

    /// Returns the value stored at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_elem` fails.
    pub fn get(&self, index: u32, flags: u64) -> Result<u32, MapError> {
        let fd = self.inner.borrow().fd;
        let value =
            bpf_map_lookup_elem(fd, &index, flags).map_err(|(_, io_error)| SyscallError {
                call: "bpf_map_lookup_elem",
                io_error,
            })?;
        value.ok_or(MapError::KeyNotFound)
    }

    /// An iterator over the elements of the devmap in arbitrary order.
    pub fn iter(&self) -> MapIter<'_, u32, u32, Self> {
        MapIter::new(self)
    }

    /// An iterator visiting all keys in arbitrary order.
    pub fn keys(&self) -> MapKeys<'_, u32> {
        MapKeys::new(self.inner.borrow())
    }
}

impl<T: BorrowMut<MapData>> DevMapHash<T> {
    /// Inserts a value in the map.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::SyscallError`] if `bpf_map_update_elem` fails.
    pub fn insert(&mut self, index: u32, value: u32, flags: u64) -> Result<(), MapError> {
        hash_map::insert(self.inner.borrow_mut(), &index, &value, flags)
    }

    /// Remove a value from the map.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::SyscallError`] if `bpf_map_delete_elem` fails.
    pub fn remove(&mut self, key: u32) -> Result<(), MapError> {
        hash_map::remove(self.inner.borrow_mut(), &key)
    }
}

impl<T: Borrow<MapData>> IterableMap<u32, u32> for DevMapHash<T> {
    fn map(&self) -> &MapData {
        self.inner.borrow()
    }

    fn get(&self, key: &u32) -> Result<u32, MapError> {
        self.get(*key, 0)
    }
}
