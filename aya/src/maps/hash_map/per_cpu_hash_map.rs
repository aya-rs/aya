//! Per-CPU hash map.
use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::AsFd as _,
};

use crate::{
    errors::MapError,
    maps::{check_kv_size, hash_map, IterableMap, MapData, MapIter, MapKeys, PerCpuValues},
    sys::{bpf_map_lookup_elem_per_cpu, bpf_map_update_elem_per_cpu},
    Pod,
};

/// Similar to [`HashMap`](crate::maps::HashMap) but each CPU holds a separate value for a given key. Typically used to
/// minimize lock contention in eBPF programs.
///
/// This type can be used with eBPF maps of type `BPF_MAP_TYPE_PERCPU_HASH` and
/// `BPF_MAP_TYPE_LRU_PERCPU_HASH`.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.6.
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::maps::PerCpuHashMap;
///
/// const CPU_IDS: u8 = 1;
/// const WAKEUPS: u8 = 2;
///
/// let mut hm = PerCpuHashMap::<_, u8, u32>::try_from(bpf.map_mut("PER_CPU_STORAGE").unwrap())?;
/// let cpu_ids = unsafe { hm.get(&CPU_IDS, 0)? };
/// let wakeups = unsafe { hm.get(&WAKEUPS, 0)? };
/// for (cpu_id, wakeups) in cpu_ids.iter().zip(wakeups.iter()) {
///     println!("cpu {} woke up {} times", cpu_id, wakeups);
/// }
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_LRU_PERCPU_HASH")]
#[doc(alias = "BPF_MAP_TYPE_PERCPU_HASH")]
pub struct PerCpuHashMap<T, K: Pod, V: Pod> {
    pub(crate) inner: T,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<T: Borrow<MapData>, K: Pod, V: Pod> PerCpuHashMap<T, K, V> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<K, V>(data)?;

        Ok(Self {
            inner: map,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    /// Returns a slice of values - one for each CPU - associated with the key.
    pub fn get(&self, key: &K, flags: u64) -> Result<PerCpuValues<V>, MapError> {
        let fd = self.inner.borrow().fd().as_fd();
        let values = bpf_map_lookup_elem_per_cpu(fd, key, flags)?;
        values.ok_or(MapError::KeyNotFound)
    }

    /// An iterator visiting all key-value pairs in arbitrary order. The
    /// iterator item type is `Result<(K, PerCpuValues<V>), MapError>`.
    pub fn iter(&self) -> MapIter<'_, K, PerCpuValues<V>, Self> {
        MapIter::new(self)
    }

    /// An iterator visiting all keys in arbitrary order. The iterator element
    /// type is `Result<K, MapError>`.
    pub fn keys(&self) -> MapKeys<'_, K> {
        MapKeys::new(self.inner.borrow())
    }
}

impl<T: BorrowMut<MapData>, K: Pod, V: Pod> PerCpuHashMap<T, K, V> {
    /// Inserts a slice of values - one for each CPU - for the given key.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[derive(thiserror::Error, Debug)]
    /// # enum Error {
    /// #     #[error(transparent)]
    /// #     IO(#[from] std::io::Error),
    /// #     #[error(transparent)]
    /// #     Map(#[from] aya::maps::MapError),
    /// #     #[error(transparent)]
    /// #     Ebpf(#[from] aya::EbpfError)
    /// # }
    /// # let mut bpf = aya::Ebpf::load(&[])?;
    /// use aya::maps::{PerCpuHashMap, PerCpuValues};
    /// use aya::util::nr_cpus;
    ///
    /// const RETRIES: u8 = 1;
    ///
    /// let nr_cpus = nr_cpus().map_err(|(_, error)| error)?;
    /// let mut hm = PerCpuHashMap::<_, u8, u32>::try_from(bpf.map_mut("PER_CPU_STORAGE").unwrap())?;
    /// hm.insert(
    ///     RETRIES,
    ///     PerCpuValues::try_from(vec![3u32; nr_cpus])?,
    ///     0,
    /// )?;
    /// # Ok::<(), Error>(())
    /// ```
    pub fn insert(
        &mut self,
        key: impl Borrow<K>,
        values: PerCpuValues<V>,
        flags: u64,
    ) -> Result<(), MapError> {
        let fd = self.inner.borrow_mut().fd().as_fd();
        bpf_map_update_elem_per_cpu(fd, key.borrow(), &values, flags)?;
        Ok(())
    }

    /// Removes a key from the map.
    pub fn remove(&mut self, key: &K) -> Result<(), MapError> {
        hash_map::remove(self.inner.borrow_mut(), key)
    }
}

impl<T: Borrow<MapData>, K: Pod, V: Pod> IterableMap<K, PerCpuValues<V>>
    for PerCpuHashMap<T, K, V>
{
    fn map(&self) -> &MapData {
        self.inner.borrow()
    }

    fn get(&self, key: &K) -> Result<PerCpuValues<V>, MapError> {
        Self::get(self, key, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        generated::bpf_map_type::{BPF_MAP_TYPE_LRU_PERCPU_HASH, BPF_MAP_TYPE_PERCPU_HASH},
        maps::{test_utils, Map},
    };

    #[test]
    fn test_try_from_ok() {
        let map = Map::PerCpuHashMap(test_utils::new_map(test_utils::new_obj_map::<u32>(
            BPF_MAP_TYPE_PERCPU_HASH,
        )));
        assert!(PerCpuHashMap::<_, u32, u32>::try_from(&map).is_ok())
    }
    #[test]
    fn test_try_from_ok_lru() {
        let map_data =
            || test_utils::new_map(test_utils::new_obj_map::<u32>(BPF_MAP_TYPE_LRU_PERCPU_HASH));
        let map = Map::PerCpuHashMap(map_data());
        assert!(PerCpuHashMap::<_, u32, u32>::try_from(&map).is_ok());
        let map = Map::PerCpuLruHashMap(map_data());
        assert!(PerCpuHashMap::<_, u32, u32>::try_from(&map).is_ok())
    }
}
