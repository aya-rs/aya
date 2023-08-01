//! Per-CPU hash map.
use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

use crate::{
    maps::{
        check_kv_size, hash_map, IterableMap, MapData, MapError, MapIter, MapKeys, PerCpuValues,
    },
    sys::{bpf_map_lookup_elem_per_cpu, bpf_map_update_elem_per_cpu, SyscallError},
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
/// # let mut bpf = aya::Bpf::load(&[])?;
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
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_LRU_PERCPU_HASH")]
#[doc(alias = "BPF_MAP_TYPE_PERCPU_HASH")]
pub struct PerCpuHashMap<T, K: Pod, V: Pod> {
    inner: T,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<T: Borrow<MapData>, K: Pod, V: Pod> PerCpuHashMap<T, K, V> {
    pub(crate) fn new(map: T) -> Result<PerCpuHashMap<T, K, V>, MapError> {
        let data = map.borrow();
        check_kv_size::<K, V>(data)?;

        let _ = data.fd_or_err()?;

        Ok(PerCpuHashMap {
            inner: map,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    /// Returns a slice of values - one for each CPU - associated with the key.
    pub fn get(&self, key: &K, flags: u64) -> Result<PerCpuValues<V>, MapError> {
        let fd = self.inner.borrow().fd_or_err()?;
        let values =
            bpf_map_lookup_elem_per_cpu(fd, key, flags).map_err(|(_, io_error)| SyscallError {
                call: "bpf_map_lookup_elem",
                io_error,
            })?;
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
    /// #     Bpf(#[from] aya::BpfError)
    /// # }
    /// # let mut bpf = aya::Bpf::load(&[])?;
    /// use aya::maps::{PerCpuHashMap, PerCpuValues};
    /// use aya::util::nr_cpus;
    ///
    /// const RETRIES: u8 = 1;
    ///
    /// let mut hm = PerCpuHashMap::<_, u8, u32>::try_from(bpf.map_mut("PER_CPU_STORAGE").unwrap())?;
    /// hm.insert(
    ///     RETRIES,
    ///     PerCpuValues::try_from(vec![3u32; nr_cpus()?])?,
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
        let fd = self.inner.borrow_mut().fd_or_err()?;
        bpf_map_update_elem_per_cpu(fd, key.borrow(), &values, flags).map_err(
            |(_, io_error)| SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            },
        )?;

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
        PerCpuHashMap::get(self, key, 0)
    }
}
