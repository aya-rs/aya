//! Per-CPU hash map.
use std::{
    convert::TryFrom,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use crate::{
    generated::bpf_map_type::{BPF_MAP_TYPE_LRU_PERCPU_HASH, BPF_MAP_TYPE_PERCPU_HASH},
    maps::{
        hash_map, IterableMap, Map, MapError, MapIter, MapKeys, MapRef, MapRefMut, PerCpuValues,
    },
    sys::{bpf_map_lookup_elem_per_cpu, bpf_map_update_elem_per_cpu},
    Pod,
};

/// Similar to [`HashMap`](crate::maps::HashMap) but each CPU holds a separate value for a given key. Tipically used to
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
/// # let bpf = aya::Bpf::load(&[], None)?;
/// use aya::maps::PerCpuHashMap;
/// use std::convert::TryFrom;
///
/// const CPU_IDS: u8 = 1;
/// const WAKEUPS: u8 = 2;
///
/// let mut hm = PerCpuHashMap::<_, u8, u32>::try_from(bpf.map("COUNTERS")?)?;
/// let cpu_ids = unsafe { hm.get(&CPU_IDS, 0)? };
/// let wakeups = unsafe { hm.get(&WAKEUPS, 0)? };
/// for (cpu_id, wakeups) in cpu_ids.iter().zip(wakeups.iter()) {
///     println!("cpu {} woke up {} times", cpu_id, wakeups);
/// }
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_LRU_PERCPU_HASH")]
#[doc(alias = "BPF_MAP_TYPE_PERCPU_HASH")]
pub struct PerCpuHashMap<T: Deref<Target = Map>, K: Pod, V: Pod> {
    inner: T,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<T: Deref<Target = Map>, K: Pod, V: Pod> PerCpuHashMap<T, K, V> {
    pub(crate) fn new(map: T) -> Result<PerCpuHashMap<T, K, V>, MapError> {
        let map_type = map.obj.def.map_type;

        // validate the map definition
        if map_type != BPF_MAP_TYPE_PERCPU_HASH as u32
            && map_type != BPF_MAP_TYPE_LRU_PERCPU_HASH as u32
        {
            return Err(MapError::InvalidMapType {
                map_type: map_type as u32,
            });
        }
        hash_map::check_kv_size::<K, V>(&map)?;
        let _ = map.fd_or_err()?;

        Ok(PerCpuHashMap {
            inner: map,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    /// Returns a slice of values - one for each CPU - associated with the key.
    pub unsafe fn get(&self, key: &K, flags: u64) -> Result<PerCpuValues<V>, MapError> {
        let fd = self.inner.deref().fd_or_err()?;
        let values = bpf_map_lookup_elem_per_cpu(fd, key, flags).map_err(|(code, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                code,
                io_error,
            }
        })?;
        values.ok_or(MapError::KeyNotFound)
    }

    /// An iterator visiting all key-value pairs in arbitrary order. The
    /// iterator item type is `Result<(K, PerCpuValues<V>), MapError>`.
    pub unsafe fn iter(&self) -> MapIter<'_, K, PerCpuValues<V>> {
        MapIter::new(self)
    }

    /// An iterator visiting all keys in arbitrary order. The iterator element
    /// type is `Result<K, MapError>`.
    pub unsafe fn keys(&self) -> MapKeys<'_, K> {
        MapKeys::new(&self.inner)
    }
}

impl<T: DerefMut<Target = Map>, K: Pod, V: Pod> PerCpuHashMap<T, K, V> {
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
    /// # let bpf = aya::Bpf::load(&[], None)?;
    /// use aya::maps::{PerCpuHashMap, PerCpuValues};
    /// use aya::util::nr_cpus;
    /// use std::convert::TryFrom;
    ///
    /// const RETRIES: u8 = 1;
    ///
    /// let mut hm = PerCpuHashMap::<_, u8, u32>::try_from(bpf.map_mut("PER_CPU_STORAGE")?)?;
    /// hm.insert(
    ///     RETRIES,
    ///     PerCpuValues::try_from(vec![3u32; nr_cpus()?])?,
    ///     0,
    /// )?;
    /// # Ok::<(), Error>(())
    /// ```
    pub fn insert(&mut self, key: K, values: PerCpuValues<V>, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.fd_or_err()?;
        bpf_map_update_elem_per_cpu(fd, &key, &values, flags).map_err(|(code, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                code,
                io_error,
            }
        })?;

        Ok(())
    }

    /// Removes a key from the map.
    pub fn remove(&mut self, key: &K) -> Result<(), MapError> {
        hash_map::remove(&mut self.inner, key)
    }
}

impl<T: Deref<Target = Map>, K: Pod, V: Pod> IterableMap<K, PerCpuValues<V>>
    for PerCpuHashMap<T, K, V>
{
    fn map(&self) -> &Map {
        &self.inner
    }

    unsafe fn get(&self, key: &K) -> Result<PerCpuValues<V>, MapError> {
        PerCpuHashMap::get(self, key, 0)
    }
}

impl<K: Pod, V: Pod> TryFrom<MapRef> for PerCpuHashMap<MapRef, K, V> {
    type Error = MapError;

    fn try_from(a: MapRef) -> Result<PerCpuHashMap<MapRef, K, V>, MapError> {
        PerCpuHashMap::new(a)
    }
}

impl<K: Pod, V: Pod> TryFrom<MapRefMut> for PerCpuHashMap<MapRefMut, K, V> {
    type Error = MapError;

    fn try_from(a: MapRefMut) -> Result<PerCpuHashMap<MapRefMut, K, V>, MapError> {
        PerCpuHashMap::new(a)
    }
}

impl<'a, K: Pod, V: Pod> TryFrom<&'a Map> for PerCpuHashMap<&'a Map, K, V> {
    type Error = MapError;

    fn try_from(a: &'a Map) -> Result<PerCpuHashMap<&'a Map, K, V>, MapError> {
        PerCpuHashMap::new(a)
    }
}

impl<'a, K: Pod, V: Pod> TryFrom<&'a mut Map> for PerCpuHashMap<&'a mut Map, K, V> {
    type Error = MapError;

    fn try_from(a: &'a mut Map) -> Result<PerCpuHashMap<&'a mut Map, K, V>, MapError> {
        PerCpuHashMap::new(a)
    }
}
