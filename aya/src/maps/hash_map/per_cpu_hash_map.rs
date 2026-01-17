//! Per-CPU hash map.
use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::AsFd as _,
};

use crate::{
    Pod,
    maps::{
        IterableMap, MapData, MapError, MapIter, MapKeys, PerCpuValues, check_kv_size, hash_map,
    },
    sys::{
        SyscallError, bpf_map_lookup_and_delete_batch_per_cpu, bpf_map_lookup_elem_per_cpu,
        bpf_map_update_elem_per_cpu,
    },
};

type BatchResult<K, V> = (Vec<K>, Vec<PerCpuValues<V>>, Option<K>);

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
        let values =
            bpf_map_lookup_elem_per_cpu(fd, key, flags).map_err(|io_error| SyscallError {
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

    /// Batch lookup and delete multiple key-value pairs from the map.
    ///
    /// This method retrieves and removes up to `batch_size` entries from the map in a single
    /// syscall, which is more efficient than calling `get` and `remove` individually for each key.
    ///
    /// # Arguments
    ///
    /// * `batch_size` - Maximum number of entries to retrieve in this batch
    /// * `in_batch` - Optional cursor from a previous batch operation (use `None` for the first call)
    /// * `flags` - Operation flags
    ///
    /// # Returns
    ///
    /// Returns a tuple of `(keys, values, out_batch)` where:
    /// - `keys` - Vector of retrieved keys
    /// - `values` - Vector of retrieved per-CPU values (one `PerCpuValues<V>` per key)
    /// - `out_batch` - Optional cursor for the next batch (pass this as `in_batch` to continue iteration)
    ///
    /// When `out_batch` is `None`, there are no more entries to retrieve.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 5.6.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # let mut bpf = aya::Ebpf::load(&[])?;
    /// use aya::maps::PerCpuHashMap;
    ///
    /// let mut hm = PerCpuHashMap::<_, u8, u32>::try_from(bpf.map_mut("PER_CPU_STORAGE").unwrap())?;
    ///
    /// // Retrieve and delete entries in batches of 64
    /// let mut cursor = None;
    /// loop {
    ///     let (keys, values, next_cursor) = hm.batch_lookup_and_delete(64, cursor.as_ref(), 0)?;
    ///
    ///     if keys.is_empty() {
    ///         break;
    ///     }
    ///
    ///     for (key, per_cpu_vals) in keys.iter().zip(values.iter()) {
    ///         println!("Key: {}, Values: {:?}", key, per_cpu_vals);
    ///     }
    ///
    ///     cursor = next_cursor;
    ///     if cursor.is_none() {
    ///         break;
    ///     }
    /// }
    /// # Ok::<(), aya::EbpfError>(())
    /// ```
    pub fn batch_lookup_and_delete(
        &self,
        batch_size: usize,
        in_batch: Option<&K>,
        flags: u64,
    ) -> Result<BatchResult<K, V>, MapError> {
        let fd = self.inner.borrow().fd().as_fd();

        bpf_map_lookup_and_delete_batch_per_cpu(fd, in_batch, batch_size, flags)
            .map(|batch| (batch.keys, batch.values, batch.out_batch))
            .map_err(|io_error| {
                SyscallError {
                    call: "bpf_map_lookup_and_delete_batch",
                    io_error,
                }
                .into()
            })
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
        bpf_map_update_elem_per_cpu(fd, key.borrow(), &values, flags)
            .map_err(|io_error| SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            })
            .map_err(Into::into)
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
    use std::io;

    use assert_matches::assert_matches;
    use aya_obj::generated::bpf_map_type::{
        BPF_MAP_TYPE_LRU_PERCPU_HASH, BPF_MAP_TYPE_PERCPU_HASH,
    };
    use libc::ENOENT;

    use super::*;
    use crate::{
        maps::{Map, test_utils},
        sys::{SysResult, override_syscall},
    };

    fn sys_error(value: i32) -> SysResult {
        Err((-1, io::Error::from_raw_os_error(value)))
    }

    #[test]
    fn test_try_from_ok() {
        let map = Map::PerCpuHashMap(test_utils::new_map(test_utils::new_obj_map::<u32>(
            BPF_MAP_TYPE_PERCPU_HASH,
        )));
        let _: PerCpuHashMap<_, u32, u32> = map.try_into().unwrap();
    }
    #[test]
    fn test_try_from_ok_lru() {
        let map_data =
            || test_utils::new_map(test_utils::new_obj_map::<u32>(BPF_MAP_TYPE_LRU_PERCPU_HASH));
        let map = Map::PerCpuHashMap(map_data());
        let _: PerCpuHashMap<_, u32, u32> = map.try_into().unwrap();
        let map = Map::PerCpuLruHashMap(map_data());
        let _: PerCpuHashMap<_, u32, u32> = map.try_into().unwrap();
    }
    #[test]
    fn test_get_not_found() {
        let map_data =
            || test_utils::new_map(test_utils::new_obj_map::<u32>(BPF_MAP_TYPE_LRU_PERCPU_HASH));
        let map = Map::PerCpuHashMap(map_data());
        let map = PerCpuHashMap::<_, u32, u32>::try_from(&map).unwrap();

        override_syscall(|_| sys_error(ENOENT));

        assert_matches!(map.get(&1, 0), Err(MapError::KeyNotFound));
    }

    #[test]
    fn test_batch_lookup_and_delete_empty() {
        use aya_obj::generated::bpf_cmd;

        use crate::sys::Syscall;

        let map_data =
            || test_utils::new_map(test_utils::new_obj_map::<u32>(BPF_MAP_TYPE_PERCPU_HASH));
        let map = Map::PerCpuHashMap(map_data());
        let map = PerCpuHashMap::<_, u32, u32>::try_from(&map).unwrap();

        // Mock the syscall to return ENOENT (no entries)
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_AND_DELETE_BATCH,
                attr,
            } => {
                // Kernel sets count to 0 when no entries are returned
                attr.batch.count = 0;
                sys_error(ENOENT)
            }
            _ => sys_error(libc::EINVAL),
        });

        let result = map.batch_lookup_and_delete(10, None, 0);
        assert_matches!(result, Ok((keys, values, cursor)) => {
            assert_eq!(keys.len(), 0);
            assert_eq!(values.len(), 0);
            assert_eq!(cursor, None);
        });
    }

    #[test]
    fn test_batch_lookup_and_delete_with_entries() {
        use std::ptr;

        use aya_obj::generated::bpf_cmd;

        use crate::{sys::Syscall, util::nr_cpus};

        let map_data =
            || test_utils::new_map(test_utils::new_obj_map::<u32>(BPF_MAP_TYPE_PERCPU_HASH));
        let map = Map::PerCpuHashMap(map_data());
        let map = PerCpuHashMap::<_, u32, u32>::try_from(&map).unwrap();

        // Mock the syscall to return 2 entries
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_AND_DELETE_BATCH,
                attr,
            } => unsafe {
                // Get nr_cpus inside the closure to avoid capturing
                let nr_cpus = nr_cpus().unwrap();

                // Fill in the keys
                let keys_ptr = attr.batch.keys as *mut u32;
                *keys_ptr.add(0) = 10;
                *keys_ptr.add(1) = 20;

                // Fill in the values (per-CPU)
                let value_size = (std::mem::size_of::<u32>() + 7) & !7;
                let values_ptr = attr.batch.values as *mut u8;

                // For key 10: values [100, 101, 102, ...]
                for cpu in 0..nr_cpus {
                    let offset = cpu * value_size;
                    ptr::write_unaligned(values_ptr.add(offset).cast::<u32>(), 100 + cpu as u32);
                }

                // For key 20: values [200, 201, 202, ...]
                for cpu in 0..nr_cpus {
                    let offset = nr_cpus * value_size + cpu * value_size;
                    ptr::write_unaligned(values_ptr.add(offset).cast::<u32>(), 200 + cpu as u32);
                }

                // Set the actual count
                attr.batch.count = 2;

                // Set out_batch (next cursor)
                let out_batch_ptr = attr.batch.out_batch as *mut u32;
                *out_batch_ptr = 30;

                Ok(0)
            },
            _ => sys_error(libc::EINVAL),
        });

        let result = map.batch_lookup_and_delete(10, None, 0);
        let nr_cpus = nr_cpus().unwrap();
        assert_matches!(result, Ok((keys, values, cursor)) => {
            assert_eq!(keys.len(), 2);
            assert_eq!(values.len(), 2);

            assert_eq!(keys[0], 10);
            assert_eq!(keys[1], 20);

            // Check per-CPU values for key 10
            assert_eq!(values[0].len(), nr_cpus);
            for (cpu, value) in values[0].iter().enumerate().take(nr_cpus) {
                assert_eq!(*value, 100 + cpu as u32);
            }

            // Check per-CPU values for key 20
            assert_eq!(values[1].len(), nr_cpus);
            for (cpu, value) in values[1].iter().enumerate().take(nr_cpus) {
                assert_eq!(*value, 200 + cpu as u32);
            }

            assert_eq!(cursor, Some(30));
        });
    }
}
