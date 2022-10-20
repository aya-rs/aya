use std::{
    convert::{AsMut, AsRef},
    marker::PhantomData,
};

use crate::{
    maps::{check_bounds, check_kv_size, IterableMap, MapData, MapError, PerCpuValues},
    sys::{bpf_map_lookup_elem_per_cpu, bpf_map_update_elem_per_cpu},
    Pod,
};

/// A per-CPU fixed-size array.
///
/// The size of the array is defined on the eBPF side using the `bpf_map_def::max_entries` field.
/// All the entries are zero-initialized when the map is created.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.6.
///
/// # Examples
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
/// use aya::maps::{PerCpuArray, PerCpuValues};
/// use aya::util::nr_cpus;
///
/// let mut array = PerCpuArray::try_from(bpf.map_mut("ARRAY").unwrap())?;
///
/// // set array[1] = 42 for all cpus
/// let nr_cpus = nr_cpus()?;
/// array.set(1, PerCpuValues::try_from(vec![42u32; nr_cpus])?, 0)?;
///
/// // retrieve the values at index 1 for all cpus
/// let values = array.get(&1, 0)?;
/// assert_eq!(values.len(), nr_cpus);
/// for cpu_val in values.iter() {
///     assert_eq!(*cpu_val, 42u32);
/// }
/// # Ok::<(), Error>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_PERCPU_ARRAY")]
pub struct PerCpuArray<T, V: Pod> {
    inner: T,
    _v: PhantomData<V>,
}

impl<T: AsRef<MapData>, V: Pod> PerCpuArray<T, V> {
    pub(crate) fn new(map: T) -> Result<PerCpuArray<T, V>, MapError> {
        let data = map.as_ref();
        check_kv_size::<u32, V>(data)?;

        let _fd = data.fd_or_err()?;

        Ok(PerCpuArray {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Returns the number of elements in the array.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn len(&self) -> u32 {
        self.inner.as_ref().obj.max_entries()
    }

    /// Returns a slice of values - one for each CPU - stored at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_elem` fails.
    pub fn get(&self, index: &u32, flags: u64) -> Result<PerCpuValues<V>, MapError> {
        let data = self.inner.as_ref();
        check_bounds(data, *index)?;
        let fd = data.fd_or_err()?;

        let value = bpf_map_lookup_elem_per_cpu(fd, index, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                io_error,
            }
        })?;
        value.ok_or(MapError::KeyNotFound)
    }

    /// An iterator over the elements of the array. The iterator item type is
    /// `Result<PerCpuValues<V>, MapError>`.
    pub fn iter(&self) -> impl Iterator<Item = Result<PerCpuValues<V>, MapError>> + '_ {
        (0..self.len()).map(move |i| self.get(&i, 0))
    }
}

impl<T: AsMut<MapData>, V: Pod> PerCpuArray<T, V> {
    /// Sets the values - one for each CPU - at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails.
    pub fn set(&mut self, index: u32, values: PerCpuValues<V>, flags: u64) -> Result<(), MapError> {
        let data = self.inner.as_mut();
        check_bounds(data, index)?;
        let fd = data.fd_or_err()?;

        bpf_map_update_elem_per_cpu(fd, &index, &values, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                io_error,
            }
        })?;
        Ok(())
    }
}

impl<T: AsRef<MapData>, V: Pod> IterableMap<u32, PerCpuValues<V>> for PerCpuArray<T, V> {
    fn map(&self) -> &MapData {
        self.inner.as_ref()
    }

    fn get(&self, index: &u32) -> Result<PerCpuValues<V>, MapError> {
        self.get(index, 0)
    }
}
