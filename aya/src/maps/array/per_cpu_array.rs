use std::{
    convert::TryFrom,
    marker::PhantomData,
    mem,
    ops::{Deref, DerefMut},
};

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY,
    maps::{IterableMap, Map, MapError, MapRef, MapRefMut, PerCpuValues},
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
/// # let bpf = aya::Bpf::load(&[], None)?;
/// use aya::maps::{PerCpuArray, PerCpuValues};
/// use aya::util::nr_cpus;
/// use std::convert::TryFrom;
///
/// let mut array = PerCpuArray::try_from(bpf.map_mut("ARRAY")?)?;
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
pub struct PerCpuArray<T: Deref<Target = Map>, V: Pod> {
    inner: T,
    _v: PhantomData<V>,
}

impl<T: Deref<Target = Map>, V: Pod> PerCpuArray<T, V> {
    fn new(map: T) -> Result<PerCpuArray<T, V>, MapError> {
        let map_type = map.obj.def.map_type;
        if map_type != BPF_MAP_TYPE_PERCPU_ARRAY as u32 {
            return Err(MapError::InvalidMapType {
                map_type: map_type as u32,
            });
        }
        let expected = mem::size_of::<u32>();
        let size = map.obj.def.key_size as usize;
        if size != expected {
            return Err(MapError::InvalidKeySize { size, expected });
        }

        let expected = mem::size_of::<V>();
        let size = map.obj.def.value_size as usize;
        if size != expected {
            return Err(MapError::InvalidValueSize { size, expected });
        }
        let _fd = map.fd_or_err()?;

        Ok(PerCpuArray {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Returns the number of elements in the array.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn len(&self) -> u32 {
        self.inner.obj.def.max_entries
    }

    /// Returns a slice of values - one for each CPU - stored at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_elem` fails.
    pub fn get(&self, index: &u32, flags: u64) -> Result<PerCpuValues<V>, MapError> {
        self.check_bounds(*index)?;
        let fd = self.inner.fd_or_err()?;

        let value = bpf_map_lookup_elem_per_cpu(fd, index, flags).map_err(|(code, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                code,
                io_error,
            }
        })?;
        value.ok_or(MapError::KeyNotFound)
    }

    /// An iterator over the elements of the array. The iterator item type is
    /// `Result<PerCpuValues<V>, MapError>`.
    pub unsafe fn iter(&self) -> impl Iterator<Item = Result<PerCpuValues<V>, MapError>> + '_ {
        (0..self.len()).map(move |i| self.get(&i, 0))
    }

    fn check_bounds(&self, index: u32) -> Result<(), MapError> {
        let max_entries = self.inner.obj.def.max_entries;
        if index >= self.inner.obj.def.max_entries {
            Err(MapError::OutOfBounds { index, max_entries })
        } else {
            Ok(())
        }
    }
}

impl<T: Deref<Target = Map> + DerefMut<Target = Map>, V: Pod> PerCpuArray<T, V> {
    /// Sets the values - one for each CPU - at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails.
    pub fn set(&mut self, index: u32, values: PerCpuValues<V>, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.fd_or_err()?;
        self.check_bounds(index)?;
        bpf_map_update_elem_per_cpu(fd, &index, &values, flags).map_err(|(code, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                code,
                io_error,
            }
        })?;
        Ok(())
    }
}

impl<T: Deref<Target = Map>, V: Pod> IterableMap<u32, PerCpuValues<V>> for PerCpuArray<T, V> {
    fn map(&self) -> &Map {
        &self.inner
    }

    unsafe fn get(&self, index: &u32) -> Result<PerCpuValues<V>, MapError> {
        self.get(index, 0)
    }
}

impl<V: Pod> TryFrom<MapRef> for PerCpuArray<MapRef, V> {
    type Error = MapError;

    fn try_from(a: MapRef) -> Result<PerCpuArray<MapRef, V>, MapError> {
        PerCpuArray::new(a)
    }
}

impl<V: Pod> TryFrom<MapRefMut> for PerCpuArray<MapRefMut, V> {
    type Error = MapError;

    fn try_from(a: MapRefMut) -> Result<PerCpuArray<MapRefMut, V>, MapError> {
        PerCpuArray::new(a)
    }
}
