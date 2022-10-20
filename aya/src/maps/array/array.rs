use std::{
    convert::{AsMut, AsRef},
    marker::PhantomData,
};

use crate::{
    maps::{check_bounds, check_kv_size, IterableMap, MapData, MapError},
    sys::{bpf_map_lookup_elem, bpf_map_update_elem},
    Pod,
};

/// A fixed-size array.
///
/// The size of the array is defined on the eBPF side using the `bpf_map_def::max_entries` field.
/// All the entries are zero-initialized when the map is created.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 3.19.
///
/// # Examples
/// ```no_run
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use aya::maps::Array;
///
/// let mut array = Array::try_from(bpf.map_mut("ARRAY").unwrap())?;
/// array.set(1, 42, 0)?;
/// assert_eq!(array.get(&1, 0)?, 42);
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_ARRAY")]
pub struct Array<T, V: Pod> {
    inner: T,
    _v: PhantomData<V>,
}

impl<T: AsRef<MapData>, V: Pod> Array<T, V> {
    pub(crate) fn new(map: T) -> Result<Array<T, V>, MapError> {
        let data = map.as_ref();
        check_kv_size::<u32, V>(data)?;

        let _fd = data.fd_or_err()?;

        Ok(Array {
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

    /// Returns the value stored at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_elem` fails.
    pub fn get(&self, index: &u32, flags: u64) -> Result<V, MapError> {
        let data = self.inner.as_ref();
        check_bounds(data, *index)?;
        let fd = data.fd_or_err()?;

        let value = bpf_map_lookup_elem(fd, index, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                io_error,
            }
        })?;
        value.ok_or(MapError::KeyNotFound)
    }

    /// An iterator over the elements of the array. The iterator item type is `Result<V,
    /// MapError>`.
    pub fn iter(&self) -> impl Iterator<Item = Result<V, MapError>> + '_ {
        (0..self.len()).map(move |i| self.get(&i, 0))
    }
}

impl<T: AsMut<MapData>, V: Pod> Array<T, V> {
    /// Sets the value of the element at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails.
    pub fn set(&mut self, index: u32, value: V, flags: u64) -> Result<(), MapError> {
        let data = self.inner.as_mut();
        check_bounds(data, index)?;
        let fd = data.fd_or_err()?;
        bpf_map_update_elem(fd, Some(&index), &value, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                io_error,
            }
        })?;
        Ok(())
    }
}

impl<T: AsRef<MapData>, V: Pod> IterableMap<u32, V> for Array<T, V> {
    fn map(&self) -> &MapData {
        self.inner.as_ref()
    }

    fn get(&self, index: &u32) -> Result<V, MapError> {
        self.get(index, 0)
    }
}
