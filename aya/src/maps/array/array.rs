use std::{
    convert::TryFrom,
    marker::PhantomData,
    mem,
    ops::{Deref, DerefMut},
};

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_ARRAY,
    maps::{IterableMap, Map, MapError, MapRef, MapRefMut},
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
/// # let bpf = aya::Bpf::load(&[], None)?;
/// use aya::maps::Array;
/// use std::convert::TryFrom;
///
/// let mut array = Array::try_from(bpf.map_mut("ARRAY")?)?;
/// array.set(1, 42, 0)?;
/// assert_eq!(array.get(&1, 0)?, 42);
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_ARRAY")]
pub struct Array<T: Deref<Target = Map>, V: Pod> {
    inner: T,
    _v: PhantomData<V>,
}

impl<T: Deref<Target = Map>, V: Pod> Array<T, V> {
    fn new(map: T) -> Result<Array<T, V>, MapError> {
        let map_type = map.obj.def.map_type;
        if map_type != BPF_MAP_TYPE_ARRAY as u32 {
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

        Ok(Array {
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

    /// Returns the value stored at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_elem` fails.
    pub fn get(&self, index: &u32, flags: u64) -> Result<V, MapError> {
        self.check_bounds(*index)?;
        let fd = self.inner.fd_or_err()?;

        let value = bpf_map_lookup_elem(fd, index, flags).map_err(|(code, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                code,
                io_error,
            }
        })?;
        value.ok_or(MapError::KeyNotFound)
    }

    /// An iterator over the elements of the array. The iterator item type is `Result<V,
    /// MapError>`.
    pub unsafe fn iter(&self) -> impl Iterator<Item = Result<V, MapError>> + '_ {
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

impl<T: Deref<Target = Map> + DerefMut<Target = Map>, V: Pod> Array<T, V> {
    /// Sets the value of the element at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails.
    pub fn set(&mut self, index: u32, value: V, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.fd_or_err()?;
        self.check_bounds(index)?;
        bpf_map_update_elem(fd, &index, &value, flags).map_err(|(code, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                code,
                io_error,
            }
        })?;
        Ok(())
    }
}

impl<T: Deref<Target = Map>, V: Pod> IterableMap<u32, V> for Array<T, V> {
    fn map(&self) -> &Map {
        &self.inner
    }

    unsafe fn get(&self, index: &u32) -> Result<V, MapError> {
        self.get(index, 0)
    }
}

impl<V: Pod> TryFrom<MapRef> for Array<MapRef, V> {
    type Error = MapError;

    fn try_from(a: MapRef) -> Result<Array<MapRef, V>, MapError> {
        Array::new(a)
    }
}

impl<V: Pod> TryFrom<MapRefMut> for Array<MapRefMut, V> {
    type Error = MapError;

    fn try_from(a: MapRefMut) -> Result<Array<MapRefMut, V>, MapError> {
        Array::new(a)
    }
}
