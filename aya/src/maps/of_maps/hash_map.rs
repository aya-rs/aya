use std::{
    convert::TryFrom,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    os::unix::io::{IntoRawFd, RawFd},
};

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_HASH_OF_MAPS,
    maps::{
        hash_map, of_maps::MapOfMaps, IterableMap, Map, MapError, MapIter, MapKeys, MapRef,
        MapRefMut,
    },
    sys::{bpf_map_get_fd_by_id, bpf_map_lookup_elem},
    Pod,
};

/// A hash map of eBPF Maps.
///
/// A `HashMap` is used to store references to eBPF Maps
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.18.
#[doc(alias = "BPF_MAP_TYPE_HASH_OF_MAPS")]
pub struct HashMap<T: Deref<Target = Map>, K> {
    inner: T,
    _k: PhantomData<K>,
}

impl<T: Deref<Target = Map>, K: Pod> HashMap<T, K> {
    pub(crate) fn new(map: T) -> Result<HashMap<T, K>, MapError> {
        let map_type = map.obj.def.map_type;

        // validate the map definition
        if map_type != BPF_MAP_TYPE_HASH_OF_MAPS as u32 {
            return Err(MapError::InvalidMapType {
                map_type: map_type as u32,
            });
        }
        hash_map::check_kv_size::<K, u32>(&map)?;
        let _ = map.fd_or_err()?;

        Ok(HashMap {
            inner: map,
            _k: PhantomData,
        })
    }

    /// Returns the fd of the map stored at the given key.
    pub unsafe fn get(&self, key: &K, flags: u64) -> Result<RawFd, MapError> {
        let fd = self.inner.deref().fd_or_err()?;
        let id = bpf_map_lookup_elem(fd, key, flags)
            .map_err(|(code, io_error)| MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                code,
                io_error,
            })?
            .ok_or(MapError::KeyNotFound)?;
        let inner_fd = bpf_map_get_fd_by_id(id).map_err(|io_error| MapError::SyscallError {
            call: "bpf_map_get_fd_by_id".to_owned(),
            code: 0,
            io_error,
        })?;
        Ok(inner_fd as RawFd)
    }

    /// An iterator visiting all key-value pairs in arbitrary order. The
    /// iterator item type is `Result<(K, V), MapError>`.
    pub unsafe fn iter(&self) -> MapIter<'_, K, RawFd> {
        MapIter::new(self)
    }

    /// An iterator visiting all keys in arbitrary order. The iterator element
    /// type is `Result<K, MapError>`.
    pub unsafe fn keys(&self) -> MapKeys<'_, K> {
        MapKeys::new(&self.inner)
    }
}

impl<T: DerefMut<Target = Map>, K: Pod> HashMap<T, K> {
    /// Inserts a map under the given key.
    pub fn insert<I: IntoRawFd>(&mut self, key: K, value: I, flags: u64) -> Result<(), MapError> {
        let map_fd = value.into_raw_fd();
        hash_map::insert(&mut self.inner, key, map_fd, flags)?;
        // safety: we're closing a RawFd which we have ownership of
        // this is required because inserting this in to the map causes
        // there to be a reference to the map in both kernel and userspace
        unsafe { libc::close(map_fd) };
        Ok(())
    }

    /// Removes a map from the map.
    pub fn remove(&mut self, key: &K) -> Result<(), MapError> {
        hash_map::remove(&mut self.inner, key)
    }
}

impl<T: Deref<Target = Map>, K: Pod> IterableMap<K, RawFd> for HashMap<T, K> {
    fn map(&self) -> &Map {
        &self.inner
    }

    unsafe fn get(&self, key: &K) -> Result<RawFd, MapError> {
        HashMap::get(self, key, 0)
    }
}

impl<T: DerefMut<Target = Map>, K: Pod> MapOfMaps for HashMap<T, K> {
    fn fd_or_err(&self) -> Result<RawFd, MapError> {
        self.inner.fd_or_err()
    }
}

impl<K: Pod> TryFrom<MapRef> for HashMap<MapRef, K> {
    type Error = MapError;

    fn try_from(a: MapRef) -> Result<HashMap<MapRef, K>, MapError> {
        HashMap::new(a)
    }
}

impl<K: Pod> TryFrom<MapRefMut> for HashMap<MapRefMut, K> {
    type Error = MapError;

    fn try_from(a: MapRefMut) -> Result<HashMap<MapRefMut, K>, MapError> {
        HashMap::new(a)
    }
}
