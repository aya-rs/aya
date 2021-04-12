use std::{
    convert::TryFrom,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    os::unix::io::{AsRawFd, RawFd},
};

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_SOCKHASH,
    maps::{
        hash_map, sock::SocketMap, IterableMap, Map, MapError, MapIter, MapKeys, MapRef, MapRefMut,
    },
    sys::bpf_map_lookup_elem,
    Pod,
};

/// A hash map that can be shared between eBPF programs and user space.
///
/// It is required that both keys and values implement the [`Pod`] trait.
///
/// # Example
///
/// ```no_run
/// # let bpf = aya::Bpf::load(&[], None)?;
/// use aya::maps::SockHash;
/// use std::convert::TryFrom;
///
/// const CONFIG_KEY_NUM_RETRIES: u8 = 1;
///
/// let mut hm = SockHash::try_from(bpf.map_mut("CONFIG")?)?;
/// hm.insert(CONFIG_KEY_NUM_RETRIES, 3, 0 /* flags */);
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_SOCKHASH")]
pub struct SockHash<T: Deref<Target = Map>, K> {
    inner: T,
    _k: PhantomData<K>,
}

impl<T: Deref<Target = Map>, K: Pod> SockHash<T, K> {
    pub(crate) fn new(map: T) -> Result<SockHash<T, K>, MapError> {
        let map_type = map.obj.def.map_type;

        // validate the map definition
        if map_type != BPF_MAP_TYPE_SOCKHASH as u32 {
            return Err(MapError::InvalidMapType {
                map_type: map_type as u32,
            })?;
        }
        hash_map::check_kv_size::<K, u32>(&map)?;
        let _ = map.fd_or_err()?;

        Ok(SockHash {
            inner: map,
            _k: PhantomData,
        })
    }

    /// Returns a copy of the value associated with the key.
    pub unsafe fn get(&self, key: &K, flags: u64) -> Result<u32, MapError> {
        let fd = self.inner.deref().fd_or_err()?;
        let value = bpf_map_lookup_elem(fd, key, flags).map_err(|(code, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                code,
                io_error,
            }
        })?;
        value.ok_or(MapError::KeyNotFound)
    }

    /// An iterator visiting all key-value pairs in arbitrary order. The
    /// iterator item type is `Result<(K, V), MapError>`.
    pub unsafe fn iter(&self) -> MapIter<'_, K, u32> {
        MapIter::new(self)
    }

    /// An iterator visiting all keys in arbitrary order. The iterator element
    /// type is `Result<K, MapError>`.
    pub unsafe fn keys(&self) -> MapKeys<'_, K> {
        MapKeys::new(&self.inner)
    }
}

impl<T: DerefMut<Target = Map>, K: Pod> SockHash<T, K> {
    /// Inserts a key-value pair into the map.
    pub fn insert<I: AsRawFd>(&mut self, key: K, value: I, flags: u64) -> Result<(), MapError> {
        hash_map::insert(&mut self.inner, key, value.as_raw_fd(), flags)
    }

    /// Removes a key from the map.
    pub fn remove(&mut self, key: &K) -> Result<(), MapError> {
        hash_map::remove(&mut self.inner, key)
    }
}

impl<T: Deref<Target = Map>, K: Pod> IterableMap<K, u32> for SockHash<T, K> {
    fn map(&self) -> &Map {
        &self.inner
    }

    unsafe fn get(&self, key: &K) -> Result<u32, MapError> {
        SockHash::get(self, key, 0)
    }
}

impl<T: DerefMut<Target = Map>, K: Pod> SocketMap for SockHash<T, K> {
    fn fd_or_err(&self) -> Result<RawFd, MapError> {
        self.inner.fd_or_err()
    }
}

impl<K: Pod> TryFrom<MapRef> for SockHash<MapRef, K> {
    type Error = MapError;

    fn try_from(a: MapRef) -> Result<SockHash<MapRef, K>, MapError> {
        SockHash::new(a)
    }
}

impl<K: Pod> TryFrom<MapRefMut> for SockHash<MapRefMut, K> {
    type Error = MapError;

    fn try_from(a: MapRefMut) -> Result<SockHash<MapRefMut, K>, MapError> {
        SockHash::new(a)
    }
}
