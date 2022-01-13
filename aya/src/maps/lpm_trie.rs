//! A LPM Trie.
use std::{convert::TryFrom, marker::PhantomData, mem, ops::Deref};

use crate::{
    generated::{bpf_lpm_trie_key, bpf_map_type::BPF_MAP_TYPE_LPM_TRIE},
    maps::{Map, IterableMap, MapError, MapRef, MapRefMut},
    sys::{bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem},
    Pod,
};

/// A Longest Prefix Match Trie.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.20.
///
/// # Examples
/// ```no_run
/// # let bpf = aya::Bpf::load(&[])?;
/// use aya::maps::LpmTrie;
/// use std::convert::TryFrom;
///
/// let mut trie = LpmTrie::try_from(bpf.map_mut("LPM_TRIE")?)?;
///
/// # Ok::<(), aya::BpfError>(())
/// ```

#[doc(alias = "BPF_MAP_TYPE_LPM_TRIE")]
pub struct LpmTrie<T: Deref<Target = Map>, K, V> {
    inner: T,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

#[repr(packed)]
pub struct Key<K: Pod> {
    pub key_base: bpf_lpm_trie_key,
    pub data: K,
}

impl<K: Pod> Key<K> {
    pub fn new(prefixlen: u32, data: K) -> Self {
        Self {
            key_base: bpf_lpm_trie_key {
                prefixlen: prefixlen,
                data: Default::default(),
            },
            data: data,
        }
    }
}

impl<K:Pod> Copy for Key<K> { }

impl<K:Pod> Clone for Key<K> {
    fn clone(&self) -> Self {
        *self
    }
}

// A Pod impl is required as bpf_lpm_trie_key is a key for a map.
unsafe impl<K: Pod> Pod for Key<K> {}

impl<T: Deref<Target = Map>, K: Pod, V: Pod> LpmTrie<T, K, V> {
    pub(crate) fn new(map: T) -> Result<LpmTrie<T, K, V>, MapError> {
        let map_type = map.obj.def.map_type;

        // validate the map definition
        if map_type != BPF_MAP_TYPE_LPM_TRIE as u32 {
            return Err(MapError::InvalidMapType {
                map_type: map_type as u32,
            });
        }
        let size = mem::size_of::<K>() + mem::size_of::<bpf_lpm_trie_key>();
        let expected = map.obj.def.key_size as usize;
        if size != expected {
            return Err(MapError::InvalidKeySize { size, expected });
        }
        let size = mem::size_of::<V>();
        let expected = map.obj.def.value_size as usize;
        if size != expected {
            return Err(MapError::InvalidValueSize { size, expected });
        };

        let _ = map.fd_or_err()?;

        Ok(LpmTrie {
            inner: map,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    /// Returns a copy of the value associated with the key.
    pub fn get(&self, key: Key<K>, flags: u64) -> Result<V, MapError> {
        let fd = self.inner.deref().fd_or_err()?;
        let value = bpf_map_lookup_elem(fd, &key, flags).map_err(|(code, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                code,
                io_error,
            }
        })?;
        value.ok_or(MapError::KeyNotFound)
    }

    /// Updates a key-value pair for the value associated with the key.
    pub fn insert(&self, key: Key<K>, value: V, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.deref().fd_or_err()?;
        bpf_map_update_elem(fd, &key, &value, flags).map_err(|(code, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                code,
                io_error,
            }
        })?;

        Ok(())
    }

    /// Deletes elements from the map by key.
    pub fn remove(&self, key: &Key<K>) -> Result<(), MapError> {
        let fd = self.inner.deref().fd_or_err()?;
        bpf_map_delete_elem(fd, &key)
            .map(|_| ())
            .map_err(|(code, io_error)| MapError::SyscallError {
                call: "bpf_map_delete_elem".to_owned(),
                code,
                io_error,
            })
    }
}


impl<T: Deref<Target = Map>, K: Pod, V: Pod> IterableMap<K, V> for LpmTrie<T, K, V> {
    fn map(&self) -> &Map {
        &self.inner
    }

    fn get(&self, key: &K) -> Result<V, MapError> {
        let lookup = Key::new(mem::size_of::<K>() as u32, *key);
        self.get(lookup, 0)
    }
}

impl<K: Pod, V: Pod> TryFrom<MapRef> for LpmTrie<MapRef, K, V> {
    type Error = MapError;

    fn try_from(a: MapRef) -> Result<LpmTrie<MapRef, K, V>, MapError> {
        LpmTrie::new(a)
    }
}

impl<K: Pod, V: Pod> TryFrom<MapRefMut> for LpmTrie<MapRefMut, K, V> {
    type Error = MapError;

    fn try_from(a: MapRefMut) -> Result<LpmTrie<MapRefMut, K, V>, MapError> {
        LpmTrie::new(a)
    }
}

impl<'a, K: Pod, V: Pod> TryFrom<&'a Map> for LpmTrie<&'a Map, K, V> {
    type Error = MapError;

    fn try_from(a: &'a Map) -> Result<LpmTrie<&'a Map, K, V>, MapError> {
        LpmTrie::new(a)
    }
}

impl<'a, K: Pod, V: Pod> TryFrom<&'a mut Map> for LpmTrie<&'a mut Map, K, V> {
    type Error = MapError;

    fn try_from(a: &'a mut Map) -> Result<LpmTrie<&'a mut Map, K, V>, MapError> {
        LpmTrie::new(a)
    }
}
