//! A LPM Trie.
use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::AsFd as _,
};

use crate::{
    maps::{check_kv_size, IterableMap, MapData, MapError, MapIter, MapKeys},
    sys::{bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem, SyscallError},
    Pod,
};

/// A Longest Prefix Match Trie.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.20.
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::maps::lpm_trie::{LpmTrie, Key};
/// use std::net::Ipv4Addr;
///
/// let mut trie = LpmTrie::try_from(bpf.map_mut("LPM_TRIE").unwrap())?;
/// let ipaddr = Ipv4Addr::new(8, 8, 8, 8);
/// // The following represents a key for the "8.8.8.8/16" subnet.
/// // The first argument - the prefix length - represents how many bits should be matched against. The second argument is the actual data to be matched.
/// let key = Key::new(16, u32::from(ipaddr).to_be());
/// trie.insert(&key, 1, 0)?;
///
/// // LpmTrie matches against the longest (most accurate) key.
/// let lookup = Key::new(32, u32::from(ipaddr).to_be());
/// let value = trie.get(&lookup, 0)?;
/// assert_eq!(value, 1);
///
/// // If we were to insert a key with longer 'prefix_len'
/// // our trie should match against it.
/// let longer_key = Key::new(24, u32::from(ipaddr).to_be());
/// trie.insert(&longer_key, 2, 0)?;
/// let value = trie.get(&lookup, 0)?;
/// assert_eq!(value, 2);
/// # Ok::<(), aya::EbpfError>(())
/// ```

#[doc(alias = "BPF_MAP_TYPE_LPM_TRIE")]
#[derive(Debug)]
pub struct LpmTrie<T, K, V> {
    pub(crate) inner: T,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

/// A Key for an LpmTrie map.
///
/// # Examples
///
/// ```no_run
/// use aya::maps::lpm_trie::{LpmTrie, Key};
/// use std::net::Ipv4Addr;
///
/// let ipaddr = Ipv4Addr::new(8,8,8,8);
/// let key =  Key::new(16, u32::from(ipaddr).to_be());
/// ```
#[repr(packed)]
pub struct Key<K: Pod> {
    prefix_len: u32,
    data: K,
}

impl<K: Pod> Key<K> {
    /// Creates a new key.
    ///
    /// `prefix_len` is the number of bits in the data to match against.
    /// `data` is the data in the key which is typically an IPv4 or IPv6 address.
    /// If using a key to perform a longest prefix match on you would use a `prefix_len`
    /// of 32 for IPv4 and 128 for IPv6.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya::maps::lpm_trie::{LpmTrie, Key};
    /// use std::net::Ipv4Addr;
    ///
    /// let ipaddr = Ipv4Addr::new(8, 8, 8, 8);
    /// let key =  Key::new(16, u32::from(ipaddr).to_be());
    /// ```
    pub fn new(prefix_len: u32, data: K) -> Self {
        Self { prefix_len, data }
    }

    /// Returns the number of bits in the data to be matched.
    pub fn prefix_len(&self) -> u32 {
        self.prefix_len
    }

    /// Returns the data stored in the Key.
    pub fn data(&self) -> K {
        self.data
    }
}

impl<K: Pod> Copy for Key<K> {}

impl<K: Pod> Clone for Key<K> {
    fn clone(&self) -> Self {
        *self
    }
}

// A Pod impl is required as Key struct is a key for a map.
unsafe impl<K: Pod> Pod for Key<K> {}

impl<T: Borrow<MapData>, K: Pod, V: Pod> LpmTrie<T, K, V> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<Key<K>, V>(data)?;

        Ok(Self {
            inner: map,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    /// Returns a copy of the value associated with the longest prefix matching key in the LpmTrie.
    pub fn get(&self, key: &Key<K>, flags: u64) -> Result<V, MapError> {
        let fd = self.inner.borrow().fd().as_fd();
        let value = bpf_map_lookup_elem(fd, key, flags).map_err(|(_, io_error)| SyscallError {
            call: "bpf_map_lookup_elem",
            io_error,
        })?;
        value.ok_or(MapError::KeyNotFound)
    }

    /// An iterator visiting all key-value pairs. The
    /// iterator item type is `Result<(K, V), MapError>`.
    pub fn iter(&self) -> MapIter<'_, Key<K>, V, Self> {
        MapIter::new(self)
    }

    /// An iterator visiting all keys. The iterator element
    /// type is `Result<Key<K>, MapError>`.
    pub fn keys(&self) -> MapKeys<'_, Key<K>> {
        MapKeys::new(self.inner.borrow())
    }
}

impl<T: BorrowMut<MapData>, K: Pod, V: Pod> LpmTrie<T, K, V> {
    /// Inserts a key value pair into the map.
    pub fn insert(
        &mut self,
        key: &Key<K>,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), MapError> {
        let fd = self.inner.borrow().fd().as_fd();
        bpf_map_update_elem(fd, Some(key), value.borrow(), flags).map_err(|(_, io_error)| {
            SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            }
        })?;

        Ok(())
    }

    /// Removes an element from the map.
    ///
    /// Both the prefix and data must match exactly - this method does not do a longest prefix match.
    pub fn remove(&mut self, key: &Key<K>) -> Result<(), MapError> {
        let fd = self.inner.borrow().fd().as_fd();
        bpf_map_delete_elem(fd, key)
            .map(|_| ())
            .map_err(|(_, io_error)| {
                SyscallError {
                    call: "bpf_map_delete_elem",
                    io_error,
                }
                .into()
            })
    }
}

impl<T: Borrow<MapData>, K: Pod, V: Pod> IterableMap<Key<K>, V> for LpmTrie<T, K, V> {
    fn map(&self) -> &MapData {
        self.inner.borrow()
    }

    fn get(&self, key: &Key<K>) -> Result<V, MapError> {
        self.get(key, 0)
    }
}

#[cfg(test)]
mod tests {
    use std::{io, net::Ipv4Addr};

    use assert_matches::assert_matches;
    use libc::{EFAULT, ENOENT};

    use super::*;
    use crate::{
        generated::{
            bpf_cmd,
            bpf_map_type::{BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_LPM_TRIE},
        },
        maps::{
            test_utils::{self, new_map},
            Map,
        },
        obj,
        sys::{override_syscall, SysResult, Syscall},
    };

    fn new_obj_map() -> obj::Map {
        test_utils::new_obj_map::<Key<u32>>(BPF_MAP_TYPE_LPM_TRIE)
    }

    fn sys_error(value: i32) -> SysResult<i64> {
        Err((-1, io::Error::from_raw_os_error(value)))
    }

    #[test]
    fn test_wrong_key_size() {
        let map = new_map(new_obj_map());
        assert_matches!(
            LpmTrie::<_, u16, u32>::new(&map),
            Err(MapError::InvalidKeySize {
                size: 6,
                expected: 8 // four bytes for prefixlen and four bytes for data.
            })
        );
    }

    #[test]
    fn test_wrong_value_size() {
        let map = new_map(new_obj_map());
        assert_matches!(
            LpmTrie::<_, u32, u16>::new(&map),
            Err(MapError::InvalidValueSize {
                size: 2,
                expected: 4
            })
        );
    }

    #[test]
    fn test_try_from_wrong_map() {
        let map = new_map(test_utils::new_obj_map::<u32>(BPF_MAP_TYPE_ARRAY));
        let map = Map::Array(map);

        assert_matches!(
            LpmTrie::<_, u32, u32>::try_from(&map),
            Err(MapError::InvalidMapType { .. })
        );
    }

    #[test]
    fn test_new_ok() {
        let map = new_map(new_obj_map());

        assert!(LpmTrie::<_, u32, u32>::new(&map).is_ok());
    }

    #[test]
    fn test_try_from_ok() {
        let map = new_map(new_obj_map());

        let map = Map::LpmTrie(map);
        assert!(LpmTrie::<_, u32, u32>::try_from(&map).is_ok())
    }

    #[test]
    fn test_insert_syscall_error() {
        let mut map = new_map(new_obj_map());
        let mut trie = LpmTrie::<_, u32, u32>::new(&mut map).unwrap();
        let ipaddr = Ipv4Addr::new(8, 8, 8, 8);
        let key = Key::new(16, u32::from(ipaddr).to_be());

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            trie.insert(&key, 1, 0),
            Err(MapError::SyscallError(SyscallError { call: "bpf_map_update_elem", io_error })) if io_error.raw_os_error() == Some(EFAULT)
        );
    }

    #[test]
    fn test_insert_ok() {
        let mut map = new_map(new_obj_map());
        let mut trie = LpmTrie::<_, u32, u32>::new(&mut map).unwrap();
        let ipaddr = Ipv4Addr::new(8, 8, 8, 8);
        let key = Key::new(16, u32::from(ipaddr).to_be());

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_UPDATE_ELEM,
                ..
            } => Ok(1),
            _ => sys_error(EFAULT),
        });

        assert!(trie.insert(&key, 1, 0).is_ok());
    }

    #[test]
    fn test_remove_syscall_error() {
        let mut map = new_map(new_obj_map());
        let mut trie = LpmTrie::<_, u32, u32>::new(&mut map).unwrap();
        let ipaddr = Ipv4Addr::new(8, 8, 8, 8);
        let key = Key::new(16, u32::from(ipaddr).to_be());

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            trie.remove(&key),
            Err(MapError::SyscallError(SyscallError { call: "bpf_map_delete_elem", io_error })) if io_error.raw_os_error() == Some(EFAULT)
        );
    }

    #[test]
    fn test_remove_ok() {
        let mut map = new_map(new_obj_map());
        let mut trie = LpmTrie::<_, u32, u32>::new(&mut map).unwrap();
        let ipaddr = Ipv4Addr::new(8, 8, 8, 8);
        let key = Key::new(16, u32::from(ipaddr).to_be());

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_DELETE_ELEM,
                ..
            } => Ok(1),
            _ => sys_error(EFAULT),
        });

        assert!(trie.remove(&key).is_ok());
    }

    #[test]
    fn test_get_syscall_error() {
        let map = new_map(new_obj_map());
        let trie = LpmTrie::<_, u32, u32>::new(&map).unwrap();
        let ipaddr = Ipv4Addr::new(8, 8, 8, 8);
        let key = Key::new(16, u32::from(ipaddr).to_be());

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            trie.get(&key, 0),
            Err(MapError::SyscallError(SyscallError { call: "bpf_map_lookup_elem", io_error })) if io_error.raw_os_error() == Some(EFAULT)
        );
    }

    #[test]
    fn test_get_not_found() {
        let map = new_map(new_obj_map());
        let trie = LpmTrie::<_, u32, u32>::new(&map).unwrap();
        let ipaddr = Ipv4Addr::new(8, 8, 8, 8);
        let key = Key::new(16, u32::from(ipaddr).to_be());

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                ..
            } => sys_error(ENOENT),
            _ => sys_error(EFAULT),
        });

        assert_matches!(trie.get(&key, 0), Err(MapError::KeyNotFound));
    }
}
