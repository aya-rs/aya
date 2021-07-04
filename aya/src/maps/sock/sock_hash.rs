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

/// A hash map of TCP or UDP sockets.
///
/// A `SockHash` is used to store TCP or UDP sockets. eBPF programs can then be
/// attached to the map to inspect, filter or redirect network buffers on those
/// sockets.
///
/// A `SockHash` can also be used to redirect packets to sockets contained by the
/// map using `bpf_redirect_map()`, `bpf_sk_redirect_hash()` etc.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.18.
///
/// # Examples
///
/// ```no_run
/// # #[derive(Debug, thiserror::Error)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     IO(#[from] std::io::Error),
/// #     #[error(transparent)]
/// #     Map(#[from] aya::maps::MapError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let mut bpf = aya::Bpf::load(&[], None)?;
/// use std::convert::{TryFrom, TryInto};
/// use std::io::Write;
/// use std::net::TcpStream;
/// use std::os::unix::io::AsRawFd;
/// use aya::maps::SockHash;
/// use aya::programs::SkMsg;
///
/// let mut intercept_egress = SockHash::try_from(bpf.map_mut("INTERCEPT_EGRESS")?)?;
/// let prog: &mut SkMsg = bpf.program_mut("intercept_egress_packet")?.try_into()?;
/// prog.load()?;
/// prog.attach(&intercept_egress)?;
///
/// let mut client = TcpStream::connect("127.0.0.1:1234")?;
/// intercept_egress.insert(1234, client.as_raw_fd(), 0)?;
///
/// // the write will be intercepted
/// client.write_all(b"foo")?;
/// # Ok::<(), Error>(())
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
            });
        }
        hash_map::check_kv_size::<K, u32>(&map)?;
        let _ = map.fd_or_err()?;

        Ok(SockHash {
            inner: map,
            _k: PhantomData,
        })
    }

    /// Returns the fd of the socket stored at the given key.
    pub unsafe fn get(&self, key: &K, flags: u64) -> Result<RawFd, MapError> {
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
    pub unsafe fn iter(&self) -> MapIter<'_, K, RawFd> {
        MapIter::new(self)
    }

    /// An iterator visiting all keys in arbitrary order. The iterator element
    /// type is `Result<K, MapError>`.
    pub unsafe fn keys(&self) -> MapKeys<'_, K> {
        MapKeys::new(&self.inner)
    }
}

impl<T: DerefMut<Target = Map>, K: Pod> SockHash<T, K> {
    /// Inserts a socket under the given key.
    pub fn insert<I: AsRawFd>(&mut self, key: K, value: I, flags: u64) -> Result<(), MapError> {
        hash_map::insert(&mut self.inner, key, value.as_raw_fd(), flags)
    }

    /// Removes a socket from the map.
    pub fn remove(&mut self, key: &K) -> Result<(), MapError> {
        hash_map::remove(&mut self.inner, key)
    }
}

impl<T: Deref<Target = Map>, K: Pod> IterableMap<K, RawFd> for SockHash<T, K> {
    fn map(&self) -> &Map {
        &self.inner
    }

    unsafe fn get(&self, key: &K) -> Result<RawFd, MapError> {
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
