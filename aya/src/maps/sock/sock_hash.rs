use std::{
    convert::{AsMut, AsRef},
    marker::PhantomData,
    os::unix::io::{AsRawFd, RawFd},
};

use crate::{
    maps::{
        check_kv_size, hash_map, sock::SockMapFd, IterableMap, MapData, MapError, MapIter, MapKeys,
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
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use std::io::Write;
/// use std::net::TcpStream;
/// use std::os::unix::io::AsRawFd;
/// use aya::maps::SockHash;
/// use aya::programs::SkMsg;
///
/// let mut intercept_egress = SockHash::<_, u32>::try_from(bpf.map("INTERCEPT_EGRESS").unwrap())?;
/// let map_fd = intercept_egress.fd()?;
///
/// let prog: &mut SkMsg = bpf.program_mut("intercept_egress_packet").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(map_fd)?;
///
/// let mut client = TcpStream::connect("127.0.0.1:1234")?;
/// let mut intercept_egress = SockHash::try_from(bpf.map_mut("INTERCEPT_EGRESS").unwrap())?;
///
/// intercept_egress.insert(1234, client.as_raw_fd(), 0)?;
///
/// // the write will be intercepted
/// client.write_all(b"foo")?;
/// # Ok::<(), Error>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_SOCKHASH")]
pub struct SockHash<T, K> {
    inner: T,
    _k: PhantomData<K>,
}

impl<T: AsRef<MapData>, K: Pod> SockHash<T, K> {
    pub(crate) fn new(map: T) -> Result<SockHash<T, K>, MapError> {
        let data = map.as_ref();
        check_kv_size::<K, u32>(data)?;
        let _ = data.fd_or_err()?;

        Ok(SockHash {
            inner: map,
            _k: PhantomData,
        })
    }

    /// Returns the fd of the socket stored at the given key.
    pub fn get(&self, key: &K, flags: u64) -> Result<RawFd, MapError> {
        let fd = self.inner.as_ref().fd_or_err()?;
        let value = bpf_map_lookup_elem(fd, key, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                io_error,
            }
        })?;
        value.ok_or(MapError::KeyNotFound)
    }

    /// An iterator visiting all key-value pairs in arbitrary order. The
    /// iterator item type is `Result<(K, V), MapError>`.
    pub fn iter(&self) -> MapIter<'_, K, RawFd, Self> {
        MapIter::new(self)
    }

    /// An iterator visiting all keys in arbitrary order. The iterator element
    /// type is `Result<K, MapError>`.
    pub fn keys(&self) -> MapKeys<'_, K> {
        MapKeys::new(self.inner.as_ref())
    }

    /// Returns the map's file descriptor.
    ///
    /// The returned file descriptor can be used to attach programs that work with
    /// socket maps, like [`SkMsg`](crate::programs::SkMsg) and [`SkSkb`](crate::programs::SkSkb).
    pub fn fd(&self) -> Result<SockMapFd, MapError> {
        Ok(SockMapFd(self.inner.as_ref().fd_or_err()?))
    }
}

impl<T: AsMut<MapData>, K: Pod> SockHash<T, K> {
    /// Inserts a socket under the given key.
    pub fn insert<I: AsRawFd>(&mut self, key: K, value: I, flags: u64) -> Result<(), MapError> {
        hash_map::insert(self.inner.as_mut(), key, value.as_raw_fd(), flags)
    }

    /// Removes a socket from the map.
    pub fn remove(&mut self, key: &K) -> Result<(), MapError> {
        hash_map::remove(self.inner.as_mut(), key)
    }
}

impl<T: AsRef<MapData>, K: Pod> IterableMap<K, RawFd> for SockHash<T, K> {
    fn map(&self) -> &MapData {
        self.inner.as_ref()
    }

    fn get(&self, key: &K) -> Result<RawFd, MapError> {
        SockHash::get(self, key, 0)
    }
}
