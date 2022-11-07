//! Data structures used to setup and share data with eBPF programs.
//!
//! The eBPF platform provides data structures - maps in eBPF speak - that are
//! used to setup and share data with eBPF programs. When you call
//! [`Bpf::load_file`](crate::Bpf::load_file) or
//! [`Bpf::load`](crate::Bpf::load), all the maps defined in the eBPF code get
//! initialized and can then be accessed using [`Bpf::map`](crate::Bpf::map),
//! [`Bpf::map_mut`](crate::Bpf::map_mut), or [`Bpf::take_map`](crate::Bpf::take_map).
//!
//! # Typed maps
//!
//! The eBPF API includes many map types each supporting different operations.
//! [`Bpf::map`](crate::Bpf::map), [`Bpf::map_mut`](crate::Bpf::map_mut), and
//! [`Bpf::take_map`](crate::Bpf::take_map) always return the
//! opaque [`&Map`](crate::maps::Map), [`&mut Map`](crate::maps::Map), and [`Map`](crate::maps::Map)
//! types respectively. Those three types can be converted to *typed maps* using
//! the [`TryFrom`](std::convert::TryFrom) or [`TryInto`](std::convert::TryInto)
//! trait. For example:
//!
//! ```no_run
//! # let mut bpf = aya::Bpf::load(&[])?;
//! use aya::maps::SockMap;
//! use aya::programs::SkMsg;
//!
//! let intercept_egress = SockMap::try_from(bpf.map_mut("INTERCEPT_EGRESS").unwrap())?;
//! let map_fd = intercept_egress.fd()?;
//! let prog: &mut SkMsg = bpf.program_mut("intercept_egress_packet").unwrap().try_into()?;
//! prog.load()?;
//! prog.attach(map_fd)?;
//!
//! # Ok::<(), aya::BpfError>(())
//! ```
//!
//! # Maps and `Pod` values
//!
//! Many map operations copy data from kernel space to user space and vice
//! versa. Because of that, all map values must be plain old data and therefore
//! implement the [Pod] trait.
use std::{
    convert::{AsMut, AsRef},
    ffi::CString,
    fmt, io,
    marker::PhantomData,
    mem,
    ops::Deref,
    os::unix::{io::RawFd, prelude::AsRawFd},
    path::Path,
    ptr,
};

use libc::{getrlimit, rlimit, RLIMIT_MEMLOCK, RLIM_INFINITY};
use log::warn;
use thiserror::Error;

use crate::{
    generated::bpf_map_type,
    obj::{self, parse_map_info},
    pin::PinError,
    sys::{
        bpf_create_map, bpf_get_object, bpf_map_get_info_by_fd, bpf_map_get_next_key,
        bpf_pin_object, kernel_version,
    },
    util::nr_cpus,
    PinningType, Pod,
};

pub mod array;
pub mod bloom_filter;
pub mod hash_map;
pub mod lpm_trie;
pub mod perf;
pub mod queue;
pub mod sock;
pub mod stack;
pub mod stack_trace;

pub use array::{Array, PerCpuArray, ProgramArray};
pub use bloom_filter::BloomFilter;
pub use hash_map::{HashMap, PerCpuHashMap};
pub use lpm_trie::LpmTrie;
#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
pub use perf::AsyncPerfEventArray;
pub use perf::PerfEventArray;
pub use queue::Queue;
pub use sock::{SockHash, SockMap};
pub use stack::Stack;
pub use stack_trace::StackTraceMap;

#[derive(Error, Debug)]
/// Errors occuring from working with Maps
pub enum MapError {
    /// Invalid map type encontered
    #[error("invalid map type {map_type}")]
    InvalidMapType {
        /// The map type
        map_type: u32,
    },

    /// Invalid map name encountered
    #[error("invalid map name `{name}`")]
    InvalidName {
        /// The map name
        name: String,
    },

    /// The map has not been created
    #[error("the map has not been created")]
    NotCreated,

    /// The map has already been created
    #[error("the map `{name}` has already been created")]
    AlreadyCreated {
        /// Map name
        name: String,
    },

    /// Failed to create map
    #[error("failed to create map `{name}` with code {code}")]
    CreateError {
        /// Map name
        name: String,
        /// Error code
        code: libc::c_long,
        #[source]
        /// Original io::Error
        io_error: io::Error,
    },

    /// Invalid key size
    #[error("invalid key size {size}, expected {expected}")]
    InvalidKeySize {
        /// Size encountered
        size: usize,
        /// Size expected
        expected: usize,
    },

    /// Invalid value size
    #[error("invalid value size {size}, expected {expected}")]
    InvalidValueSize {
        /// Size encountered
        size: usize,
        /// Size expected
        expected: usize,
    },

    /// Index is out of bounds
    #[error("the index is {index} but `max_entries` is {max_entries}")]
    OutOfBounds {
        /// Index accessed
        index: u32,
        /// Map size
        max_entries: u32,
    },

    /// Key not found
    #[error("key not found")]
    KeyNotFound,

    /// Element not found
    #[error("element not found")]
    ElementNotFound,

    /// Progam Not Loaded
    #[error("the program is not loaded")]
    ProgramNotLoaded,

    /// Syscall failed
    #[error("the `{call}` syscall failed")]
    SyscallError {
        /// Syscall Name
        call: String,
        /// Original io::Error
        io_error: io::Error,
    },

    /// Could not pin map by name
    #[error("map `{name:?}` requested pinning by name. pinning failed")]
    PinError {
        /// The map name
        name: Option<String>,
        /// The reason for the failure
        #[source]
        error: PinError,
    },
}

/// A map file descriptor.
pub struct MapFd(RawFd);

impl AsRawFd for MapFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct RlimitSize(usize);
impl fmt::Display for RlimitSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 < 1024 {
            write!(f, "{} bytes", self.0)
        } else if self.0 < 1024 * 1024 {
            write!(f, "{} KiB", self.0 / 1024)
        } else {
            write!(f, "{} MiB", self.0 / 1024 / 1024)
        }
    }
}

/// Raises a warning about rlimit. Should be used only if creating a map was not
/// successful.
fn maybe_warn_rlimit() {
    let mut limit = std::mem::MaybeUninit::<rlimit>::uninit();
    let ret = unsafe { getrlimit(RLIMIT_MEMLOCK, limit.as_mut_ptr()) };
    if ret == 0 {
        let limit = unsafe { limit.assume_init() };

        let limit: RlimitSize = RlimitSize(limit.rlim_cur.try_into().unwrap());
        if limit.0 == RLIM_INFINITY.try_into().unwrap() {
            return;
        }
        warn!(
            "RLIMIT_MEMLOCK value is {}, not RLIM_INFNITY; if experiencing problems with creating \
            maps, try raising RMILIT_MEMLOCK either to RLIM_INFINITY or to a higher value sufficient \
            for size of your maps",
            limit
        );
    }
}

/// eBPF map types.
#[derive(Debug)]
pub enum Map {
    /// A [`Array`] map
    Array(MapData),
    /// A [`PerCpuArray`] map
    PerCpuArray(MapData),
    /// A [`ProgramArray`] map
    ProgramArray(MapData),
    /// A [`HashMap`] map
    HashMap(MapData),
    /// A [`PerCpuHashMap`] map
    PerCpuHashMap(MapData),
    /// A [`PerfEventArray`] map
    PerfEventArray(MapData),
    /// A [`SockMap`] map
    SockMap(MapData),
    /// A [`SockHash`] map
    SockHash(MapData),
    /// A [`BloomFilter`] map
    BloomFilter(MapData),
    /// A [`LpmTrie`] map
    LpmTrie(MapData),
    /// A [`Stack`] map
    Stack(MapData),
    /// A [`StackTraceMap`] map
    StackTraceMap(MapData),
    /// A [`Queue`] map
    Queue(MapData),
}

impl Map {
    /// Returns the low level map type.
    fn map_type(&self) -> u32 {
        match self {
            Map::Array(map) => map.obj.map_type(),
            Map::PerCpuArray(map) => map.obj.map_type(),
            Map::ProgramArray(map) => map.obj.map_type(),
            Map::HashMap(map) => map.obj.map_type(),
            Map::PerCpuHashMap(map) => map.obj.map_type(),
            Map::PerfEventArray(map) => map.obj.map_type(),
            Map::SockHash(map) => map.obj.map_type(),
            Map::SockMap(map) => map.obj.map_type(),
            Map::BloomFilter(map) => map.obj.map_type(),
            Map::LpmTrie(map) => map.obj.map_type(),
            Map::Stack(map) => map.obj.map_type(),
            Map::StackTraceMap(map) => map.obj.map_type(),
            Map::Queue(map) => map.obj.map_type(),
        }
    }
}

macro_rules! impl_try_from_map {
    ($($tx:ident from Map::$ty:ident),+ $(,)?) => {
        $(
            impl<'a> TryFrom<&'a Map> for $tx<&'a MapData> {
                type Error = MapError;

                fn try_from(map: &'a Map) -> Result<$tx<&'a MapData>, MapError> {
                    match map {
                        Map::$ty(m) => {
                            $tx::new(m)
                        },
                        _ => Err(MapError::InvalidMapType{ map_type: map.map_type()}),
                    }
                }
            }

            impl<'a,> TryFrom<&'a mut Map> for $tx<&'a mut MapData> {
                type Error = MapError;

                fn try_from(map: &'a mut Map) -> Result<$tx<&'a mut MapData>, MapError> {
                    match map {
                        Map::$ty(m) => {
                            $tx::new(m)
                        },
                        _ => Err(MapError::InvalidMapType{ map_type: map.map_type()}),
                    }
                }
            }

            impl TryFrom<Map> for $tx<MapData> {
                type Error = MapError;

                fn try_from(map: Map) -> Result<$tx<MapData>, MapError> {
                    match map {
                        Map::$ty(m) => {
                            $tx::new(m)
                        },
                        _ => Err(MapError::InvalidMapType{ map_type: map.map_type()}),
                    }
                }
            }
       )+
   }
}

impl_try_from_map!(
    ProgramArray from Map::ProgramArray,
    SockMap from Map::SockMap,
    PerfEventArray from Map::PerfEventArray,
    StackTraceMap from Map::StackTraceMap,
);

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
impl_try_from_map!(
    AsyncPerfEventArray from Map::PerfEventArray,
);

macro_rules! impl_try_from_map_generic_key_or_value {
    ($($ty:ident),+ $(,)?) => {
        $(
            impl<'a, V:Pod> TryFrom<&'a Map> for $ty<&'a MapData, V> {
                type Error = MapError;

                fn try_from(map: &'a Map) -> Result<$ty<&'a MapData , V>, MapError> {
                    match map {
                        Map::$ty(m) => {
                            $ty::new(m)
                        },
                        _ => Err(MapError::InvalidMapType{ map_type: map.map_type()}),
                    }
                }
            }

            impl<'a,V: Pod> TryFrom<&'a mut Map> for $ty<&'a mut MapData, V> {
                type Error = MapError;

                fn try_from(map: &'a mut Map) -> Result<$ty<&'a mut MapData, V>, MapError> {
                    match map {
                        Map::$ty(m) => {
                            $ty::new(m)
                        },
                        _ => Err(MapError::InvalidMapType{ map_type: map.map_type()}),
                    }
                }
            }

            impl<V: Pod> TryFrom<Map> for $ty<MapData, V> {
                type Error = MapError;

                fn try_from(map: Map) -> Result<$ty<MapData, V>, MapError> {
                    match map {
                        Map::$ty(m) => {
                            $ty::new(m)
                        },
                        _ => Err(MapError::InvalidMapType{ map_type: map.map_type()}),
                    }
                }
            }
       )+
   }
}

impl_try_from_map_generic_key_or_value!(Array, PerCpuArray, SockHash, BloomFilter, Queue, Stack,);

macro_rules! impl_try_from_map_generic_key_and_value {
    ($($ty:ident),+ $(,)?) => {
        $(
            impl<'a, V: Pod, K: Pod> TryFrom<&'a Map> for $ty<&'a MapData, V, K> {
                type Error = MapError;

                fn try_from(map: &'a Map) -> Result<$ty<&'a MapData,V,K>, MapError> {
                    match map {
                        Map::$ty(m) => {
                            $ty::new(m)
                        },
                        _ => Err(MapError::InvalidMapType{ map_type: map.map_type()}),
                    }
                }
            }

            impl<'a,V: Pod,K: Pod> TryFrom<&'a mut Map> for $ty<&'a mut MapData, V, K> {
                type Error = MapError;

                fn try_from(map: &'a mut Map) -> Result<$ty<&'a mut MapData, V, K>, MapError> {
                    match map {
                        Map::$ty(m) => {
                            $ty::new(m)
                        },
                        _ => Err(MapError::InvalidMapType{ map_type: map.map_type()}),
                }
            }
            }
       )+
   }
}

impl_try_from_map_generic_key_and_value!(HashMap, PerCpuHashMap, LpmTrie);

pub(crate) fn check_bounds(map: &MapData, index: u32) -> Result<(), MapError> {
    let max_entries = map.obj.max_entries();
    if index >= max_entries {
        Err(MapError::OutOfBounds { index, max_entries })
    } else {
        Ok(())
    }
}

pub(crate) fn check_kv_size<K, V>(map: &MapData) -> Result<(), MapError> {
    let size = mem::size_of::<K>();
    let expected = map.obj.key_size() as usize;
    if size != expected {
        return Err(MapError::InvalidKeySize { size, expected });
    }
    let size = mem::size_of::<V>();
    let expected = map.obj.value_size() as usize;
    if size != expected {
        return Err(MapError::InvalidValueSize { size, expected });
    };
    Ok(())
}

pub(crate) fn check_v_size<V>(map: &MapData) -> Result<(), MapError> {
    let size = mem::size_of::<V>();
    let expected = map.obj.value_size() as usize;
    if size != expected {
        return Err(MapError::InvalidValueSize { size, expected });
    };
    Ok(())
}

/// A generic handle to a BPF map.
///
/// You should never need to use this unless you're implementing a new map type.
#[derive(Debug)]
pub struct MapData {
    pub(crate) obj: obj::Map,
    pub(crate) fd: Option<RawFd>,
    pub(crate) btf_fd: Option<RawFd>,
    /// Indicates if this map has been pinned to bpffs
    pub pinned: bool,
}

impl AsRef<MapData> for MapData {
    fn as_ref(&self) -> &MapData {
        self
    }
}

impl AsMut<MapData> for MapData {
    fn as_mut(&mut self) -> &mut MapData {
        self
    }
}

impl MapData {
    /// Creates a new map with the provided `name`
    pub fn create(&mut self, name: &str) -> Result<RawFd, MapError> {
        if self.fd.is_some() {
            return Err(MapError::AlreadyCreated { name: name.into() });
        }

        let c_name = CString::new(name).map_err(|_| MapError::InvalidName { name: name.into() })?;

        let fd = bpf_create_map(&c_name, &self.obj, self.btf_fd).map_err(|(code, io_error)| {
            let k_ver = kernel_version().unwrap();
            if k_ver < (5, 11, 0) {
                maybe_warn_rlimit();
            }

            MapError::CreateError {
                name: name.into(),
                code,
                io_error,
            }
        })? as RawFd;

        self.fd = Some(fd);

        Ok(fd)
    }

    pub(crate) fn open_pinned<P: AsRef<Path>>(
        &mut self,
        name: &str,
        path: P,
    ) -> Result<RawFd, MapError> {
        if self.fd.is_some() {
            return Err(MapError::AlreadyCreated { name: name.into() });
        }
        let map_path = path.as_ref().join(name);
        let path_string = CString::new(map_path.to_str().unwrap()).unwrap();
        let fd = bpf_get_object(&path_string).map_err(|(_, io_error)| MapError::SyscallError {
            call: "BPF_OBJ_GET".to_string(),
            io_error,
        })? as RawFd;

        self.fd = Some(fd);

        Ok(fd)
    }

    /// Loads a map from a pinned path in bpffs.
    pub fn from_pin<P: AsRef<Path>>(path: P) -> Result<MapData, MapError> {
        let path_string =
            CString::new(path.as_ref().to_string_lossy().into_owned()).map_err(|e| {
                MapError::PinError {
                    name: None,
                    error: PinError::InvalidPinPath {
                        error: e.to_string(),
                    },
                }
            })?;

        let fd = bpf_get_object(&path_string).map_err(|(_, io_error)| MapError::SyscallError {
            call: "BPF_OBJ_GET".to_owned(),
            io_error,
        })? as RawFd;

        let info = bpf_map_get_info_by_fd(fd).map_err(|io_error| MapError::SyscallError {
            call: "BPF_MAP_GET_INFO_BY_FD".to_owned(),
            io_error,
        })?;

        Ok(MapData {
            obj: parse_map_info(info, PinningType::ByName),
            fd: Some(fd),
            btf_fd: None,
            pinned: true,
        })
    }

    /// Loads a map from a [`RawFd`].
    ///
    /// If loading from a BPF Filesystem (bpffs) you should use [`Map::from_pin`](crate::maps::MapData::from_pin).
    /// This API is intended for cases where you have received a valid BPF FD from some other means.
    /// For example, you received an FD over Unix Domain Socket.
    pub fn from_fd(fd: RawFd) -> Result<MapData, MapError> {
        let info = bpf_map_get_info_by_fd(fd).map_err(|io_error| MapError::SyscallError {
            call: "BPF_OBJ_GET".to_owned(),
            io_error,
        })?;

        Ok(MapData {
            obj: parse_map_info(info, PinningType::None),
            fd: Some(fd),
            btf_fd: None,
            pinned: false,
        })
    }

    pub(crate) fn fd_or_err(&self) -> Result<RawFd, MapError> {
        self.fd.ok_or(MapError::NotCreated)
    }

    pub(crate) fn pin<P: AsRef<Path>>(&mut self, name: &str, path: P) -> Result<(), PinError> {
        if self.pinned {
            return Err(PinError::AlreadyPinned { name: name.into() });
        }
        let map_path = path.as_ref().join(name);
        let fd = self.fd.ok_or(PinError::NoFd {
            name: name.to_string(),
        })?;
        let path_string = CString::new(map_path.to_string_lossy().into_owned()).map_err(|e| {
            PinError::InvalidPinPath {
                error: e.to_string(),
            }
        })?;
        bpf_pin_object(fd, &path_string).map_err(|(_, io_error)| PinError::SyscallError {
            name: "BPF_OBJ_PIN".to_string(),
            io_error,
        })?;
        self.pinned = true;
        Ok(())
    }

    /// Returns the file descriptor of the map.
    ///
    /// Can be converted to [`RawFd`] using [`AsRawFd`].
    pub fn fd(&self) -> Option<MapFd> {
        self.fd.map(MapFd)
    }
}

impl Drop for MapData {
    fn drop(&mut self) {
        // TODO: Replace this with an OwnedFd once that is stabilized.
        if let Some(fd) = self.fd.take() {
            unsafe { libc::close(fd) };
        }
    }
}

impl Clone for MapData {
    fn clone(&self) -> MapData {
        MapData {
            obj: self.obj.clone(),
            fd: {
                if let Some(fd) = self.fd {
                    unsafe { Some(libc::dup(fd)) };
                }
                None
            },
            btf_fd: self.btf_fd,
            pinned: self.pinned,
        }
    }
}

/// An iterable map
pub trait IterableMap<K: Pod, V> {
    /// Get a generic map handle
    fn map(&self) -> &MapData;

    /// Get the value for the provided `key`
    fn get(&self, key: &K) -> Result<V, MapError>;
}

/// Iterator returned by `map.keys()`.
pub struct MapKeys<'coll, K: Pod> {
    map: &'coll MapData,
    err: bool,
    key: Option<K>,
}

impl<'coll, K: Pod> MapKeys<'coll, K> {
    fn new(map: &'coll MapData) -> MapKeys<'coll, K> {
        MapKeys {
            map,
            err: false,
            key: None,
        }
    }
}

impl<K: Pod> Iterator for MapKeys<'_, K> {
    type Item = Result<K, MapError>;

    fn next(&mut self) -> Option<Result<K, MapError>> {
        if self.err {
            return None;
        }

        let fd = match self.map.fd_or_err() {
            Ok(fd) => fd,
            Err(e) => {
                self.err = true;
                return Some(Err(e));
            }
        };

        match bpf_map_get_next_key(fd, self.key.as_ref()) {
            Ok(Some(key)) => {
                self.key = Some(key);
                Some(Ok(key))
            }
            Ok(None) => {
                self.key = None;
                None
            }
            Err((_, io_error)) => {
                self.err = true;
                Some(Err(MapError::SyscallError {
                    call: "bpf_map_get_next_key".to_owned(),
                    io_error,
                }))
            }
        }
    }
}

/// Iterator returned by `map.iter()`.
pub struct MapIter<'coll, K: Pod, V, I: IterableMap<K, V>> {
    keys: MapKeys<'coll, K>,
    map: &'coll I,
    _v: PhantomData<V>,
}

impl<'coll, K: Pod, V, I: IterableMap<K, V>> MapIter<'coll, K, V, I> {
    fn new(map: &'coll I) -> MapIter<'coll, K, V, I> {
        MapIter {
            keys: MapKeys::new(map.map()),
            map,
            _v: PhantomData,
        }
    }
}

impl<K: Pod, V, I: IterableMap<K, V>> Iterator for MapIter<'_, K, V, I> {
    type Item = Result<(K, V), MapError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.keys.next() {
                Some(Ok(key)) => match self.map.get(&key) {
                    Ok(value) => return Some(Ok((key, value))),
                    Err(MapError::KeyNotFound) => continue,
                    Err(e) => return Some(Err(e)),
                },
                Some(Err(e)) => return Some(Err(e)),
                None => return None,
            }
        }
    }
}

impl TryFrom<u32> for bpf_map_type {
    type Error = MapError;

    fn try_from(map_type: u32) -> Result<Self, Self::Error> {
        use bpf_map_type::*;
        Ok(match map_type {
            x if x == BPF_MAP_TYPE_UNSPEC as u32 => BPF_MAP_TYPE_UNSPEC,
            x if x == BPF_MAP_TYPE_HASH as u32 => BPF_MAP_TYPE_HASH,
            x if x == BPF_MAP_TYPE_ARRAY as u32 => BPF_MAP_TYPE_ARRAY,
            x if x == BPF_MAP_TYPE_PROG_ARRAY as u32 => BPF_MAP_TYPE_PROG_ARRAY,
            x if x == BPF_MAP_TYPE_PERF_EVENT_ARRAY as u32 => BPF_MAP_TYPE_PERF_EVENT_ARRAY,
            x if x == BPF_MAP_TYPE_PERCPU_HASH as u32 => BPF_MAP_TYPE_PERCPU_HASH,
            x if x == BPF_MAP_TYPE_PERCPU_ARRAY as u32 => BPF_MAP_TYPE_PERCPU_ARRAY,
            x if x == BPF_MAP_TYPE_STACK_TRACE as u32 => BPF_MAP_TYPE_STACK_TRACE,
            x if x == BPF_MAP_TYPE_CGROUP_ARRAY as u32 => BPF_MAP_TYPE_CGROUP_ARRAY,
            x if x == BPF_MAP_TYPE_LRU_HASH as u32 => BPF_MAP_TYPE_LRU_HASH,
            x if x == BPF_MAP_TYPE_LRU_PERCPU_HASH as u32 => BPF_MAP_TYPE_LRU_PERCPU_HASH,
            x if x == BPF_MAP_TYPE_LPM_TRIE as u32 => BPF_MAP_TYPE_LPM_TRIE,
            x if x == BPF_MAP_TYPE_BLOOM_FILTER as u32 => BPF_MAP_TYPE_BLOOM_FILTER,
            x if x == BPF_MAP_TYPE_ARRAY_OF_MAPS as u32 => BPF_MAP_TYPE_ARRAY_OF_MAPS,
            x if x == BPF_MAP_TYPE_HASH_OF_MAPS as u32 => BPF_MAP_TYPE_HASH_OF_MAPS,
            x if x == BPF_MAP_TYPE_DEVMAP as u32 => BPF_MAP_TYPE_DEVMAP,
            x if x == BPF_MAP_TYPE_SOCKMAP as u32 => BPF_MAP_TYPE_SOCKMAP,
            x if x == BPF_MAP_TYPE_CPUMAP as u32 => BPF_MAP_TYPE_CPUMAP,
            x if x == BPF_MAP_TYPE_XSKMAP as u32 => BPF_MAP_TYPE_XSKMAP,
            x if x == BPF_MAP_TYPE_SOCKHASH as u32 => BPF_MAP_TYPE_SOCKHASH,
            x if x == BPF_MAP_TYPE_CGROUP_STORAGE as u32 => BPF_MAP_TYPE_CGROUP_STORAGE,
            x if x == BPF_MAP_TYPE_REUSEPORT_SOCKARRAY as u32 => BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
            x if x == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE as u32 => {
                BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
            }
            x if x == BPF_MAP_TYPE_QUEUE as u32 => BPF_MAP_TYPE_QUEUE,
            x if x == BPF_MAP_TYPE_STACK as u32 => BPF_MAP_TYPE_STACK,
            x if x == BPF_MAP_TYPE_SK_STORAGE as u32 => BPF_MAP_TYPE_SK_STORAGE,
            x if x == BPF_MAP_TYPE_DEVMAP_HASH as u32 => BPF_MAP_TYPE_DEVMAP_HASH,
            x if x == BPF_MAP_TYPE_STRUCT_OPS as u32 => BPF_MAP_TYPE_STRUCT_OPS,
            x if x == BPF_MAP_TYPE_RINGBUF as u32 => BPF_MAP_TYPE_RINGBUF,
            x if x == BPF_MAP_TYPE_INODE_STORAGE as u32 => BPF_MAP_TYPE_INODE_STORAGE,
            x if x == BPF_MAP_TYPE_TASK_STORAGE as u32 => BPF_MAP_TYPE_TASK_STORAGE,
            _ => return Err(MapError::InvalidMapType { map_type }),
        })
    }
}

pub(crate) struct PerCpuKernelMem {
    bytes: Vec<u8>,
}

impl PerCpuKernelMem {
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }
}

/// A slice of per-CPU values.
///
/// Used by maps that implement per-CPU storage like [`PerCpuHashMap`].
///
/// # Examples
///
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
/// # let bpf = aya::Bpf::load(&[])?;
/// use aya::maps::PerCpuValues;
/// use aya::util::nr_cpus;
///
/// let values = PerCpuValues::try_from(vec![42u32; nr_cpus()?])?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
pub struct PerCpuValues<T: Pod> {
    values: Box<[T]>,
}

impl<T: Pod> TryFrom<Vec<T>> for PerCpuValues<T> {
    type Error = io::Error;

    fn try_from(values: Vec<T>) -> Result<Self, Self::Error> {
        let nr_cpus = nr_cpus()?;
        if values.len() != nr_cpus {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("not enough values ({}), nr_cpus: {}", values.len(), nr_cpus),
            ));
        }
        Ok(PerCpuValues {
            values: values.into_boxed_slice(),
        })
    }
}

impl<T: Pod> PerCpuValues<T> {
    pub(crate) fn alloc_kernel_mem() -> Result<PerCpuKernelMem, io::Error> {
        let value_size = (mem::size_of::<T>() + 7) & !7;
        Ok(PerCpuKernelMem {
            bytes: vec![0u8; nr_cpus()? * value_size],
        })
    }

    pub(crate) unsafe fn from_kernel_mem(mem: PerCpuKernelMem) -> PerCpuValues<T> {
        let mem_ptr = mem.bytes.as_ptr() as usize;
        let value_size = (mem::size_of::<T>() + 7) & !7;
        let mut values = Vec::new();
        let mut offset = 0;
        while offset < mem.bytes.len() {
            values.push(ptr::read_unaligned((mem_ptr + offset) as *const _));
            offset += value_size;
        }

        PerCpuValues {
            values: values.into_boxed_slice(),
        }
    }

    pub(crate) fn build_kernel_mem(&self) -> Result<PerCpuKernelMem, io::Error> {
        let mut mem = PerCpuValues::<T>::alloc_kernel_mem()?;
        let mem_ptr = mem.as_mut_ptr() as usize;
        let value_size = (mem::size_of::<T>() + 7) & !7;
        for i in 0..self.values.len() {
            unsafe { ptr::write_unaligned((mem_ptr + i * value_size) as *mut _, self.values[i]) };
        }

        Ok(mem)
    }
}

impl<T: Pod> Deref for PerCpuValues<T> {
    type Target = Box<[T]>;

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

#[cfg(test)]
mod tests {
    use libc::EFAULT;

    use crate::{
        bpf_map_def,
        generated::{bpf_cmd, bpf_map_type::BPF_MAP_TYPE_HASH},
        maps::MapData,
        obj::MapKind,
        sys::{override_syscall, Syscall},
    };

    use super::*;

    fn new_obj_map() -> obj::Map {
        obj::Map::Legacy(obj::LegacyMap {
            def: bpf_map_def {
                map_type: BPF_MAP_TYPE_HASH as u32,
                key_size: 4,
                value_size: 4,
                max_entries: 1024,
                ..Default::default()
            },
            section_index: 0,
            symbol_index: 0,
            data: Vec::new(),
            kind: MapKind::Other,
        })
    }

    fn new_map() -> MapData {
        MapData {
            obj: new_obj_map(),
            fd: None,
            pinned: false,
            btf_fd: None,
        }
    }

    #[test]
    fn test_create() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_CREATE,
                ..
            } => Ok(42),
            _ => Err((-1, io::Error::from_raw_os_error(EFAULT))),
        });

        let mut map = new_map();
        assert!(matches!(map.create("foo"), Ok(42)));
        assert_eq!(map.fd, Some(42));
        assert!(matches!(
            map.create("foo"),
            Err(MapError::AlreadyCreated { .. })
        ));
    }

    #[test]
    fn test_create_failed() {
        override_syscall(|_| Err((-42, io::Error::from_raw_os_error(EFAULT))));

        let mut map = new_map();
        let ret = map.create("foo");
        assert!(matches!(ret, Err(MapError::CreateError { .. })));
        if let Err(MapError::CreateError {
            name,
            code,
            io_error,
        }) = ret
        {
            assert_eq!(name, "foo");
            assert_eq!(code, -42);
            assert_eq!(io_error.raw_os_error(), Some(EFAULT));
        }
        assert_eq!(map.fd, None);
    }
}
