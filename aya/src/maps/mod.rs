//! Data structures used to setup and share data with eBPF programs.
//!
//! The eBPF platform provides data structures - maps in eBPF speak - that are
//! used to setup and share data with eBPF programs. When you call
//! [`Bpf::load_file`](crate::Bpf::load_file) or
//! [`Bpf::load`](crate::Bpf::load), all the maps defined in the eBPF code get
//! initialized and can then be accessed using [`Bpf::map`](crate::Bpf::map),
//! [`Bpf::map_mut`](crate::Bpf::map_mut), or
//! [`Bpf::take_map`](crate::Bpf::take_map).
//!
//! # Typed maps
//!
//! The eBPF API includes many map types each supporting different operations.
//! [`Bpf::map`](crate::Bpf::map), [`Bpf::map_mut`](crate::Bpf::map_mut), and
//! [`Bpf::take_map`](crate::Bpf::take_map) always return the opaque
//! [`&Map`](crate::maps::Map), [`&mut Map`](crate::maps::Map), and [`Map`]
//! types respectively. Those three types can be converted to *typed maps* using
//! the [`TryFrom`] or [`TryInto`] trait. For example:
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
    ffi::CString,
    fmt, io,
    marker::PhantomData,
    mem,
    ops::Deref,
    os::fd::{AsFd as _, AsRawFd, BorrowedFd, IntoRawFd as _, OwnedFd, RawFd},
    path::Path,
    ptr,
};

use crate::util::KernelVersion;
use libc::{getrlimit, rlimit, RLIMIT_MEMLOCK, RLIM_INFINITY};
use log::warn;
use obj::maps::InvalidMapTypeError;
use thiserror::Error;

use crate::{
    obj::{self, parse_map_info},
    pin::PinError,
    sys::{
        bpf_create_map, bpf_get_object, bpf_map_get_info_by_fd, bpf_map_get_next_key,
        bpf_pin_object, SyscallError,
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
#[cfg(any(feature = "async_tokio", feature = "async_std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "async_tokio", feature = "async_std"))))]
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
    #[error(transparent)]
    SyscallError(#[from] SyscallError),

    /// Could not pin map by name
    #[error("map `{name:?}` requested pinning by name. pinning failed")]
    PinError {
        /// The map name
        name: Option<String>,
        /// The reason for the failure
        #[source]
        error: PinError,
    },

    /// Unsupported Map type
    #[error("Unsupported map type found {map_type}")]
    Unsupported {
        /// The map type
        map_type: u32,
    },
}

// Note that this is not just derived using #[from] because InvalidMapTypeError cannot implement
// Error due the the fact that aya-obj is nostd and error_in_core is not stabilized
// (https://github.com/rust-lang/rust/issues/103765).
impl From<InvalidMapTypeError> for MapError {
    fn from(e: InvalidMapTypeError) -> Self {
        let InvalidMapTypeError { map_type } = e;
        MapError::InvalidMapType { map_type }
    }
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
    /// A [`HashMap`] map that uses a LRU eviction policy.
    LruHashMap(MapData),
    /// A [`PerCpuHashMap`] map that uses a LRU eviction policy.
    PerCpuLruHashMap(MapData),
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
    /// An unsupported map type
    Unsupported(MapData),
}

impl Map {
    /// Returns the low level map type.
    fn map_type(&self) -> u32 {
        match self {
            Self::Array(map) => map.obj.map_type(),
            Self::PerCpuArray(map) => map.obj.map_type(),
            Self::ProgramArray(map) => map.obj.map_type(),
            Self::HashMap(map) => map.obj.map_type(),
            Self::LruHashMap(map) => map.obj.map_type(),
            Self::PerCpuHashMap(map) => map.obj.map_type(),
            Self::PerCpuLruHashMap(map) => map.obj.map_type(),
            Self::PerfEventArray(map) => map.obj.map_type(),
            Self::SockHash(map) => map.obj.map_type(),
            Self::SockMap(map) => map.obj.map_type(),
            Self::BloomFilter(map) => map.obj.map_type(),
            Self::LpmTrie(map) => map.obj.map_type(),
            Self::Stack(map) => map.obj.map_type(),
            Self::StackTraceMap(map) => map.obj.map_type(),
            Self::Queue(map) => map.obj.map_type(),
            Self::Unsupported(map) => map.obj.map_type(),
        }
    }
}

// Implements TryFrom<Map> for different map implementations. Different map implementations can be
// constructed from different variants of the map enum. Also, the implementation may have type
// parameters (which we assume all have the bound `Pod` and nothing else).
macro_rules! impl_try_from_map {
    // At the root the type parameters are marked as a single token tree which will be pasted into
    // the invocation for each type. Note that the later patterns require that the token tree be
    // zero or more comma separated idents wrapped in parens. Note that the tt metavar is used here
    // rather than the repeated idents used later because the macro language does not allow one
    // repetition to be pasted inside another.
    ($ty_param:tt {
        $($ty:ident $(from $($variant:ident)|+)?),+ $(,)?
    }) => {
        $(impl_try_from_map!(<$ty_param> $ty $(from $($variant)|+)?);)+
    };
    // Add the "from $variant" using $ty as the default if it is missing.
    (<$ty_param:tt> $ty:ident) => {
        impl_try_from_map!(<$ty_param> $ty from $ty);
    };
    // Dispatch for each of the lifetimes.
    (
        <($($ty_param:ident),*)> $ty:ident from $($variant:ident)|+
    ) => {
        impl_try_from_map!(<'a> ($($ty_param),*) $ty from $($variant)|+);
        impl_try_from_map!(<'a mut> ($($ty_param),*) $ty from $($variant)|+);
        impl_try_from_map!(<> ($($ty_param),*) $ty from $($variant)|+);
    };
    // An individual impl.
    (
        <$($l:lifetime $($m:ident)?)?>
        ($($ty_param:ident),*)
        $ty:ident from $($variant:ident)|+
    ) => {
        impl<$($l,)? $($ty_param: Pod),*> TryFrom<$(&$l $($m)?)? Map>
            for $ty<$(&$l $($m)?)? MapData, $($ty_param),*>
        {
            type Error = MapError;

            fn try_from(map: $(&$l $($m)?)? Map) -> Result<Self, Self::Error> {
                match map {
                    $(Map::$variant(map_data) => Self::new(map_data),)+
                    map => Err(MapError::InvalidMapType {
                        map_type: map.map_type()
                    }),
                }
            }
        }
    };
}

impl_try_from_map!(() {
    ProgramArray,
    SockMap,
    PerfEventArray,
    StackTraceMap,
});

#[cfg(any(feature = "async_tokio", feature = "async_std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "async_tokio", feature = "async_std"))))]
impl_try_from_map!(() {
    AsyncPerfEventArray from PerfEventArray,
});

impl_try_from_map!((V) {
    Array,
    PerCpuArray,
    SockHash,
    BloomFilter,
    Queue,
    Stack,
});

impl_try_from_map!((K, V) {
    HashMap from HashMap|LruHashMap,
    PerCpuHashMap from PerCpuHashMap|PerCpuLruHashMap,
    LpmTrie,
});

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
    pub(crate) fd: RawFd,
    /// Indicates if this map has been pinned to bpffs
    pub pinned: bool,
}

impl MapData {
    /// Creates a new map with the provided `name`
    pub fn create(
        obj: obj::Map,
        name: &str,
        btf_fd: Option<BorrowedFd<'_>>,
    ) -> Result<Self, MapError> {
        let c_name = CString::new(name).map_err(|_| MapError::InvalidName { name: name.into() })?;

        #[cfg(not(test))]
        let kernel_version = KernelVersion::current().unwrap();
        #[cfg(test)]
        let kernel_version = KernelVersion::new(0xff, 0xff, 0xff);
        let fd =
            bpf_create_map(&c_name, &obj, btf_fd, kernel_version).map_err(|(code, io_error)| {
                if kernel_version < KernelVersion::new(5, 11, 0) {
                    maybe_warn_rlimit();
                }

                MapError::CreateError {
                    name: name.into(),
                    code,
                    io_error,
                }
            })?;

        #[allow(trivial_numeric_casts)]
        let fd = fd as RawFd;
        Ok(Self {
            obj,
            fd,
            pinned: false,
        })
    }

    pub(crate) fn create_pinned<P: AsRef<Path>>(
        path: P,
        obj: obj::Map,
        name: &str,
        btf_fd: Option<BorrowedFd<'_>>,
    ) -> Result<Self, MapError> {
        use std::os::unix::ffi::OsStrExt as _;

        // try to open map in case it's already pinned
        let path = path.as_ref().join(name);
        let path_string = match CString::new(path.as_os_str().as_bytes()) {
            Ok(path) => path,
            Err(error) => {
                return Err(MapError::PinError {
                    name: Some(name.into()),
                    error: PinError::InvalidPinPath { path, error },
                });
            }
        };
        match bpf_get_object(&path_string).map_err(|(_, io_error)| SyscallError {
            call: "BPF_OBJ_GET",
            io_error,
        }) {
            Ok(fd) => Ok(Self {
                obj,
                fd: fd.into_raw_fd(),
                pinned: false,
            }),
            Err(_) => {
                let mut map = Self::create(obj, name, btf_fd)?;
                map.pin(name, path).map_err(|error| MapError::PinError {
                    name: Some(name.into()),
                    error,
                })?;
                Ok(map)
            }
        }
    }

    /// Loads a map from a pinned path in bpffs.
    pub fn from_pin<P: AsRef<Path>>(path: P) -> Result<Self, MapError> {
        use std::os::unix::ffi::OsStrExt as _;

        let path = path.as_ref();
        let path_string =
            CString::new(path.as_os_str().as_bytes()).map_err(|error| MapError::PinError {
                name: None,
                error: PinError::InvalidPinPath {
                    path: path.into(),
                    error,
                },
            })?;

        let fd = bpf_get_object(&path_string).map_err(|(_, io_error)| SyscallError {
            call: "BPF_OBJ_GET",
            io_error,
        })?;

        let info = bpf_map_get_info_by_fd(fd.as_fd())?;

        Ok(Self {
            obj: parse_map_info(info, PinningType::ByName),
            fd: fd.into_raw_fd(),
            pinned: true,
        })
    }

    /// Loads a map from a file descriptor.
    ///
    /// If loading from a BPF Filesystem (bpffs) you should use [`Map::from_pin`](crate::maps::MapData::from_pin).
    /// This API is intended for cases where you have received a valid BPF FD from some other means.
    /// For example, you received an FD over Unix Domain Socket.
    pub fn from_fd(fd: OwnedFd) -> Result<Self, MapError> {
        let info = bpf_map_get_info_by_fd(fd.as_fd())?;

        Ok(Self {
            obj: parse_map_info(info, PinningType::None),
            fd: fd.into_raw_fd(),
            pinned: false,
        })
    }

    pub(crate) fn pin<P: AsRef<Path>>(&mut self, name: &str, path: P) -> Result<(), PinError> {
        use std::os::unix::ffi::OsStrExt as _;

        let Self { fd, pinned, obj: _ } = self;
        if *pinned {
            return Err(PinError::AlreadyPinned { name: name.into() });
        }
        let path = path.as_ref().join(name);
        let path_string = CString::new(path.as_os_str().as_bytes())
            .map_err(|error| PinError::InvalidPinPath { path, error })?;
        bpf_pin_object(*fd, &path_string).map_err(|(_, io_error)| SyscallError {
            call: "BPF_OBJ_PIN",
            io_error,
        })?;
        *pinned = true;
        Ok(())
    }

    /// Returns the file descriptor of the map.
    ///
    /// Can be converted to [`RawFd`] using [`AsRawFd`].
    pub fn fd(&self) -> MapFd {
        MapFd(self.fd)
    }
}

impl Drop for MapData {
    fn drop(&mut self) {
        // TODO: Replace this with an OwnedFd once that is stabilized.
        //
        // SAFETY: `drop` is only called once.
        unsafe { libc::close(self.fd) };
    }
}

impl Clone for MapData {
    fn clone(&self) -> Self {
        let Self { obj, fd, pinned } = self;
        Self {
            obj: obj.clone(),
            fd: unsafe { libc::dup(*fd) },
            pinned: *pinned,
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
    fn new(map: &'coll MapData) -> Self {
        Self {
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

        let fd = self.map.fd;
        let key =
            bpf_map_get_next_key(fd, self.key.as_ref()).map_err(|(_, io_error)| SyscallError {
                call: "bpf_map_get_next_key",
                io_error,
            });
        match key {
            Err(err) => {
                self.err = true;
                Some(Err(err.into()))
            }
            Ok(key) => {
                self.key = key;
                key.map(Ok)
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
    fn new(map: &'coll I) -> Self {
        Self {
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
        Ok(Self {
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

    pub(crate) unsafe fn from_kernel_mem(mem: PerCpuKernelMem) -> Self {
        let mem_ptr = mem.bytes.as_ptr() as usize;
        let value_size = (mem::size_of::<T>() + 7) & !7;
        let mut values = Vec::new();
        let mut offset = 0;
        while offset < mem.bytes.len() {
            values.push(ptr::read_unaligned((mem_ptr + offset) as *const _));
            offset += value_size;
        }

        Self {
            values: values.into_boxed_slice(),
        }
    }

    pub(crate) fn build_kernel_mem(&self) -> Result<PerCpuKernelMem, io::Error> {
        let mut mem = Self::alloc_kernel_mem()?;
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
    use assert_matches::assert_matches;
    use libc::EFAULT;

    use crate::{
        bpf_map_def,
        generated::{bpf_cmd, bpf_map_type::BPF_MAP_TYPE_HASH},
        maps::MapData,
        obj::{maps::LegacyMap, BpfSectionKind},
        sys::{override_syscall, Syscall},
    };

    use super::*;

    fn new_obj_map() -> obj::Map {
        obj::Map::Legacy(LegacyMap {
            def: bpf_map_def {
                map_type: BPF_MAP_TYPE_HASH as u32,
                key_size: 4,
                value_size: 4,
                max_entries: 1024,
                ..Default::default()
            },
            section_index: 0,
            section_kind: BpfSectionKind::Maps,
            symbol_index: Some(0),
            data: Vec::new(),
        })
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

        assert_matches!(
            MapData::create(new_obj_map(), "foo", None),
            Ok(MapData {
                obj: _,
                fd: 42,
                pinned: false
            })
        );
    }

    #[test]
    fn test_create_failed() {
        override_syscall(|_| Err((-42, io::Error::from_raw_os_error(EFAULT))));

        assert_matches!(
            MapData::create(new_obj_map(), "foo", None),
            Err(MapError::CreateError { name, code, io_error }) => {
                assert_eq!(name, "foo");
                assert_eq!(code, -42);
                assert_eq!(io_error.raw_os_error(), Some(EFAULT));
            }
        );
    }
}
