//! Data structures used to setup and share data with eBPF programs.
//!
//! The eBPF platform provides data structures - maps in eBPF speak - that are
//! used to setup and share data with eBPF programs. When you call
//! [`Ebpf::load_file`](crate::Ebpf::load_file) or
//! [`Ebpf::load`](crate::Ebpf::load), all the maps defined in the eBPF code get
//! initialized and can then be accessed using [`Ebpf::map`](crate::Ebpf::map),
//! [`Ebpf::map_mut`](crate::Ebpf::map_mut), or
//! [`Ebpf::take_map`](crate::Ebpf::take_map).
//!
//! # Typed maps
//!
//! The eBPF API includes many map types each supporting different operations.
//! [`Ebpf::map`](crate::Ebpf::map), [`Ebpf::map_mut`](crate::Ebpf::map_mut), and
//! [`Ebpf::take_map`](crate::Ebpf::take_map) always return the opaque
//! [`&Map`](crate::maps::Map), [`&mut Map`](crate::maps::Map), and [`Map`]
//! types respectively. Those three types can be converted to *typed maps* using
//! the [`TryFrom`] or [`TryInto`] trait. For example:
//!
//! ```no_run
//! # #[derive(Debug, thiserror::Error)]
//! # enum Error {
//! #     #[error(transparent)]
//! #     IO(#[from] std::io::Error),
//! #     #[error(transparent)]
//! #     Map(#[from] aya::maps::MapError),
//! #     #[error(transparent)]
//! #     Program(#[from] aya::programs::ProgramError),
//! #     #[error(transparent)]
//! #     Ebpf(#[from] aya::EbpfError)
//! # }
//! # let mut bpf = aya::Ebpf::load(&[])?;
//! use aya::maps::SockMap;
//! use aya::programs::SkMsg;
//!
//! let intercept_egress = SockMap::try_from(bpf.map_mut("INTERCEPT_EGRESS").unwrap())?;
//! let map_fd = intercept_egress.fd().try_clone()?;
//! let prog: &mut SkMsg = bpf.program_mut("intercept_egress_packet").unwrap().try_into()?;
//! prog.load()?;
//! prog.attach(&map_fd)?;
//!
//! # Ok::<(), Error>(())
//! ```
//!
//! # Maps and `Pod` values
//!
//! Many map operations copy data from kernel space to user space and vice
//! versa. Because of that, all map values must be plain old data and therefore
//! implement the [Pod] trait.
use std::{
    borrow::Borrow,
    ffi::{c_long, CString},
    fmt, io,
    marker::PhantomData,
    mem,
    ops::Deref,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::Path,
    ptr,
};

use libc::{getrlimit, rlim_t, rlimit, RLIMIT_MEMLOCK, RLIM_INFINITY};
use log::warn;
use obj::maps::InvalidMapTypeError;
use thiserror::Error;

use crate::{
    generated::bpf_map_info,
    obj::{self, parse_map_info, EbpfSectionKind},
    pin::PinError,
    sys::{
        bpf_create_map, bpf_get_object, bpf_map_freeze, bpf_map_get_fd_by_id,
        bpf_map_get_info_by_fd, bpf_map_get_next_key, bpf_map_update_elem_ptr, bpf_pin_object,
        iter_map_ids, SyscallError,
    },
    util::{bytes_of_bpf_name, nr_cpus, KernelVersion},
    PinningType, Pod,
};

pub mod array;
pub mod bloom_filter;
pub mod hash_map;
pub mod lpm_trie;
pub mod perf;
pub mod queue;
pub mod ring_buf;
pub mod sock;
pub mod stack;
pub mod stack_trace;
pub mod xdp;

pub use array::{Array, PerCpuArray, ProgramArray};
pub use bloom_filter::BloomFilter;
pub use hash_map::{HashMap, PerCpuHashMap};
pub use lpm_trie::LpmTrie;
#[cfg(any(feature = "async_tokio", feature = "async_std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "async_tokio", feature = "async_std"))))]
pub use perf::AsyncPerfEventArray;
pub use perf::PerfEventArray;
pub use queue::Queue;
pub use ring_buf::RingBuf;
pub use sock::{SockHash, SockMap};
pub use stack::Stack;
pub use stack_trace::StackTraceMap;
pub use xdp::{CpuMap, DevMap, DevMapHash, XskMap};

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
        code: c_long,
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

    /// Could not pin map
    #[error("map `{name:?}` requested pinning. pinning failed")]
    PinError {
        /// The map name
        name: Option<String>,
        /// The reason for the failure
        #[source]
        error: PinError,
    },

    /// Program IDs are not supported
    #[error("program ids are not supported by the current kernel")]
    ProgIdNotSupported,

    /// Unsupported Map type
    #[error("Unsupported map type found {map_type}")]
    Unsupported {
        /// The map type
        map_type: u32,
    },
}

// Note that this is not just derived using #[from] because InvalidMapTypeError cannot implement
// Error due the the fact that aya-obj is no_std and error_in_core is not stabilized
// (https://github.com/rust-lang/rust/issues/103765).
impl From<InvalidMapTypeError> for MapError {
    fn from(e: InvalidMapTypeError) -> Self {
        let InvalidMapTypeError { map_type } = e;
        Self::InvalidMapType { map_type }
    }
}

/// A map file descriptor.
#[derive(Debug)]
pub struct MapFd(OwnedFd);

impl AsFd for MapFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        let Self(fd) = self;
        fd.as_fd()
    }
}

/// Raises a warning about rlimit. Should be used only if creating a map was not
/// successful.
fn maybe_warn_rlimit() {
    let mut limit = mem::MaybeUninit::<rlimit>::uninit();
    let ret = unsafe { getrlimit(RLIMIT_MEMLOCK, limit.as_mut_ptr()) };
    if ret == 0 {
        let limit = unsafe { limit.assume_init() };

        if limit.rlim_cur == RLIM_INFINITY {
            return;
        }
        struct HumanSize(rlim_t);

        impl fmt::Display for HumanSize {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let &Self(size) = self;
                if size < 1024 {
                    write!(f, "{} bytes", size)
                } else if size < 1024 * 1024 {
                    write!(f, "{} KiB", size / 1024)
                } else {
                    write!(f, "{} MiB", size / 1024 / 1024)
                }
            }
        }
        warn!(
            "RLIMIT_MEMLOCK value is {}, not RLIM_INFINITY; if experiencing problems with creating \
            maps, try raising RLIMIT_MEMLOCK either to RLIM_INFINITY or to a higher value sufficient \
            for the size of your maps",
            HumanSize(limit.rlim_cur)
        );
    }
}

/// eBPF map types.
#[derive(Debug)]
pub enum Map {
    /// An [`Array`] map.
    Array(MapData),
    /// A [`BloomFilter`] map.
    BloomFilter(MapData),
    /// A [`CpuMap`] map.
    CpuMap(MapData),
    /// A [`DevMap`] map.
    DevMap(MapData),
    /// A [`DevMapHash`] map.
    DevMapHash(MapData),
    /// A [`HashMap`] map.
    HashMap(MapData),
    /// A [`LpmTrie`] map.
    LpmTrie(MapData),
    /// A [`HashMap`] map that uses a LRU eviction policy.
    LruHashMap(MapData),
    /// A [`PerCpuArray`] map.
    PerCpuArray(MapData),
    /// A [`PerCpuHashMap`] map.
    PerCpuHashMap(MapData),
    /// A [`PerCpuHashMap`] map that uses a LRU eviction policy.
    PerCpuLruHashMap(MapData),
    /// A [`PerfEventArray`] map.
    PerfEventArray(MapData),
    /// A [`ProgramArray`] map.
    ProgramArray(MapData),
    /// A [`Queue`] map.
    Queue(MapData),
    /// A [`RingBuf`] map.
    RingBuf(MapData),
    /// A [`SockHash`] map
    SockHash(MapData),
    /// A [`SockMap`] map.
    SockMap(MapData),
    /// A [`Stack`] map.
    Stack(MapData),
    /// A [`StackTraceMap`] map.
    StackTraceMap(MapData),
    /// An unsupported map type.
    Unsupported(MapData),
    /// A [`XskMap`] map.
    XskMap(MapData),
}

impl Map {
    /// Returns the low level map type.
    fn map_type(&self) -> u32 {
        match self {
            Self::Array(map) => map.obj.map_type(),
            Self::BloomFilter(map) => map.obj.map_type(),
            Self::CpuMap(map) => map.obj.map_type(),
            Self::DevMap(map) => map.obj.map_type(),
            Self::DevMapHash(map) => map.obj.map_type(),
            Self::HashMap(map) => map.obj.map_type(),
            Self::LpmTrie(map) => map.obj.map_type(),
            Self::LruHashMap(map) => map.obj.map_type(),
            Self::PerCpuArray(map) => map.obj.map_type(),
            Self::PerCpuHashMap(map) => map.obj.map_type(),
            Self::PerCpuLruHashMap(map) => map.obj.map_type(),
            Self::PerfEventArray(map) => map.obj.map_type(),
            Self::ProgramArray(map) => map.obj.map_type(),
            Self::Queue(map) => map.obj.map_type(),
            Self::RingBuf(map) => map.obj.map_type(),
            Self::SockHash(map) => map.obj.map_type(),
            Self::SockMap(map) => map.obj.map_type(),
            Self::Stack(map) => map.obj.map_type(),
            Self::StackTraceMap(map) => map.obj.map_type(),
            Self::Unsupported(map) => map.obj.map_type(),
            Self::XskMap(map) => map.obj.map_type(),
        }
    }

    /// Pins the map to a BPF filesystem.
    ///
    /// When a map is pinned it will remain loaded until the corresponding file
    /// is deleted. All parent directories in the given `path` must already exist.
    pub fn pin<P: AsRef<Path>>(&self, path: P) -> Result<(), PinError> {
        match self {
            Self::Array(map) => map.pin(path),
            Self::BloomFilter(map) => map.pin(path),
            Self::CpuMap(map) => map.pin(path),
            Self::DevMap(map) => map.pin(path),
            Self::DevMapHash(map) => map.pin(path),
            Self::HashMap(map) => map.pin(path),
            Self::LpmTrie(map) => map.pin(path),
            Self::LruHashMap(map) => map.pin(path),
            Self::PerCpuArray(map) => map.pin(path),
            Self::PerCpuHashMap(map) => map.pin(path),
            Self::PerCpuLruHashMap(map) => map.pin(path),
            Self::PerfEventArray(map) => map.pin(path),
            Self::ProgramArray(map) => map.pin(path),
            Self::Queue(map) => map.pin(path),
            Self::RingBuf(map) => map.pin(path),
            Self::SockHash(map) => map.pin(path),
            Self::SockMap(map) => map.pin(path),
            Self::Stack(map) => map.pin(path),
            Self::StackTraceMap(map) => map.pin(path),
            Self::Unsupported(map) => map.pin(path),
            Self::XskMap(map) => map.pin(path),
        }
    }
}

// Implements map pinning for different map implementations
macro_rules! impl_map_pin {
    ($ty_param:tt {
        $($ty:ident),+ $(,)?
    }) => {
        $(impl_map_pin!(<$ty_param> $ty);)+
    };
    (
      <($($ty_param:ident),*)>
      $ty:ident
    ) => {
            impl<T: Borrow<MapData>, $($ty_param: Pod),*> $ty<T, $($ty_param),*>
            {
                    /// Pins the map to a BPF filesystem.
                    ///
                    /// When a map is pinned it will remain loaded until the corresponding file
                    /// is deleted. All parent directories in the given `path` must already exist.
                    pub fn pin<P: AsRef<Path>>(self, path: P) -> Result<(), PinError> {
                        let data = self.inner.borrow();
                        data.pin(path)
                    }
            }

    };
}

impl_map_pin!(() {
    ProgramArray,
    SockMap,
    StackTraceMap,
    CpuMap,
    DevMap,
    DevMapHash,
    XskMap,
});

impl_map_pin!((V) {
    Array,
    PerCpuArray,
    SockHash,
    BloomFilter,
    Queue,
    Stack,
});

impl_map_pin!((K, V) {
    HashMap,
    PerCpuHashMap,
    LpmTrie,
});

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
    CpuMap,
    DevMap,
    DevMapHash,
    PerfEventArray,
    ProgramArray,
    RingBuf,
    SockMap,
    StackTraceMap,
    XskMap,
});

#[cfg(any(feature = "async_tokio", feature = "async_std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "async_tokio", feature = "async_std"))))]
impl_try_from_map!(() {
    AsyncPerfEventArray from PerfEventArray,
});

impl_try_from_map!((V) {
    Array,
    BloomFilter,
    PerCpuArray,
    Queue,
    SockHash,
    Stack,
});

impl_try_from_map!((K, V) {
    HashMap from HashMap|LruHashMap,
    LpmTrie,
    PerCpuHashMap from PerCpuHashMap|PerCpuLruHashMap,
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
    obj: obj::Map,
    fd: MapFd,
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
        let fd = MapFd(fd);
        Ok(Self { obj, fd })
    }

    pub(crate) fn create_pinned_by_name<P: AsRef<Path>>(
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
            Ok(fd) => {
                let fd = MapFd(fd);
                Ok(Self { obj, fd })
            }
            Err(_) => {
                let map = Self::create(obj, name, btf_fd)?;
                map.pin(&path).map_err(|error| MapError::PinError {
                    name: Some(name.into()),
                    error,
                })?;
                Ok(map)
            }
        }
    }

    pub(crate) fn finalize(&mut self) -> Result<(), MapError> {
        let Self { obj, fd } = self;
        if !obj.data().is_empty() && obj.section_kind() != EbpfSectionKind::Bss {
            bpf_map_update_elem_ptr(fd.as_fd(), &0 as *const _, obj.data_mut().as_mut_ptr(), 0)
                .map_err(|(_, io_error)| SyscallError {
                    call: "bpf_map_update_elem",
                    io_error,
                })
                .map_err(MapError::from)?;
        }
        if obj.section_kind() == EbpfSectionKind::Rodata {
            bpf_map_freeze(fd.as_fd())
                .map_err(|(_, io_error)| SyscallError {
                    call: "bpf_map_freeze",
                    io_error,
                })
                .map_err(MapError::from)?;
        }
        Ok(())
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

        Self::from_fd(fd)
    }

    /// Loads a map from a map id.
    pub fn from_id(id: u32) -> Result<Self, MapError> {
        let fd = bpf_map_get_fd_by_id(id)?;
        Self::from_fd(fd)
    }

    /// Loads a map from a file descriptor.
    ///
    /// If loading from a BPF Filesystem (bpffs) you should use [`Map::from_pin`](crate::maps::MapData::from_pin).
    /// This API is intended for cases where you have received a valid BPF FD from some other means.
    /// For example, you received an FD over Unix Domain Socket.
    pub fn from_fd(fd: OwnedFd) -> Result<Self, MapError> {
        let MapInfo(info) = MapInfo::new_from_fd(fd.as_fd())?;
        Ok(Self {
            obj: parse_map_info(info, PinningType::None),
            fd: MapFd(fd),
        })
    }

    /// Allows the map to be pinned to the provided path.
    ///
    /// Any directories in the the path provided should have been created by the caller.
    /// The path must be on a BPF filesystem.
    ///
    /// # Errors
    ///
    /// Returns a [`PinError::SyscallError`] if the underlying syscall fails.
    /// This may also happen if the path already exists, in which case the wrapped
    /// [`std::io::Error`] kind will be [`std::io::ErrorKind::AlreadyExists`].
    /// Returns a [`PinError::InvalidPinPath`] if the path provided cannot be
    /// converted to a [`CString`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # let mut bpf = aya::Ebpf::load(&[])?;
    /// # use aya::maps::MapData;
    ///
    /// let mut map = MapData::from_pin("/sys/fs/bpf/my_map")?;
    /// map.pin("/sys/fs/bpf/my_map2")?;
    ///
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn pin<P: AsRef<Path>>(&self, path: P) -> Result<(), PinError> {
        use std::os::unix::ffi::OsStrExt as _;

        let Self { fd, obj: _ } = self;
        let path = path.as_ref();
        let path_string = CString::new(path.as_os_str().as_bytes()).map_err(|error| {
            PinError::InvalidPinPath {
                path: path.to_path_buf(),
                error,
            }
        })?;
        bpf_pin_object(fd.as_fd(), &path_string).map_err(|(_, io_error)| SyscallError {
            call: "BPF_OBJ_PIN",
            io_error,
        })?;
        Ok(())
    }

    /// Returns the file descriptor of the map.
    pub fn fd(&self) -> &MapFd {
        let Self { obj: _, fd } = self;
        fd
    }

    pub(crate) fn obj(&self) -> &obj::Map {
        let Self { obj, fd: _ } = self;
        obj
    }

    /// Returns the kernel's information about the loaded map.
    pub fn info(&self) -> Result<MapInfo, MapError> {
        MapInfo::new_from_fd(self.fd.as_fd())
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

        let fd = self.map.fd().as_fd();
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
/// #     Ebpf(#[from] aya::EbpfError)
/// # }
/// # let bpf = aya::Ebpf::load(&[])?;
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

/// Provides information about a loaded map, like name, id and size.
#[derive(Debug)]
pub struct MapInfo(bpf_map_info);

impl MapInfo {
    fn new_from_fd(fd: BorrowedFd<'_>) -> Result<Self, MapError> {
        let info = bpf_map_get_info_by_fd(fd.as_fd())?;
        Ok(Self(info))
    }

    /// Loads map info from a map id.
    pub fn from_id(id: u32) -> Result<Self, MapError> {
        bpf_map_get_fd_by_id(id)
            .map_err(MapError::from)
            .and_then(|fd| Self::new_from_fd(fd.as_fd()))
    }

    /// The name of the map, limited to 16 bytes.
    pub fn name(&self) -> &[u8] {
        bytes_of_bpf_name(&self.0.name)
    }

    /// The name of the map as a &str. If the name is not valid unicode, None is returned.
    pub fn name_as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.name()).ok()
    }

    /// The id for this map. Each map has a unique id.
    pub fn id(&self) -> u32 {
        self.0.id
    }

    /// The map type as defined by the linux kernel enum
    /// [`bpf_map_type`](https://elixir.bootlin.com/linux/v6.4.4/source/include/uapi/linux/bpf.h#L905).
    pub fn map_type(&self) -> u32 {
        self.0.type_
    }

    /// The key size for this map.
    pub fn key_size(&self) -> u32 {
        self.0.key_size
    }

    /// The value size for this map.
    pub fn value_size(&self) -> u32 {
        self.0.value_size
    }

    /// The maximum number of entries in this map.
    pub fn max_entries(&self) -> u32 {
        self.0.max_entries
    }

    /// The flags for this map.
    pub fn map_flags(&self) -> u32 {
        self.0.map_flags
    }

    /// Returns a file descriptor referencing the map.
    ///
    /// The returned file descriptor can be closed at any time and doing so does
    /// not influence the life cycle of the map.
    pub fn fd(&self) -> Result<MapFd, MapError> {
        let Self(info) = self;
        let fd = bpf_map_get_fd_by_id(info.id)?;
        Ok(MapFd(fd))
    }

    /// Loads a map from a pinned path in bpffs.
    pub fn from_pin<P: AsRef<Path>>(path: P) -> Result<Self, MapError> {
        use std::os::unix::ffi::OsStrExt as _;

        // TODO: avoid this unwrap by adding a new error variant.
        let path_string = CString::new(path.as_ref().as_os_str().as_bytes()).unwrap();
        let fd = bpf_get_object(&path_string).map_err(|(_, io_error)| SyscallError {
            call: "BPF_OBJ_GET",
            io_error,
        })?;

        Self::new_from_fd(fd.as_fd())
    }
}

/// Returns an iterator over all loaded bpf maps.
///
/// This differs from [`crate::Ebpf::maps`] since it will return all maps
/// listed on the host system and not only maps for a specific [`crate::Ebpf`] instance.
///
/// # Example
/// ```
/// # use aya::maps::loaded_maps;
///
/// for m in loaded_maps() {
///     match m {
///         Ok(map) => println!("{:?}", map.name_as_str()),
///         Err(e) => println!("Error iterating maps: {:?}", e),
///     }
/// }
/// ```
///
/// # Errors
///
/// Returns [`MapError::SyscallError`] if any of the syscalls required to either get
/// next map id, get the map fd, or the [`MapInfo`] fail. In cases where
/// iteration can't be performed, for example the caller does not have the necessary privileges,
/// a single item will be yielded containing the error that occurred.
pub fn loaded_maps() -> impl Iterator<Item = Result<MapInfo, MapError>> {
    iter_map_ids().map(|id| {
        let id = id?;
        MapInfo::from_id(id)
    })
}

#[cfg(test)]
mod test_utils {
    use crate::{
        bpf_map_def,
        generated::{bpf_cmd, bpf_map_type},
        maps::MapData,
        obj::{self, maps::LegacyMap, EbpfSectionKind},
        sys::{override_syscall, Syscall},
    };

    pub(super) fn new_map(obj: obj::Map) -> MapData {
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_CREATE,
                ..
            } => Ok(1337),
            call => panic!("unexpected syscall {:?}", call),
        });
        MapData::create(obj, "foo", None).unwrap()
    }

    pub(super) fn new_obj_map(map_type: bpf_map_type) -> obj::Map {
        obj::Map::Legacy(LegacyMap {
            def: bpf_map_def {
                map_type: map_type as u32,
                key_size: 4,
                value_size: 4,
                max_entries: 1024,
                ..Default::default()
            },
            section_index: 0,
            section_kind: EbpfSectionKind::Maps,
            data: Vec::new(),
            symbol_index: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd as _;

    use assert_matches::assert_matches;
    use libc::{c_char, EFAULT};

    fn new_obj_map() -> obj::Map {
        test_utils::new_obj_map(crate::generated::bpf_map_type::BPF_MAP_TYPE_HASH)
    }

    use super::*;
    use crate::{
        generated::bpf_cmd,
        sys::{override_syscall, Syscall},
    };

    #[test]
    fn test_from_map_id() {
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_GET_FD_BY_ID,
                attr,
            } => {
                assert_eq!(
                    unsafe { attr.__bindgen_anon_6.__bindgen_anon_1.map_id },
                    1234
                );
                Ok(42)
            }
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_OBJ_GET_INFO_BY_FD,
                attr,
            } => {
                assert_eq!(unsafe { attr.info.bpf_fd }, 42);
                Ok(0)
            }
            _ => Err((-1, io::Error::from_raw_os_error(EFAULT))),
        });

        assert_matches!(
            MapData::from_id(1234),
            Ok(MapData {
                obj: _,
                fd,
            }) => assert_eq!(fd.as_fd().as_raw_fd(), 42)
        );
    }

    #[test]
    fn test_create() {
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_CREATE,
                ..
            } => Ok(42),
            _ => Err((-1, io::Error::from_raw_os_error(EFAULT))),
        });

        assert_matches!(
            MapData::create(new_obj_map(), "foo", None),
            Ok(MapData {
                obj: _,
                fd,
            }) => assert_eq!(fd.as_fd().as_raw_fd(), 42)
        );
    }

    #[test]
    // Syscall overrides are performing integer-to-pointer conversions, which
    // should be done with `ptr::from_exposed_addr` in Rust nightly, but we have
    // to support stable as well.
    #[cfg_attr(miri, ignore)]
    fn test_name() {
        use crate::generated::bpf_map_info;

        const TEST_NAME: &str = "foo";

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_CREATE,
                ..
            } => Ok(42),
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_OBJ_GET_INFO_BY_FD,
                attr,
            } => {
                assert_eq!(
                    unsafe { attr.info.info_len },
                    mem::size_of::<bpf_map_info>() as u32
                );
                let map_info = unsafe { &mut *(attr.info.info as *mut bpf_map_info) };
                map_info.name[..TEST_NAME.len()].copy_from_slice(unsafe {
                    mem::transmute::<&[u8], &[c_char]>(TEST_NAME.as_bytes())
                });
                Ok(0)
            }
            _ => Err((-1, io::Error::from_raw_os_error(EFAULT))),
        });

        let map_data = MapData::create(new_obj_map(), TEST_NAME, None).unwrap();
        assert_eq!(TEST_NAME, map_data.info().unwrap().name_as_str().unwrap());
    }

    #[test]
    // Syscall overrides are performing integer-to-pointer conversions, which
    // should be done with `ptr::from_exposed_addr` in Rust nightly, but we have
    // to support stable as well.
    #[cfg_attr(miri, ignore)]
    fn test_loaded_maps() {
        use crate::generated::bpf_map_info;

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_GET_NEXT_ID,
                attr,
            } => unsafe {
                let id = attr.__bindgen_anon_6.__bindgen_anon_1.start_id;
                if id < 5 {
                    attr.__bindgen_anon_6.next_id = id + 1;
                    Ok(0)
                } else {
                    Err((-1, io::Error::from_raw_os_error(libc::ENOENT)))
                }
            },
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_GET_FD_BY_ID,
                attr,
            } => Ok((1000 + unsafe { attr.__bindgen_anon_6.__bindgen_anon_1.map_id }) as c_long),
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_OBJ_GET_INFO_BY_FD,
                attr,
            } => {
                let map_info = unsafe { &mut *(attr.info.info as *mut bpf_map_info) };
                map_info.id = unsafe { attr.info.bpf_fd } - 1000;
                map_info.key_size = 32;
                map_info.value_size = 64;
                map_info.map_flags = 1234;
                map_info.max_entries = 99;
                Ok(0)
            }
            _ => Err((-1, io::Error::from_raw_os_error(EFAULT))),
        });

        let loaded_maps: Vec<_> = loaded_maps().collect();
        assert_eq!(loaded_maps.len(), 5);

        for (i, map_info) in loaded_maps.into_iter().enumerate() {
            let i = i + 1;
            let map_info = map_info.unwrap();
            assert_eq!(map_info.id(), i as u32);
            assert_eq!(map_info.key_size(), 32);
            assert_eq!(map_info.value_size(), 64);
            assert_eq!(map_info.map_flags(), 1234);
            assert_eq!(map_info.max_entries(), 99);
            assert_eq!(map_info.fd().unwrap().as_fd().as_raw_fd(), 1000 + i as i32);
        }
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
