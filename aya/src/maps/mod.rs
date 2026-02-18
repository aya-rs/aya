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
    ffi::CString,
    io,
    marker::PhantomData,
    ops::Deref,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::Path,
    ptr,
};

use aya_obj::{EbpfSectionKind, InvalidTypeBinding, generated::bpf_map_type, parse_map_info};
use thiserror::Error;

use crate::{
    PinningType, Pod,
    pin::PinError,
    sys::{
        SyscallError, bpf_create_map, bpf_get_object, bpf_map_freeze, bpf_map_get_fd_by_id,
        bpf_map_get_next_key, bpf_map_update_elem_ptr, bpf_pin_object,
    },
    util::nr_cpus,
};

pub mod array;
pub mod bloom_filter;
pub mod hash_map;
mod info;
pub mod lpm_trie;
pub mod of_maps;
pub mod perf;
pub mod queue;
pub mod ring_buf;
pub mod sk_storage;
pub mod sock;
pub mod stack;
pub mod stack_trace;
pub mod xdp;

pub use array::{Array, PerCpuArray, ProgramArray};
pub use bloom_filter::BloomFilter;
pub use hash_map::{HashMap, PerCpuHashMap};
pub use info::{MapInfo, MapType, loaded_maps};
pub use lpm_trie::LpmTrie;
pub use of_maps::{ArrayOfMaps, HashOfMaps};
pub use perf::PerfEventArray;
pub use queue::Queue;
pub use ring_buf::RingBuf;
pub use sk_storage::SkStorage;
pub use sock::{SockHash, SockMap};
pub use stack::Stack;
pub use stack_trace::StackTraceMap;
pub use xdp::{CpuMap, DevMap, DevMapHash, XskMap};

/// Trait for constructing a typed map from [`MapData`].
///
/// This is used by map-of-maps types ([`ArrayOfMaps`], [`HashOfMaps`]) to
/// let callers specify the expected inner map type when retrieving entries.
///
/// This trait is sealed and cannot be implemented outside of this crate.
pub trait FromMapData: Sized + sealed::Sealed {
    /// Constructs a typed map from raw [`MapData`].
    fn from_map_data(map_data: MapData) -> Result<Self, MapError>;
}

mod sealed {
    #[expect(unnameable_types, reason = "intentionally unnameable sealed trait")]
    pub trait Sealed {}
}

#[derive(Error, Debug)]
/// Errors occuring from working with Maps
pub enum MapError {
    /// Missing inner map binding for a map-of-maps.
    #[error(
        "map `{name}` is a map-of-maps but has no inner map binding; \
             use #[map(inner = \"<template>\")] or ensure the BTF definition includes a `values` field"
    )]
    MissingInnerMapBinding {
        /// The map name.
        name: String,
    },

    /// Inner map not found for a map-of-maps.
    #[error("inner map `{inner_name}` not found for map-of-maps `{name}`")]
    InnerMapNotFound {
        /// The outer map name.
        name: String,
        /// The inner map name.
        inner_name: String,
    },

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
    #[error("failed to create map `{name}`")]
    CreateError {
        /// Map name
        name: String,
        #[source]
        /// Original [`io::Error`]
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

    /// An IO error occurred
    #[error(transparent)]
    IoError(#[from] io::Error),

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
    #[error(
        "type of {name} ({map_type:?}) is unsupported; see `EbpfLoader::allow_unsupported_maps`"
    )]
    Unsupported {
        /// Map name
        name: String,
        /// The map type
        map_type: bpf_map_type,
    },
}

impl From<InvalidTypeBinding<u32>> for MapError {
    fn from(e: InvalidTypeBinding<u32>) -> Self {
        let InvalidTypeBinding { value } = e;
        Self::InvalidMapType { map_type: value }
    }
}

/// A map file descriptor.
#[derive(Debug)]
pub struct MapFd {
    fd: crate::MockableFd,
}

impl MapFd {
    const fn from_fd(fd: crate::MockableFd) -> Self {
        Self { fd }
    }

    /// Creates a new instance that shares the same underlying file description as `self`.
    pub fn try_clone(&self) -> io::Result<Self> {
        let Self { fd } = self;
        let fd = fd.try_clone()?;
        Ok(Self { fd })
    }
}

impl AsFd for MapFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        let Self { fd } = self;
        fd.as_fd()
    }
}

/// eBPF map types.
#[derive(Debug)]
pub enum Map {
    /// An [`Array`] map.
    Array(MapData),
    /// An [`ArrayOfMaps`] map.
    ArrayOfMaps(MapData),
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
    /// A [`HashOfMaps`] map.
    HashOfMaps(MapData),
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
    /// A [`SkStorage`] map.
    SkStorage(MapData),
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
    const fn map_type(&self) -> u32 {
        match self {
            Self::Array(map) => map.obj.map_type(),
            Self::ArrayOfMaps(map) => map.obj.map_type(),
            Self::BloomFilter(map) => map.obj.map_type(),
            Self::CpuMap(map) => map.obj.map_type(),
            Self::DevMap(map) => map.obj.map_type(),
            Self::DevMapHash(map) => map.obj.map_type(),
            Self::HashMap(map) => map.obj.map_type(),
            Self::HashOfMaps(map) => map.obj.map_type(),
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
            Self::SkStorage(map) => map.obj.map_type(),
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
            Self::ArrayOfMaps(map) => map.pin(path),
            Self::BloomFilter(map) => map.pin(path),
            Self::CpuMap(map) => map.pin(path),
            Self::DevMap(map) => map.pin(path),
            Self::DevMapHash(map) => map.pin(path),
            Self::HashMap(map) => map.pin(path),
            Self::HashOfMaps(map) => map.pin(path),
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
            Self::SkStorage(map) => map.pin(path),
            Self::Stack(map) => map.pin(path),
            Self::StackTraceMap(map) => map.pin(path),
            Self::Unsupported(map) => map.pin(path),
            Self::XskMap(map) => map.pin(path),
        }
    }

    /// Constructs a [`Map`] enum variant directly from a [`MapData`] instance. This allows creating
    /// a user-space handle to a pinned BPF map.
    ///
    /// # Arguments
    ///
    /// * `map_data` - The map data obtained from [`MapData::from_pin`].
    ///
    /// # Errors
    ///
    /// Returns an error if the map type is not supported.
    pub fn from_map_data(map_data: MapData) -> Result<Self, MapError> {
        let map_type = map_data.obj.map_type();
        let map = match bpf_map_type::try_from(map_type)? {
            bpf_map_type::BPF_MAP_TYPE_HASH => Self::HashMap(map_data),
            bpf_map_type::BPF_MAP_TYPE_ARRAY => Self::Array(map_data),
            bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY => Self::ProgramArray(map_data),
            bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY => Self::PerfEventArray(map_data),
            bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH => Self::PerCpuHashMap(map_data),
            bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY => Self::PerCpuArray(map_data),
            bpf_map_type::BPF_MAP_TYPE_STACK_TRACE => Self::StackTraceMap(map_data),
            bpf_map_type::BPF_MAP_TYPE_LRU_HASH => Self::LruHashMap(map_data),
            bpf_map_type::BPF_MAP_TYPE_LRU_PERCPU_HASH => Self::PerCpuLruHashMap(map_data),
            bpf_map_type::BPF_MAP_TYPE_LPM_TRIE => Self::LpmTrie(map_data),
            bpf_map_type::BPF_MAP_TYPE_DEVMAP => Self::DevMap(map_data),
            bpf_map_type::BPF_MAP_TYPE_SOCKMAP => Self::SockMap(map_data),
            bpf_map_type::BPF_MAP_TYPE_CPUMAP => Self::CpuMap(map_data),
            bpf_map_type::BPF_MAP_TYPE_XSKMAP => Self::XskMap(map_data),
            bpf_map_type::BPF_MAP_TYPE_SOCKHASH => Self::SockHash(map_data),
            bpf_map_type::BPF_MAP_TYPE_QUEUE => Self::Queue(map_data),
            bpf_map_type::BPF_MAP_TYPE_STACK => Self::Stack(map_data),
            bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH => Self::DevMapHash(map_data),
            bpf_map_type::BPF_MAP_TYPE_RINGBUF => Self::RingBuf(map_data),
            bpf_map_type::BPF_MAP_TYPE_BLOOM_FILTER => Self::BloomFilter(map_data),
            bpf_map_type::BPF_MAP_TYPE_CGROUP_ARRAY => Self::Unsupported(map_data),
            bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS => Self::ArrayOfMaps(map_data),
            bpf_map_type::BPF_MAP_TYPE_HASH_OF_MAPS => Self::HashOfMaps(map_data),
            bpf_map_type::BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED => Self::Unsupported(map_data),
            bpf_map_type::BPF_MAP_TYPE_REUSEPORT_SOCKARRAY => Self::Unsupported(map_data),
            bpf_map_type::BPF_MAP_TYPE_SK_STORAGE => Self::SkStorage(map_data),
            bpf_map_type::BPF_MAP_TYPE_STRUCT_OPS => Self::Unsupported(map_data),
            bpf_map_type::BPF_MAP_TYPE_INODE_STORAGE => Self::Unsupported(map_data),
            bpf_map_type::BPF_MAP_TYPE_TASK_STORAGE => Self::Unsupported(map_data),
            bpf_map_type::BPF_MAP_TYPE_USER_RINGBUF => Self::Unsupported(map_data),
            bpf_map_type::BPF_MAP_TYPE_CGRP_STORAGE => Self::Unsupported(map_data),
            bpf_map_type::BPF_MAP_TYPE_ARENA => Self::Unsupported(map_data),
            bpf_map_type::BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED => {
                Self::Unsupported(map_data)
            }
            bpf_map_type::BPF_MAP_TYPE_UNSPEC => return Err(MapError::InvalidMapType { map_type }),
            bpf_map_type::__MAX_BPF_MAP_TYPE => return Err(MapError::InvalidMapType { map_type }),
        };
        Ok(map)
    }

    /// Returns the file descriptor of the map.
    pub const fn fd(&self) -> &MapFd {
        match self {
            Self::Array(map) => map.fd(),
            Self::ArrayOfMaps(map) => map.fd(),
            Self::BloomFilter(map) => map.fd(),
            Self::CpuMap(map) => map.fd(),
            Self::DevMap(map) => map.fd(),
            Self::DevMapHash(map) => map.fd(),
            Self::HashMap(map) => map.fd(),
            Self::HashOfMaps(map) => map.fd(),
            Self::LpmTrie(map) => map.fd(),
            Self::LruHashMap(map) => map.fd(),
            Self::PerCpuArray(map) => map.fd(),
            Self::PerCpuHashMap(map) => map.fd(),
            Self::PerCpuLruHashMap(map) => map.fd(),
            Self::PerfEventArray(map) => map.fd(),
            Self::ProgramArray(map) => map.fd(),
            Self::Queue(map) => map.fd(),
            Self::RingBuf(map) => map.fd(),
            Self::SockHash(map) => map.fd(),
            Self::SockMap(map) => map.fd(),
            Self::SkStorage(map) => map.fd(),
            Self::Stack(map) => map.fd(),
            Self::StackTraceMap(map) => map.fd(),
            Self::Unsupported(map) => map.fd(),
            Self::XskMap(map) => map.fd(),
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
    ArrayOfMaps,
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
    SkStorage,
    Stack,
});

impl_map_pin!((K) {
    HashOfMaps,
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
        $($(#[$meta:meta])* $ty:ident $(from $($variant:ident)|+)?),+ $(,)?
    }) => {
        $(impl_try_from_map!($(#[$meta])* <$ty_param> $ty $(from $($variant)|+)?);)+
    };
    // Add the "from $variant" using $ty as the default if it is missing.
    ($(#[$meta:meta])* <$ty_param:tt> $ty:ident) => {
        impl_try_from_map!($(#[$meta])* <$ty_param> $ty from $ty);
    };
    // Dispatch for each of the lifetimes.
    (
        $(#[$meta:meta])* <($($ty_param:ident),*)> $ty:ident from $($variant:ident)|+
    ) => {
        impl_try_from_map!($(#[$meta])* <'a> ($($ty_param),*) $ty from $($variant)|+);
        impl_try_from_map!($(#[$meta])* <'a mut> ($($ty_param),*) $ty from $($variant)|+);
        impl_try_from_map!($(#[$meta])* <> ($($ty_param),*) $ty from $($variant)|+);
    };
    // An individual impl.
    (
        $(#[$meta:meta])*
        <$($l:lifetime $($m:ident)?)?>
        ($($ty_param:ident),*)
        $ty:ident from $($variant:ident)|+
    ) => {
        $(#[$meta])*
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
    ArrayOfMaps,
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

impl_try_from_map!((V) {
    Array,
    BloomFilter,
    PerCpuArray,
    Queue,
    SockHash,
    SkStorage,
    Stack,
});

impl_try_from_map!((K) {
    HashOfMaps,
});

impl_try_from_map!((K, V) {
    HashMap from HashMap|LruHashMap,
    LpmTrie,
    PerCpuHashMap from PerCpuHashMap|PerCpuLruHashMap,
});

impl<V: Pod> sealed::Sealed for Array<MapData, V> {}
impl<V: Pod> FromMapData for Array<MapData, V> {
    fn from_map_data(map_data: MapData) -> Result<Self, MapError> {
        Self::new(map_data)
    }
}

impl<K: Pod, V: Pod> sealed::Sealed for HashMap<MapData, K, V> {}
impl<K: Pod, V: Pod> FromMapData for HashMap<MapData, K, V> {
    fn from_map_data(map_data: MapData) -> Result<Self, MapError> {
        Self::new(map_data)
    }
}

impl sealed::Sealed for MapData {}
impl FromMapData for MapData {
    fn from_map_data(map_data: MapData) -> Result<Self, MapError> {
        Ok(map_data)
    }
}

pub(crate) const fn check_bounds(map: &MapData, index: u32) -> Result<(), MapError> {
    let max_entries = map.obj.max_entries();
    if index >= max_entries {
        Err(MapError::OutOfBounds { index, max_entries })
    } else {
        Ok(())
    }
}

pub(crate) const fn check_kv_size<K, V>(map: &MapData) -> Result<(), MapError> {
    let size = size_of::<K>();
    let expected = map.obj.key_size() as usize;
    if size != expected {
        return Err(MapError::InvalidKeySize { size, expected });
    }
    let size = size_of::<V>();
    let expected = map.obj.value_size() as usize;
    if size != expected {
        return Err(MapError::InvalidValueSize { size, expected });
    }
    Ok(())
}

pub(crate) const fn check_v_size<V>(map: &MapData) -> Result<(), MapError> {
    let size = size_of::<V>();
    let expected = map.obj.value_size() as usize;
    if size != expected {
        return Err(MapError::InvalidValueSize { size, expected });
    }
    Ok(())
}

/// A generic handle to a BPF map.
///
/// You should never need to use this unless you're implementing a new map type.
#[derive(Debug)]
pub struct MapData {
    obj: aya_obj::Map,
    fd: MapFd,
}

impl MapData {
    /// Creates a new map with the provided `name`
    pub fn create(
        obj: aya_obj::Map,
        name: &str,
        btf_fd: Option<BorrowedFd<'_>>,
    ) -> Result<Self, MapError> {
        Self::create_with_inner_map_fd(obj, name, btf_fd, None)
    }

    /// Creates a new map with the provided `name` and optional `inner_map_fd` for map-of-maps types.
    pub(crate) fn create_with_inner_map_fd(
        mut obj: aya_obj::Map,
        name: &str,
        btf_fd: Option<BorrowedFd<'_>>,
        inner_map_fd: Option<BorrowedFd<'_>>,
    ) -> Result<Self, MapError> {
        let c_name = CString::new(name)
            .map_err(|std::ffi::NulError { .. }| MapError::InvalidName { name: name.into() })?;

        // BPF_MAP_TYPE_PERF_EVENT_ARRAY's max_entries should not exceed the number of
        // CPUs.
        //
        // By default, the newest versions of Aya, libbpf and cilium/ebpf define `max_entries` of
        // `PerfEventArray` as `0`, with an intention to get it replaced with a correct value
        // by the loader.
        //
        // We allow custom values (potentially coming either from older versions of aya-ebpf or
        // programs written in C) as long as they don't exceed the number of CPUs.
        //
        // Otherwise, when the value is `0` or too large, we set it to the number of CPUs.
        if obj.map_type() == bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY as u32 {
            let nr_cpus = nr_cpus().map_err(|(_, error)| MapError::IoError(error))? as u32;
            if obj.max_entries() == 0 || obj.max_entries() > nr_cpus {
                obj.set_max_entries(nr_cpus);
            }
        }

        let fd = bpf_create_map(&c_name, &obj, btf_fd, inner_map_fd).map_err(|io_error| {
            MapError::CreateError {
                name: name.into(),
                io_error,
            }
        })?;
        Ok(Self {
            obj,
            fd: MapFd::from_fd(fd),
        })
    }

    pub(crate) fn create_pinned_by_name<P: AsRef<Path>>(
        path: P,
        obj: aya_obj::Map,
        name: &str,
        btf_fd: Option<BorrowedFd<'_>>,
        inner_map_fd: Option<BorrowedFd<'_>>,
    ) -> Result<Self, MapError> {
        use std::os::unix::ffi::OsStrExt as _;

        // try to open map in case it's already pinned
        let path = path.as_ref();
        let path_string = match CString::new(path.as_os_str().as_bytes()) {
            Ok(path) => path,
            Err(error) => {
                return Err(MapError::PinError {
                    name: Some(name.into()),
                    error: PinError::InvalidPinPath {
                        path: path.to_path_buf(),
                        error,
                    },
                });
            }
        };
        if let Ok(fd) = bpf_get_object(&path_string) {
            Ok(Self {
                obj,
                fd: MapFd::from_fd(fd),
            })
        } else {
            let map = Self::create_with_inner_map_fd(obj, name, btf_fd, inner_map_fd)?;
            map.pin(path).map_err(|error| MapError::PinError {
                name: Some(name.into()),
                error,
            })?;
            Ok(map)
        }
    }

    pub(crate) fn finalize(&mut self) -> Result<(), MapError> {
        let Self { obj, fd } = self;
        if !obj.data().is_empty() {
            bpf_map_update_elem_ptr(fd.as_fd(), &0, obj.data_mut().as_mut_ptr(), 0)
                .map_err(|io_error| SyscallError {
                    call: "bpf_map_update_elem",
                    io_error,
                })
                .map_err(MapError::from)?;
        }
        if obj.section_kind() == EbpfSectionKind::Rodata {
            bpf_map_freeze(fd.as_fd())
                .map_err(|io_error| SyscallError {
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

        let fd = bpf_get_object(&path_string).map_err(|io_error| SyscallError {
            call: "BPF_OBJ_GET",
            io_error,
        })?;

        Self::from_fd_inner(fd)
    }

    /// Loads a map from a map id.
    pub fn from_id(id: u32) -> Result<Self, MapError> {
        let fd = bpf_map_get_fd_by_id(id)?;
        Self::from_fd_inner(fd)
    }

    fn from_fd_inner(fd: crate::MockableFd) -> Result<Self, MapError> {
        let MapInfo(info) = MapInfo::new_from_fd(fd.as_fd())?;
        Ok(Self {
            obj: parse_map_info(info, PinningType::None),
            fd: MapFd::from_fd(fd),
        })
    }

    /// Loads a map from a file descriptor.
    ///
    /// If loading from a BPF Filesystem (bpffs) you should use [`Map::from_pin`](crate::maps::MapData::from_pin).
    /// This API is intended for cases where you have received a valid BPF FD from some other means.
    /// For example, you received an FD over Unix Domain Socket.
    pub fn from_fd(fd: OwnedFd) -> Result<Self, MapError> {
        let fd = crate::MockableFd::from_fd(fd);
        Self::from_fd_inner(fd)
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
        bpf_pin_object(fd.as_fd(), &path_string).map_err(|io_error| SyscallError {
            call: "BPF_OBJ_PIN",
            io_error,
        })?;
        Ok(())
    }

    /// Returns the file descriptor of the map.
    pub const fn fd(&self) -> &MapFd {
        let Self { obj: _, fd } = self;
        fd
    }

    pub(crate) const fn obj(&self) -> &aya_obj::Map {
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
    const fn new(map: &'coll MapData) -> Self {
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
        let key = bpf_map_get_next_key(fd, self.key.as_ref()).map_err(|io_error| SyscallError {
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
                    Err(MapError::KeyNotFound) => {}
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
    pub(crate) const fn as_mut_ptr(&mut self) -> *mut u8 {
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
/// let nr_cpus = nr_cpus().map_err(|(_, error)| error)?;
/// let values = PerCpuValues::try_from(vec![42u32; nr_cpus])?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
pub struct PerCpuValues<T: Pod> {
    values: Box<[T]>,
}

impl<T: Pod> TryFrom<Vec<T>> for PerCpuValues<T> {
    type Error = io::Error;

    fn try_from(values: Vec<T>) -> Result<Self, Self::Error> {
        let nr_cpus = nr_cpus().map_err(|(_, error)| error)?;
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
        let value_size = size_of::<T>().next_multiple_of(8);
        let nr_cpus = nr_cpus().map_err(|(_, error)| error)?;
        Ok(PerCpuKernelMem {
            bytes: vec![0u8; nr_cpus * value_size],
        })
    }

    pub(crate) unsafe fn from_kernel_mem(mem: PerCpuKernelMem) -> Self {
        let stride = size_of::<T>().next_multiple_of(8);
        let mut values = Vec::new();
        let mut offset = 0;
        while offset < mem.bytes.len() {
            values.push(unsafe { ptr::read_unaligned(mem.bytes.as_ptr().add(offset).cast()) });
            offset += stride;
        }

        Self {
            values: values.into_boxed_slice(),
        }
    }

    pub(crate) fn build_kernel_mem(&self) -> Result<PerCpuKernelMem, io::Error> {
        let mut mem = Self::alloc_kernel_mem()?;
        let mem_ptr = mem.as_mut_ptr();
        let value_size = size_of::<T>().next_multiple_of(8);
        for (i, value) in self.values.iter().enumerate() {
            unsafe { ptr::write_unaligned(mem_ptr.byte_add(i * value_size).cast(), *value) }
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
mod test_utils {
    use aya_obj::{
        EbpfSectionKind,
        generated::{bpf_cmd, bpf_map_type},
        maps::LegacyMap,
    };

    use crate::{
        bpf_map_def,
        maps::MapData,
        sys::{Syscall, override_syscall},
    };

    pub(super) fn new_map(obj: aya_obj::Map) -> MapData {
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_CREATE,
                ..
            } => Ok(crate::MockableFd::mock_signed_fd().into()),
            call => panic!("unexpected syscall {call:?}"),
        });
        MapData::create(obj, "foo", None).unwrap()
    }

    pub(super) fn new_obj_map<K>(map_type: bpf_map_type) -> aya_obj::Map {
        aya_obj::Map::Legacy(LegacyMap {
            def: bpf_map_def {
                map_type: map_type as u32,
                key_size: size_of::<K>() as u32,
                value_size: 4,
                max_entries: 1024,
                ..Default::default()
            },
            inner_def: None,
            section_index: 0,
            section_kind: EbpfSectionKind::Maps,
            data: Vec::new(),
            symbol_index: None,
        })
    }

    pub(super) fn new_obj_map_with_max_entries<K>(
        map_type: bpf_map_type,
        max_entries: u32,
    ) -> aya_obj::Map {
        aya_obj::Map::Legacy(LegacyMap {
            def: bpf_map_def {
                map_type: map_type as u32,
                key_size: size_of::<K>() as u32,
                value_size: 4,
                max_entries,
                ..Default::default()
            },
            inner_def: None,
            section_index: 0,
            section_kind: EbpfSectionKind::Maps,
            data: Vec::new(),
            symbol_index: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::c_char, os::fd::AsRawFd as _};

    use assert_matches::assert_matches;
    use aya_obj::generated::{bpf_cmd, bpf_map_info};
    use libc::EFAULT;

    use super::*;
    use crate::sys::{Syscall, override_syscall};

    fn new_obj_map() -> aya_obj::Map {
        test_utils::new_obj_map::<u32>(bpf_map_type::BPF_MAP_TYPE_HASH)
    }

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
                Ok(crate::MockableFd::mock_signed_fd().into())
            }
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_OBJ_GET_INFO_BY_FD,
                attr,
            } => {
                assert_eq!(
                    unsafe { attr.info.bpf_fd },
                    crate::MockableFd::mock_unsigned_fd(),
                );
                Ok(0)
            }
            _ => Err((-1, io::Error::from_raw_os_error(EFAULT))),
        });

        assert_matches!(
            MapData::from_id(1234),
            Ok(MapData {
                obj: _,
                fd,
            }) => assert_eq!(fd.as_fd().as_raw_fd(), crate::MockableFd::mock_signed_fd())
        );
    }

    #[test]
    fn test_create() {
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_CREATE,
                ..
            } => Ok(crate::MockableFd::mock_signed_fd().into()),
            _ => Err((-1, io::Error::from_raw_os_error(EFAULT))),
        });

        assert_matches!(
            MapData::create(new_obj_map(), "foo", None),
            Ok(MapData {
                obj: _,
                fd,
            }) => assert_eq!(fd.as_fd().as_raw_fd(), crate::MockableFd::mock_signed_fd())
        );
    }

    #[test]
    fn test_create_perf_event_array() {
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_CREATE,
                ..
            } => Ok(crate::MockableFd::mock_signed_fd().into()),
            _ => Err((-1, io::Error::from_raw_os_error(EFAULT))),
        });

        let nr_cpus = nr_cpus().unwrap();

        // Create with max_entries > nr_cpus is clamped to nr_cpus
        assert_matches!(
            MapData::create(test_utils::new_obj_map_with_max_entries::<u32>(
                bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                65535,
            ), "foo", None),
            Ok(MapData {
                obj,
                fd,
            }) => {
                assert_eq!(fd.as_fd().as_raw_fd(), crate::MockableFd::mock_signed_fd());
                assert_eq!(obj.max_entries(), nr_cpus as u32)
            }
        );

        // Create with max_entries = 0 is set to nr_cpus
        assert_matches!(
            MapData::create(test_utils::new_obj_map_with_max_entries::<u32>(
                bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                0,
            ), "foo", None),
            Ok(MapData {
                obj,
                fd,
            }) => {
                assert_eq!(fd.as_fd().as_raw_fd(), crate::MockableFd::mock_signed_fd());
                assert_eq!(obj.max_entries(), nr_cpus as u32)
            }
        );

        // Create with max_entries < nr_cpus is unchanged
        assert_matches!(
            MapData::create(test_utils::new_obj_map_with_max_entries::<u32>(
                bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                1,
            ), "foo", None),
            Ok(MapData {
                obj,
                fd,
            }) => {
                assert_eq!(fd.as_fd().as_raw_fd(), crate::MockableFd::mock_signed_fd());
                assert_eq!(obj.max_entries(), 1)
            }
        );
    }

    #[test]
    fn test_name() {
        const TEST_NAME: &str = "foo";

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_CREATE,
                ..
            } => Ok(crate::MockableFd::mock_signed_fd().into()),
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_OBJ_GET_INFO_BY_FD,
                attr,
            } => {
                assert_eq!(
                    unsafe { attr.info.info_len },
                    size_of::<bpf_map_info>() as u32
                );
                unsafe {
                    let name_bytes = std::mem::transmute::<&[u8], &[c_char]>(TEST_NAME.as_bytes());
                    let map_info = attr.info.info as *mut bpf_map_info;
                    map_info.write({
                        let mut map_info = map_info.read();
                        map_info.name[..name_bytes.len()].copy_from_slice(name_bytes);
                        map_info
                    })
                }
                Ok(0)
            }
            _ => Err((-1, io::Error::from_raw_os_error(EFAULT))),
        });

        let map_data = MapData::create(new_obj_map(), TEST_NAME, None).unwrap();
        assert_eq!(TEST_NAME, map_data.info().unwrap().name_as_str().unwrap());
    }

    #[test]
    fn test_loaded_maps() {
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
            } => Ok((unsafe { attr.__bindgen_anon_6.__bindgen_anon_1.map_id }
                + crate::MockableFd::mock_unsigned_fd())
            .into()),
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_OBJ_GET_INFO_BY_FD,
                attr,
            } => {
                unsafe {
                    let info = attr.info;
                    let map_info = info.info as *mut bpf_map_info;
                    map_info.write({
                        let mut map_info = map_info.read();
                        map_info.id = info.bpf_fd - crate::MockableFd::mock_unsigned_fd();
                        map_info.key_size = 32;
                        map_info.value_size = 64;
                        map_info.map_flags = 1234;
                        map_info.max_entries = 99;
                        map_info
                    });
                }
                Ok(0)
            }
            _ => Err((-1, io::Error::from_raw_os_error(EFAULT))),
        });

        assert_eq!(
            loaded_maps()
                .map(|map_info| {
                    let map_info = map_info.unwrap();
                    (
                        map_info.id(),
                        map_info.key_size(),
                        map_info.value_size(),
                        map_info.map_flags(),
                        map_info.max_entries(),
                        map_info.fd().unwrap().as_fd().as_raw_fd(),
                    )
                })
                .collect::<Vec<_>>(),
            (1..6)
                .map(|i: u8| (
                    i.into(),
                    32,
                    64,
                    1234,
                    99,
                    crate::MockableFd::mock_signed_fd() + i32::from(i)
                ))
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn test_create_failed() {
        override_syscall(|_| Err((-1, io::Error::from_raw_os_error(EFAULT))));

        assert_matches!(
            MapData::create(new_obj_map(), "foo", None),
            Err(MapError::CreateError { name, io_error }) => {
                assert_eq!(name, "foo");
                assert_eq!(io_error.raw_os_error(), Some(EFAULT));
            }
        );
    }
}
