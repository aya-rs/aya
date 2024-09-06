//! Metadata information about an eBPF map.

use std::{
    ffi::CString,
    os::fd::{AsFd as _, BorrowedFd},
    path::Path,
};

use aya_obj::generated::{bpf_map_info, bpf_map_type};

use super::{MapError, MapFd};
use crate::{
    sys::{
        bpf_get_object, bpf_map_get_fd_by_id, bpf_map_get_info_by_fd, iter_map_ids, SyscallError,
    },
    util::bytes_of_bpf_name,
    FEATURES,
};

/// Provides Provides metadata information about a loaded eBPF map.
///
/// Introduced in kernel v4.13.
#[doc(alias = "bpf_map_info")]
#[derive(Debug)]
pub struct MapInfo(pub(crate) bpf_map_info);

impl MapInfo {
    pub(crate) fn new_from_fd(fd: BorrowedFd<'_>) -> Result<Self, MapError> {
        let info = bpf_map_get_info_by_fd(fd.as_fd())?;
        Ok(Self(info))
    }

    /// Loads map info from a map ID.
    ///
    /// Uses kernel v4.13 features.
    pub fn from_id(id: u32) -> Result<Self, MapError> {
        bpf_map_get_fd_by_id(id)
            .map_err(MapError::from)
            .and_then(|fd| Self::new_from_fd(fd.as_fd()))
    }

    /// The type of map.
    ///
    /// Introduced in kernel v4.13.
    pub fn map_type(&self) -> Result<MapType, MapError> {
        bpf_map_type::try_from(self.0.type_)
            .unwrap_or(bpf_map_type::__MAX_BPF_MAP_TYPE)
            .try_into()
    }

    /// The unique ID for this map.
    ///
    /// Introduced in kernel v4.13.
    pub fn id(&self) -> u32 {
        self.0.id
    }

    /// The key size for this map in bytes.
    ///
    /// Introduced in kernel v4.13.
    pub fn key_size(&self) -> u32 {
        self.0.key_size
    }

    /// The value size for this map in bytes.
    ///
    /// Introduced in kernel v4.13.
    pub fn value_size(&self) -> u32 {
        self.0.value_size
    }

    /// The maximum number of entries in this map.
    ///
    /// Introduced in kernel v4.13.
    pub fn max_entries(&self) -> u32 {
        self.0.max_entries
    }

    /// The flags used in loading this map.
    ///
    /// Introduced in kernel v4.13.
    pub fn map_flags(&self) -> u32 {
        self.0.map_flags
    }

    /// The name of the map, limited to 16 bytes.
    ///
    /// Introduced in kernel v4.15.
    pub fn name(&self) -> &[u8] {
        bytes_of_bpf_name(&self.0.name)
    }

    /// The name of the map as a &str.
    ///
    /// `None` is returned if the name was not valid unicode or if field is not available.
    ///
    /// Introduced in kernel v4.15.
    pub fn name_as_str(&self) -> Option<&str> {
        let name = std::str::from_utf8(self.name()).ok()?;
        // Char in program name was introduced in the same commit as map name
        (FEATURES.bpf_name() || !name.is_empty()).then_some(name)
    }

    /// Returns a file descriptor referencing the map.
    ///
    /// The returned file descriptor can be closed at any time and doing so does
    /// not influence the life cycle of the map.
    ///
    /// Uses kernel v4.13 features.
    pub fn fd(&self) -> Result<MapFd, MapError> {
        let Self(info) = self;
        let fd = bpf_map_get_fd_by_id(info.id)?;
        Ok(MapFd::from_fd(fd))
    }

    /// Loads a map from a pinned path in bpffs.
    ///
    /// Uses kernel v4.4 and v4.13 features.
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

/// Returns an iterator of [`MapInfo`] over all eBPF maps on the host.
///
/// Unlike [`Ebpf::maps`](crate::Ebpf::maps), this includes all maps on the host system, not
/// just those tied to a specific [`crate::Ebpf`] instance.
///
/// Uses kernel v4.13 features.
///
/// # Example
/// ```
/// # use aya::maps::loaded_maps;
/// #
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
/// next map id, get the map fd, or the [`MapInfo`] fail.
///
/// In cases where iteration can't be performed, for example the caller does not have the necessary
/// privileges, a single item will be yielded containing the error that occurred.
pub fn loaded_maps() -> impl Iterator<Item = Result<MapInfo, MapError>> {
    iter_map_ids().map(|id| {
        let id = id?;
        MapInfo::from_id(id)
    })
}

/// The type of eBPF map.
#[non_exhaustive]
#[doc(alias = "bpf_map_type")]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MapType {
    /// An unspecified program type.
    Unspecified = bpf_map_type::BPF_MAP_TYPE_UNSPEC as isize,
    /// A Hash map type. See [`HashMap`](super::hash_map::HashMap) for the map implementation.
    ///
    /// Introduced in kernel v3.19.
    #[doc(alias = "BPF_MAP_TYPE_HASH")]
    Hash = bpf_map_type::BPF_MAP_TYPE_HASH as isize,
    /// An Array map type. See [`Array`](super::array::Array) for the map implementation.
    ///
    /// Introduced in kernel v3.19.
    #[doc(alias = "BPF_MAP_TYPE_ARRAY")]
    Array = bpf_map_type::BPF_MAP_TYPE_ARRAY as isize,
    /// A Program Array map type. See [`ProgramArray`](super::array::ProgramArray) for the map
    /// implementation.
    ///
    /// Introduced in kernel v4.2.
    #[doc(alias = "BPF_MAP_TYPE_PROG_ARRAY")]
    ProgramArray = bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY as isize,
    /// A Perf Event Array map type. See [`PerfEventArray`](super::perf::PerfEventArray) and
    /// [`AsyncPerfEventArray`](super::perf::AsyncPerfEventArray) for the map implementations.
    ///
    /// Introduced in kernel v4.3.
    #[doc(alias = "BPF_MAP_TYPE_PERF_EVENT_ARRAY")]
    PerfEventArray = bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY as isize,
    /// A per-CPU Hash map type. See [`PerCpuHashMap`](super::hash_map::PerCpuHashMap) for the map
    /// implementation.
    ///
    /// Introduced in kernel v4.6.
    #[doc(alias = "BPF_MAP_TYPE_PERCPU_HASH")]
    PerCpuHash = bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH as isize,
    /// A per-CPU Array map type. See [`PerCpuArray`](super::array::PerCpuArray) for the map
    /// implementation.
    ///
    /// Introduced in kernel v4.6.
    #[doc(alias = "BPF_MAP_TYPE_PERCPU_ARRAY")]
    PerCpuArray = bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY as isize,
    /// A Stack Trace map type. See [`StackTraceMap`](super::stack_trace::StackTraceMap) for the map
    /// implementation.
    ///
    /// Introduced in kernel v4.6.
    #[doc(alias = "BPF_MAP_TYPE_STACK_TRACE")]
    StackTrace = bpf_map_type::BPF_MAP_TYPE_STACK_TRACE as isize,
    /// A cGroup Array map type.
    ///
    /// Introduced in kernel v4.8.
    #[doc(alias = "BPF_MAP_TYPE_CGROUP_ARRAY")]
    CgroupArray = bpf_map_type::BPF_MAP_TYPE_CGROUP_ARRAY as isize,
    /// A Least Recently Used (LRU) Hash map type. See [`HashMap`](super::hash_map::HashMap) for
    /// the map implementation.
    ///
    /// Introduced in kernel v4.10.
    #[doc(alias = "BPF_MAP_TYPE_LRU_HASH")]
    LruHash = bpf_map_type::BPF_MAP_TYPE_LRU_HASH as isize,
    /// A Least Recently Used (LRU) per-CPU Hash map type. See
    /// [`PerCpuHashMap`](super::hash_map::PerCpuHashMap) for the map implementation.
    ///
    /// Introduced in kernel v4.10.
    #[doc(alias = "BPF_MAP_TYPE_LRU_PERCPU_HASH")]
    LruPerCpuHash = bpf_map_type::BPF_MAP_TYPE_LRU_PERCPU_HASH as isize,
    /// A Longest Prefix Match (LPM) Trie map type. See [`LpmTrie`](super::lpm_trie::LpmTrie) for
    /// the map implementation.
    ///
    /// Introduced in kernel v4.11.
    #[doc(alias = "BPF_MAP_TYPE_LPM_TRIE")]
    LpmTrie = bpf_map_type::BPF_MAP_TYPE_LPM_TRIE as isize,
    /// An Array of Maps map type.
    ///
    /// Introduced in kernel v4.12.
    #[doc(alias = "BPF_MAP_TYPE_ARRAY_OF_MAPS")]
    ArrayOfMaps = bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS as isize,
    /// A Hash of Maps map type.
    ///
    /// Introduced in kernel v4.12.
    #[doc(alias = "BPF_MAP_TYPE_HASH_OF_MAPS")]
    HashOfMaps = bpf_map_type::BPF_MAP_TYPE_HASH_OF_MAPS as isize,
    /// A Device Map type. See [`DevMap`](super::xdp::DevMap) for the map implementation.
    ///
    /// Introduced in kernel v4.14.
    #[doc(alias = "BPF_MAP_TYPE_DEVMAP")]
    DevMap = bpf_map_type::BPF_MAP_TYPE_DEVMAP as isize,
    /// A Socket Map type. See [`SockMap`](super::sock::SockMap) for the map implementation.
    ///
    /// Introduced in kernel v4.14.
    #[doc(alias = "BPF_MAP_TYPE_SOCKMAP")]
    SockMap = bpf_map_type::BPF_MAP_TYPE_SOCKMAP as isize,
    /// A CPU Map type. See [`CpuMap`](super::xdp::CpuMap) for the map implementation.
    ///
    /// Introduced in kernel v4.15.
    #[doc(alias = "BPF_MAP_TYPE_CPUMAP")]
    CpuMap = bpf_map_type::BPF_MAP_TYPE_CPUMAP as isize,
    /// An XDP Socket Map type. See [`XskMap`](super::xdp::XskMap) for the map implementation.
    ///
    /// Introduced in kernel v4.18.
    #[doc(alias = "BPF_MAP_TYPE_XSKMAP")]
    XskMap = bpf_map_type::BPF_MAP_TYPE_XSKMAP as isize,
    /// A Socket Hash map type. See [`SockHash`](super::sock::SockHash) for the map implementation.
    ///
    /// Introduced in kernel v4.18.
    #[doc(alias = "BPF_MAP_TYPE_SOCKHASH")]
    SockHash = bpf_map_type::BPF_MAP_TYPE_SOCKHASH as isize,
    /// A cGroup Storage map type.
    ///
    /// Introduced in kernel v4.19.
    // #[deprecated]
    #[doc(alias = "BPF_MAP_TYPE_CGROUP_STORAGE")]
    #[doc(alias = "BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED")]
    CgroupStorage = bpf_map_type::BPF_MAP_TYPE_CGROUP_STORAGE as isize,
    /// A Reuseport Socket Array map type.
    ///
    /// Introduced in kernel v4.19.
    #[doc(alias = "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY")]
    ReuseportSockArray = bpf_map_type::BPF_MAP_TYPE_REUSEPORT_SOCKARRAY as isize,
    /// A per-CPU cGroup Storage map type.
    ///
    /// Introduced in kernel v4.20.
    #[doc(alias = "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE")]
    #[doc(alias = "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED")]
    PerCpuCgroupStorage = bpf_map_type::BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE as isize,
    /// A Queue map type. See [`Queue`](super::queue::Queue) for the map implementation.
    ///
    /// Introduced in kernel v4.20.
    #[doc(alias = "BPF_MAP_TYPE_QUEUE")]
    Queue = bpf_map_type::BPF_MAP_TYPE_QUEUE as isize,
    /// A Stack map type. See [`Stack`](super::stack::Stack) for the map implementation.
    ///
    /// Introduced in kernel v4.20.
    #[doc(alias = "BPF_MAP_TYPE_STACK")]
    Stack = bpf_map_type::BPF_MAP_TYPE_STACK as isize,
    /// A Socket-local Storage map type.
    ///
    /// Introduced in kernel v5.2.
    #[doc(alias = "BPF_MAP_TYPE_SK_STORAGE")]
    SkStorage = bpf_map_type::BPF_MAP_TYPE_SK_STORAGE as isize,
    /// A Device Hash Map type. See [`DevMapHash`](super::xdp::DevMapHash) for the map
    /// implementation.
    ///
    /// Introduced in kernel v5.4.
    #[doc(alias = "BPF_MAP_TYPE_DEVMAP_HASH")]
    DevMapHash = bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH as isize,
    /// A Struct Ops map type.
    ///
    /// Introduced in kernel v5.6.
    #[doc(alias = "BPF_MAP_TYPE_STRUCT_OPS")]
    StructOps = bpf_map_type::BPF_MAP_TYPE_STRUCT_OPS as isize,
    /// A Ring Buffer map type. See [`RingBuf`](super::ring_buf::RingBuf) for the map
    /// implementation.
    ///
    /// Introduced in kernel v5.8.
    #[doc(alias = "BPF_MAP_TYPE_RINGBUF")]
    RingBuf = bpf_map_type::BPF_MAP_TYPE_RINGBUF as isize,
    /// An Inode Storage map type.
    ///
    /// Introduced in kernel v5.10.
    #[doc(alias = "BPF_MAP_TYPE_INODE_STORAGE")]
    InodeStorage = bpf_map_type::BPF_MAP_TYPE_INODE_STORAGE as isize,
    /// A Task Storage map type.
    ///
    /// Introduced in kernel v5.11.
    #[doc(alias = "BPF_MAP_TYPE_TASK_STORAGE")]
    TaskStorage = bpf_map_type::BPF_MAP_TYPE_TASK_STORAGE as isize,
    /// A Bloom Filter map type. See [`BloomFilter`](super::bloom_filter::BloomFilter) for the map
    /// implementation.
    ///
    /// Introduced in kernel v5.16.
    #[doc(alias = "BPF_MAP_TYPE_BLOOM_FILTER")]
    BloomFilter = bpf_map_type::BPF_MAP_TYPE_BLOOM_FILTER as isize,
    /// A User Ring Buffer map type.
    ///
    /// Introduced in kernel v6.1.
    #[doc(alias = "BPF_MAP_TYPE_USER_RINGBUF")]
    UserRingBuf = bpf_map_type::BPF_MAP_TYPE_USER_RINGBUF as isize,
    /// A cGroup Storage map type.
    ///
    /// Introduced in kernel v6.2.
    #[doc(alias = "BPF_MAP_TYPE_CGRP_STORAGE")]
    CgrpStorage = bpf_map_type::BPF_MAP_TYPE_CGRP_STORAGE as isize,
    /// An Arena map type.
    ///
    /// Introduced in kernel v6.9.
    #[doc(alias = "BPF_MAP_TYPE_ARENA")]
    Arena = bpf_map_type::BPF_MAP_TYPE_ARENA as isize,
}

impl TryFrom<bpf_map_type> for MapType {
    type Error = MapError;

    fn try_from(map_type: bpf_map_type) -> Result<Self, Self::Error> {
        use bpf_map_type::*;
        Ok(match map_type {
            BPF_MAP_TYPE_UNSPEC => Self::Unspecified,
            BPF_MAP_TYPE_HASH => Self::Hash,
            BPF_MAP_TYPE_ARRAY => Self::Array,
            BPF_MAP_TYPE_PROG_ARRAY => Self::ProgramArray,
            BPF_MAP_TYPE_PERF_EVENT_ARRAY => Self::PerfEventArray,
            BPF_MAP_TYPE_PERCPU_HASH => Self::PerCpuHash,
            BPF_MAP_TYPE_PERCPU_ARRAY => Self::PerCpuArray,
            BPF_MAP_TYPE_STACK_TRACE => Self::StackTrace,
            BPF_MAP_TYPE_CGROUP_ARRAY => Self::CgroupArray,
            BPF_MAP_TYPE_LRU_HASH => Self::LruHash,
            BPF_MAP_TYPE_LRU_PERCPU_HASH => Self::LruPerCpuHash,
            BPF_MAP_TYPE_LPM_TRIE => Self::LpmTrie,
            BPF_MAP_TYPE_ARRAY_OF_MAPS => Self::ArrayOfMaps,
            BPF_MAP_TYPE_HASH_OF_MAPS => Self::HashOfMaps,
            BPF_MAP_TYPE_DEVMAP => Self::DevMap,
            BPF_MAP_TYPE_SOCKMAP => Self::SockMap,
            BPF_MAP_TYPE_CPUMAP => Self::CpuMap,
            BPF_MAP_TYPE_XSKMAP => Self::XskMap,
            BPF_MAP_TYPE_SOCKHASH => Self::SockHash,
            BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED => Self::CgroupStorage,
            BPF_MAP_TYPE_REUSEPORT_SOCKARRAY => Self::ReuseportSockArray,
            BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED => Self::PerCpuCgroupStorage,
            BPF_MAP_TYPE_QUEUE => Self::Queue,
            BPF_MAP_TYPE_STACK => Self::Stack,
            BPF_MAP_TYPE_SK_STORAGE => Self::SkStorage,
            BPF_MAP_TYPE_DEVMAP_HASH => Self::DevMapHash,
            BPF_MAP_TYPE_STRUCT_OPS => Self::StructOps,
            BPF_MAP_TYPE_RINGBUF => Self::RingBuf,
            BPF_MAP_TYPE_INODE_STORAGE => Self::InodeStorage,
            BPF_MAP_TYPE_TASK_STORAGE => Self::TaskStorage,
            BPF_MAP_TYPE_BLOOM_FILTER => Self::BloomFilter,
            BPF_MAP_TYPE_USER_RINGBUF => Self::UserRingBuf,
            BPF_MAP_TYPE_CGRP_STORAGE => Self::CgrpStorage,
            BPF_MAP_TYPE_ARENA => Self::Arena,
            __MAX_BPF_MAP_TYPE => {
                return Err(MapError::InvalidMapType {
                    map_type: map_type as u32,
                })
            }
        })
    }
}
