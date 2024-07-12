//! Map struct and type bindings.

use alloc::vec::Vec;
use core::mem;

#[cfg(not(feature = "std"))]
use crate::std;
use crate::{generated::bpf_map_type, EbpfSectionKind};

/// Invalid map type encontered
pub struct InvalidMapTypeError {
    /// The map type
    pub map_type: u32,
}

/// The type of BPF Map
#[derive(Copy, Clone, Debug)]
pub enum BpfMapType {
    /// Not Specified
    Unspecified,
    /// Hash
    Hash,
    /// Array
    Array,
    /// Prog Array
    ProgArray,
    /// Perf Event Array
    PerfEventArray,
    /// Per-CPU Hash
    PerCpuHash,
    /// Per-CPU Array
    PerCpuArray,
    /// Stack Trace
    StackTrace,
    /// Cgroup Array
    CgroupArray,
    /// LRU Hash
    LruHash,
    /// LRU Per-CPU Hash
    LruPerCpuHash,
    /// LPM Trie
    LpmTrie,
    /// Array of Maps
    ArrayOfMaps,
    /// Hash of Maps
    HashOfMaps,
    /// Devmap
    Devmap,
    /// Sockmap
    Sockmap,
    /// Cpumap
    Cpumap,
    /// Xskmap
    Xskmap,
    /// Sockhash
    Sockhash,
    /// Cgroup Storage (deprecated)
    CgroupStorageDeprecated,
    /// Reuseport Sockarray
    ReuseportSockarray,
    /// Per-CPU Cgroup Storage (deprecated)
    PerCpuCgroupStorageDeprecated,
    /// Queue
    Queue,
    /// Stack
    Stack,
    /// Sk Storage
    SkStorage,
    /// Devmap Hash
    DevmapHash,
    /// Struct Ops
    StructOps,
    /// Ringbuf
    Ringbuf,
    /// Inode Storage
    InodeStorage,
    /// Task Storage
    TaskStorage,
    /// Bloom Filter
    BloomFilter,
    /// User Ringbuf
    UserRingbuf,
    /// Cgroup Storage
    CgroupStorage,
    /// Arena
    Arena,
}

impl From<BpfMapType> for bpf_map_type {
    fn from(value: BpfMapType) -> Self {
        match value {
            BpfMapType::Unspecified => bpf_map_type::BPF_MAP_TYPE_UNSPEC,
            BpfMapType::Hash => bpf_map_type::BPF_MAP_TYPE_HASH,
            BpfMapType::Array => bpf_map_type::BPF_MAP_TYPE_ARRAY,
            BpfMapType::ProgArray => bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY,
            BpfMapType::PerfEventArray => bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY,
            BpfMapType::PerCpuHash => bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH,
            BpfMapType::PerCpuArray => bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY,
            BpfMapType::StackTrace => bpf_map_type::BPF_MAP_TYPE_STACK_TRACE,
            BpfMapType::CgroupArray => bpf_map_type::BPF_MAP_TYPE_CGROUP_ARRAY,
            BpfMapType::LruHash => bpf_map_type::BPF_MAP_TYPE_LRU_HASH,
            BpfMapType::LruPerCpuHash => bpf_map_type::BPF_MAP_TYPE_LRU_PERCPU_HASH,
            BpfMapType::LpmTrie => bpf_map_type::BPF_MAP_TYPE_LPM_TRIE,
            BpfMapType::ArrayOfMaps => bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS,
            BpfMapType::HashOfMaps => bpf_map_type::BPF_MAP_TYPE_HASH_OF_MAPS,
            BpfMapType::Devmap => bpf_map_type::BPF_MAP_TYPE_DEVMAP,
            BpfMapType::Sockmap => bpf_map_type::BPF_MAP_TYPE_SOCKMAP,
            BpfMapType::Cpumap => bpf_map_type::BPF_MAP_TYPE_CPUMAP,
            BpfMapType::Xskmap => bpf_map_type::BPF_MAP_TYPE_XSKMAP,
            BpfMapType::Sockhash => bpf_map_type::BPF_MAP_TYPE_SOCKHASH,
            BpfMapType::CgroupStorageDeprecated => {
                bpf_map_type::BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED
            }
            BpfMapType::ReuseportSockarray => bpf_map_type::BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
            BpfMapType::PerCpuCgroupStorageDeprecated => {
                bpf_map_type::BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED
            }
            BpfMapType::Queue => bpf_map_type::BPF_MAP_TYPE_QUEUE,
            BpfMapType::Stack => bpf_map_type::BPF_MAP_TYPE_STACK,
            BpfMapType::SkStorage => bpf_map_type::BPF_MAP_TYPE_SK_STORAGE,
            BpfMapType::DevmapHash => bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH,
            BpfMapType::StructOps => bpf_map_type::BPF_MAP_TYPE_STRUCT_OPS,
            BpfMapType::Ringbuf => bpf_map_type::BPF_MAP_TYPE_RINGBUF,
            BpfMapType::InodeStorage => bpf_map_type::BPF_MAP_TYPE_INODE_STORAGE,
            BpfMapType::TaskStorage => bpf_map_type::BPF_MAP_TYPE_TASK_STORAGE,
            BpfMapType::BloomFilter => bpf_map_type::BPF_MAP_TYPE_BLOOM_FILTER,
            BpfMapType::UserRingbuf => bpf_map_type::BPF_MAP_TYPE_USER_RINGBUF,
            BpfMapType::CgroupStorage => bpf_map_type::BPF_MAP_TYPE_CGRP_STORAGE,
            BpfMapType::Arena => bpf_map_type::BPF_MAP_TYPE_ARENA,
        }
    }
}

impl TryFrom<u32> for crate::generated::bpf_map_type {
    type Error = InvalidMapTypeError;

    fn try_from(map_type: u32) -> Result<Self, Self::Error> {
        use crate::generated::bpf_map_type::*;
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
            x if x == BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED as u32 => {
                BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED
            }
            x if x == BPF_MAP_TYPE_CGRP_STORAGE as u32 => BPF_MAP_TYPE_CGRP_STORAGE,
            x if x == BPF_MAP_TYPE_REUSEPORT_SOCKARRAY as u32 => BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
            x if x == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED as u32 => {
                BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED
            }
            x if x == BPF_MAP_TYPE_QUEUE as u32 => BPF_MAP_TYPE_QUEUE,
            x if x == BPF_MAP_TYPE_STACK as u32 => BPF_MAP_TYPE_STACK,
            x if x == BPF_MAP_TYPE_SK_STORAGE as u32 => BPF_MAP_TYPE_SK_STORAGE,
            x if x == BPF_MAP_TYPE_DEVMAP_HASH as u32 => BPF_MAP_TYPE_DEVMAP_HASH,
            x if x == BPF_MAP_TYPE_STRUCT_OPS as u32 => BPF_MAP_TYPE_STRUCT_OPS,
            x if x == BPF_MAP_TYPE_RINGBUF as u32 => BPF_MAP_TYPE_RINGBUF,
            x if x == BPF_MAP_TYPE_INODE_STORAGE as u32 => BPF_MAP_TYPE_INODE_STORAGE,
            x if x == BPF_MAP_TYPE_TASK_STORAGE as u32 => BPF_MAP_TYPE_TASK_STORAGE,
            x if x == BPF_MAP_TYPE_BLOOM_FILTER as u32 => BPF_MAP_TYPE_BLOOM_FILTER,
            x if x == BPF_MAP_TYPE_USER_RINGBUF as u32 => BPF_MAP_TYPE_USER_RINGBUF,
            x if x == BPF_MAP_TYPE_CGRP_STORAGE as u32 => BPF_MAP_TYPE_CGRP_STORAGE,
            _ => return Err(InvalidMapTypeError { map_type }),
        })
    }
}

/// BTF definition of a map
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BtfMapDef {
    pub(crate) map_type: u32,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) map_flags: u32,
    pub(crate) pinning: PinningType,
    /// BTF type id of the map key
    pub btf_key_type_id: u32,
    /// BTF type id of the map value
    pub btf_value_type_id: u32,
}

/// The pinning type
///
/// Upon pinning a map, a file representation is created for the map,
/// so that the map can be alive and retrievable across sessions.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum PinningType {
    /// No pinning
    #[default]
    None = 0,
    /// Pin by the name
    ByName = 1,
}

/// The error type returned when failing to parse a [PinningType]
#[derive(Debug, thiserror::Error)]
pub enum PinningError {
    /// Unsupported pinning type
    #[error("unsupported pinning type `{pinning_type}`")]
    Unsupported {
        /// The unsupported pinning type
        pinning_type: u32,
    },
}

impl TryFrom<u32> for PinningType {
    type Error = PinningError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PinningType::None),
            1 => Ok(PinningType::ByName),
            pinning_type => Err(PinningError::Unsupported { pinning_type }),
        }
    }
}

/// Map definition in legacy BPF map declaration style
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct bpf_map_def {
    // minimum features required by old BPF programs
    /// The map type
    pub map_type: u32,
    /// The key_size
    pub key_size: u32,
    /// The value size
    pub value_size: u32,
    /// Max entry number
    pub max_entries: u32,
    /// Map flags
    pub map_flags: u32,
    // optional features
    /// Id
    pub id: u32,
    /// Pinning type
    pub pinning: PinningType,
}

/// The first five __u32 of `bpf_map_def` must be defined.
pub(crate) const MINIMUM_MAP_SIZE: usize = mem::size_of::<u32>() * 5;

/// Map data defined in `maps` or `.maps` sections
#[derive(Debug, Clone)]
pub enum Map {
    /// A map defined in the `maps` section
    Legacy(LegacyMap),
    /// A map defined in the `.maps` section
    Btf(BtfMap),
}

impl Map {
    /// Returns the map type
    pub fn map_type(&self) -> u32 {
        match self {
            Map::Legacy(m) => m.def.map_type,
            Map::Btf(m) => m.def.map_type,
        }
    }

    /// Returns the key size in bytes
    pub fn key_size(&self) -> u32 {
        match self {
            Map::Legacy(m) => m.def.key_size,
            Map::Btf(m) => m.def.key_size,
        }
    }

    /// Returns the value size in bytes
    pub fn value_size(&self) -> u32 {
        match self {
            Map::Legacy(m) => m.def.value_size,
            Map::Btf(m) => m.def.value_size,
        }
    }

    /// Set the value size in bytes
    pub fn set_value_size(&mut self, size: u32) {
        match self {
            Map::Legacy(m) => m.def.value_size = size,
            Map::Btf(m) => m.def.value_size = size,
        }
    }

    /// Returns the max entry number
    pub fn max_entries(&self) -> u32 {
        match self {
            Map::Legacy(m) => m.def.max_entries,
            Map::Btf(m) => m.def.max_entries,
        }
    }

    /// Sets the max entry number
    pub fn set_max_entries(&mut self, v: u32) {
        match self {
            Map::Legacy(m) => m.def.max_entries = v,
            Map::Btf(m) => m.def.max_entries = v,
        }
    }

    /// Returns the map flags
    pub fn map_flags(&self) -> u32 {
        match self {
            Map::Legacy(m) => m.def.map_flags,
            Map::Btf(m) => m.def.map_flags,
        }
    }

    /// Returns the pinning type of the map
    pub fn pinning(&self) -> PinningType {
        match self {
            Map::Legacy(m) => m.def.pinning,
            Map::Btf(m) => m.def.pinning,
        }
    }

    /// Returns the map data
    pub fn data(&self) -> &[u8] {
        match self {
            Map::Legacy(m) => &m.data,
            Map::Btf(m) => &m.data,
        }
    }

    /// Returns the map data as mutable
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        match self {
            Map::Legacy(m) => m.data.as_mut(),
            Map::Btf(m) => m.data.as_mut(),
        }
    }

    /// Returns the section index
    pub fn section_index(&self) -> usize {
        match self {
            Map::Legacy(m) => m.section_index,
            Map::Btf(m) => m.section_index,
        }
    }

    /// Returns the section kind.
    pub fn section_kind(&self) -> EbpfSectionKind {
        match self {
            Map::Legacy(m) => m.section_kind,
            Map::Btf(_) => EbpfSectionKind::BtfMaps,
        }
    }

    /// Returns the symbol index.
    ///
    /// This is `None` for data maps (.bss, .data and .rodata) since those don't
    /// need symbols in order to be relocated.
    pub fn symbol_index(&self) -> Option<usize> {
        match self {
            Map::Legacy(m) => m.symbol_index,
            Map::Btf(m) => Some(m.symbol_index),
        }
    }
}

/// A map declared with legacy BPF map declaration style, most likely from a `maps` section.
///
/// See [Drop support for legacy BPF map declaration syntax - Libbpf: the road to v1.0](https://github.com/libbpf/libbpf/wiki/Libbpf:-the-road-to-v1.0#drop-support-for-legacy-bpf-map-declaration-syntax)
/// for more info.
#[derive(Debug, Clone)]
pub struct LegacyMap {
    /// The definition of the map
    pub def: bpf_map_def,
    /// The section index
    pub section_index: usize,
    /// The section kind
    pub section_kind: EbpfSectionKind,
    /// The symbol index.
    ///
    /// This is None for data maps (.bss .data and .rodata).  We don't need
    /// symbols to relocate those since they don't contain multiple maps, but
    /// are just a flat array of bytes.
    pub symbol_index: Option<usize>,
    /// The map data
    pub data: Vec<u8>,
}

/// A BTF-defined map, most likely from a `.maps` section.
#[derive(Debug, Clone)]
pub struct BtfMap {
    /// The definition of the map
    pub def: BtfMapDef,
    pub(crate) section_index: usize,
    pub(crate) symbol_index: usize,
    pub(crate) data: Vec<u8>,
}
