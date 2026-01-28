//! Map struct and type bindings.

use alloc::vec::Vec;

use crate::{
    EbpfSectionKind, InvalidTypeBinding,
    generated::{bpf_map_type::BPF_MAP_TYPE_STRUCT_OPS, BPF_F_LINK},
};

impl TryFrom<u32> for crate::generated::bpf_map_type {
    type Error = InvalidTypeBinding<u32>;

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
            x if x == BPF_MAP_TYPE_ARENA as u32 => BPF_MAP_TYPE_ARENA,
            _ => return Err(InvalidTypeBinding { value: map_type }),
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
            0 => Ok(Self::None),
            1 => Ok(Self::ByName),
            pinning_type => Err(PinningError::Unsupported { pinning_type }),
        }
    }
}

/// Map definition in legacy BPF map declaration style
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
pub(crate) const MINIMUM_MAP_SIZE: usize = size_of::<u32>() * 5;

/// Map data defined in `maps` or `.maps` sections
#[derive(Debug, Clone)]
pub enum Map {
    /// A map defined in the `maps` section
    Legacy(LegacyMap),
    /// A map defined in the `.maps` section
    Btf(BtfMap),
    /// A struct_ops map defined in `.struct_ops` or `.struct_ops.link` sections
    StructOps(StructOpsMap),
}

impl Map {
    /// Returns the map type
    pub fn map_type(&self) -> u32 {
        match self {
            Self::Legacy(m) => m.def.map_type,
            Self::Btf(m) => m.def.map_type,
            Self::StructOps(_) => BPF_MAP_TYPE_STRUCT_OPS as u32,
        }
    }

    /// Returns the key size in bytes
    pub fn key_size(&self) -> u32 {
        match self {
            Self::Legacy(m) => m.def.key_size,
            Self::Btf(m) => m.def.key_size,
            // struct_ops maps always have key_size of 4
            Self::StructOps(_) => 4,
        }
    }

    /// Returns the value size in bytes
    pub fn value_size(&self) -> u32 {
        match self {
            Self::Legacy(m) => m.def.value_size,
            Self::Btf(m) => m.def.value_size,
            // For struct_ops, value_size is the size of the struct data
            Self::StructOps(m) => m.data.len() as u32,
        }
    }

    /// Set the value size in bytes
    pub fn set_value_size(&mut self, size: u32) {
        match self {
            Self::Legacy(m) => m.def.value_size = size,
            Self::Btf(m) => m.def.value_size = size,
            // struct_ops value_size is determined by the data, cannot be set
            Self::StructOps(_) => {}
        }
    }

    /// Returns the max entry number
    pub fn max_entries(&self) -> u32 {
        match self {
            Self::Legacy(m) => m.def.max_entries,
            Self::Btf(m) => m.def.max_entries,
            // struct_ops maps always have max_entries of 1
            Self::StructOps(_) => 1,
        }
    }

    /// Sets the max entry number
    pub fn set_max_entries(&mut self, v: u32) {
        match self {
            Self::Legacy(m) => m.def.max_entries = v,
            Self::Btf(m) => m.def.max_entries = v,
            // struct_ops max_entries is always 1, cannot be changed
            Self::StructOps(_) => {}
        }
    }

    /// Returns the map flags
    pub fn map_flags(&self) -> u32 {
        match self {
            Self::Legacy(m) => m.def.map_flags,
            Self::Btf(m) => m.def.map_flags,
            Self::StructOps(m) => {
                if m.is_link {
                    BPF_F_LINK
                } else {
                    0
                }
            }
        }
    }

    /// Returns the pinning type of the map
    pub fn pinning(&self) -> PinningType {
        match self {
            Self::Legacy(m) => m.def.pinning,
            Self::Btf(m) => m.def.pinning,
            Self::StructOps(_) => PinningType::None,
        }
    }

    /// Returns the map data
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Legacy(m) => &m.data,
            Self::Btf(m) => &m.data,
            Self::StructOps(m) => &m.data,
        }
    }

    /// Returns the map data as mutable
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        match self {
            Self::Legacy(m) => m.data.as_mut(),
            Self::Btf(m) => m.data.as_mut(),
            Self::StructOps(m) => m.data.as_mut(),
        }
    }

    /// Returns the section index
    pub fn section_index(&self) -> usize {
        match self {
            Self::Legacy(m) => m.section_index,
            Self::Btf(m) => m.section_index,
            Self::StructOps(m) => m.section_index,
        }
    }

    /// Returns the section kind.
    pub fn section_kind(&self) -> EbpfSectionKind {
        match self {
            Self::Legacy(m) => m.section_kind,
            Self::Btf(_) => EbpfSectionKind::BtfMaps,
            Self::StructOps(m) => {
                if m.is_link {
                    EbpfSectionKind::StructOpsLink
                } else {
                    EbpfSectionKind::StructOps
                }
            }
        }
    }

    /// Returns the symbol index.
    ///
    /// This is `None` for data maps (.bss, .data and .rodata) since those don't
    /// need symbols in order to be relocated.
    pub fn symbol_index(&self) -> Option<usize> {
        match self {
            Self::Legacy(m) => m.symbol_index,
            Self::Btf(m) => Some(m.symbol_index),
            Self::StructOps(m) => Some(m.symbol_index),
        }
    }

    /// Returns the BTF value type ID for struct_ops maps.
    ///
    /// This is the type ID of the struct_ops type in the program's BTF.
    pub fn btf_value_type_id(&self) -> Option<u32> {
        match self {
            Self::Legacy(_) => None,
            Self::Btf(m) => Some(m.def.btf_value_type_id),
            Self::StructOps(m) => Some(m.btf_type_id),
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

/// Information about a function pointer field in a struct_ops struct.
#[derive(Debug, Clone)]
pub struct StructOpsFuncInfo {
    /// The name of the struct member (function pointer field)
    pub member_name: alloc::string::String,
    /// The offset of this member within the struct (in bytes)
    pub member_offset: u32,
    /// The name of the BPF program that implements this callback
    pub prog_name: alloc::string::String,
}

/// A struct_ops map, defined in `.struct_ops` or `.struct_ops.link` sections.
///
/// Struct_ops maps are special BPF maps that allow implementing kernel subsystem
/// callbacks (like tcp_congestion_ops, hid_bpf_ops, sched_ext_ops) in BPF programs.
#[derive(Debug, Clone)]
pub struct StructOpsMap {
    /// The name of the struct_ops type (e.g., "hid_bpf_ops", "tcp_congestion_ops")
    pub type_name: alloc::string::String,
    /// BTF type ID of the struct_ops type
    pub btf_type_id: u32,
    /// The section index where this struct_ops was defined
    pub section_index: usize,
    /// The symbol index for this struct_ops variable
    pub symbol_index: usize,
    /// The struct instance data (will have program FDs filled in during loading)
    pub data: Vec<u8>,
    /// Whether this is a link-based struct_ops (from `.struct_ops.link` section)
    pub is_link: bool,
    /// Information about function pointer fields that need BPF programs
    pub func_info: Vec<StructOpsFuncInfo>,
    /// Byte offset of the `data` field within the kernel wrapper struct
    /// (e.g., offset of `data` in `bpf_struct_ops_hid_bpf_ops`)
    /// This offset must be added to all member offsets when writing to the struct.
    pub data_offset: u32,
}
