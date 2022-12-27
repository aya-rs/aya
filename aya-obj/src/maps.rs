//! Map struct and type bindings.

use thiserror::Error;

/// Invalid map type encontered
pub struct InvalidMapTypeError {
    /// The map type
    pub map_type: u32,
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
            _ => return Err(InvalidMapTypeError { map_type }),
        })
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BtfMapDef {
    pub(crate) map_type: u32,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) map_flags: u32,
    pub(crate) pinning: PinningType,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PinningType {
    None = 0,
    ByName = 1,
}

#[derive(Debug, Error)]
pub enum PinningError {
    #[error("unsupported pinning type")]
    Unsupported,
}

impl TryFrom<u32> for PinningType {
    type Error = PinningError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PinningType::None),
            1 => Ok(PinningType::ByName),
            _ => Err(PinningError::Unsupported),
        }
    }
}

impl Default for PinningType {
    fn default() -> Self {
        PinningType::None
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct bpf_map_def {
    // minimum features required by old BPF programs
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    // optional features
    pub id: u32,
    pub pinning: PinningType,
}
