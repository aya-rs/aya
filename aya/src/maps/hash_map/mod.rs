//! Hash map types.
use std::os::fd::AsFd as _;

use crate::{
    maps::MapError,
    sys::{bpf_map_delete_elem, bpf_map_update_elem, SyscallError},
    Pod,
};

#[allow(clippy::module_inception)]
mod hash_map;
mod per_cpu_hash_map;

pub use hash_map::*;
pub use per_cpu_hash_map::*;

use super::MapData;

pub(crate) fn insert<K: Pod, V: Pod>(
    map: &MapData,
    key: &K,
    value: &V,
    flags: u64,
) -> Result<(), MapError> {
    let fd = map.fd().as_fd();
    bpf_map_update_elem(fd, Some(key), value, flags).map_err(|(_, io_error)| SyscallError {
        call: "bpf_map_update_elem",
        io_error,
    })?;

    Ok(())
}

pub(crate) fn remove<K: Pod>(map: &MapData, key: &K) -> Result<(), MapError> {
    let fd = map.fd().as_fd();
    bpf_map_delete_elem(fd, key)
        .map(|_| ())
        .map_err(|(_, io_error)| {
            SyscallError {
                call: "bpf_map_delete_elem",
                io_error,
            }
            .into()
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
