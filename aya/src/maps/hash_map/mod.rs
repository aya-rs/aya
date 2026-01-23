//! Hash map types.
use std::os::fd::AsFd as _;

use crate::{
    Pod,
    maps::MapError,
    sys::{SyscallError, bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem},
};

#[expect(
    clippy::module_inception,
    reason = "module name matches the exported type"
)]
mod hash_map;
mod per_cpu_hash_map;

pub use hash_map::*;
pub use per_cpu_hash_map::*;

use super::MapData;

pub(crate) fn get<K: Pod, V: Pod>(map: &MapData, key: &K, flags: u64) -> Result<V, MapError> {
    let fd = map.fd().as_fd();
    let value = bpf_map_lookup_elem(fd, key, flags).map_err(|io_error| SyscallError {
        call: "bpf_map_lookup_elem",
        io_error,
    })?;
    value.ok_or(MapError::KeyNotFound)
}

pub(crate) fn insert<K: Pod, V: Pod>(
    map: &MapData,
    key: &K,
    value: &V,
    flags: u64,
) -> Result<(), MapError> {
    let fd = map.fd().as_fd();
    bpf_map_update_elem(fd, Some(key), value, flags)
        .map_err(|io_error| SyscallError {
            call: "bpf_map_update_elem",
            io_error,
        })
        .map_err(Into::into)
}

pub(crate) fn remove<K: Pod>(map: &MapData, key: &K) -> Result<(), MapError> {
    let fd = map.fd().as_fd();
    bpf_map_delete_elem(fd, key)
        .map_err(|io_error| SyscallError {
            call: "bpf_map_delete_elem",
            io_error,
        })
        .map_err(Into::into)
}
