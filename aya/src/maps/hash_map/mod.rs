//! Hash map types.
use std::os::fd::AsRawFd;

use crate::{
    maps::MapError,
    sys::{bpf_map_delete_elem, bpf_map_update_elem},
    Pod,
};

#[allow(clippy::module_inception)]
mod hash_map;
mod per_cpu_hash_map;

pub use hash_map::*;
pub use per_cpu_hash_map::*;

use super::MapData;

pub(crate) fn insert<K: Pod, V: Pod>(
    map: &mut MapData,
    key: &K,
    value: &V,
    flags: u64,
) -> Result<(), MapError> {
    let fd = map.fd_or_err()?;
    // TODO (AM)
    bpf_map_update_elem(fd.as_raw_fd(), Some(key), value, flags).map_err(|(_, io_error)| {
        MapError::SyscallError {
            call: "bpf_map_update_elem".to_owned(),
            io_error,
        }
    })?;

    Ok(())
}

pub(crate) fn remove<K: Pod>(map: &mut MapData, key: &K) -> Result<(), MapError> {
    let fd = map.fd_or_err()?;
    // TODO (AM)
    bpf_map_delete_elem(fd.as_raw_fd(), key)
        .map(|_| ())
        .map_err(|(_, io_error)| MapError::SyscallError {
            call: "bpf_map_delete_elem".to_owned(),
            io_error,
        })
}
