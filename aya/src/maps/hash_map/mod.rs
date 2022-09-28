//! Hash map types.
use std::mem;

use crate::{
    maps::MapError,
    sys::{bpf_map_delete_elem, bpf_map_update_elem},
};

#[allow(clippy::module_inception)]
mod hash_map;
mod per_cpu_hash_map;

pub use hash_map::*;
pub use per_cpu_hash_map::*;

use super::MapData;

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

pub(crate) fn insert<K, V>(
    map: &mut MapData,
    key: K,
    value: V,
    flags: u64,
) -> Result<(), MapError> {
    let fd = map.fd_or_err()?;
    bpf_map_update_elem(fd, Some(&key), &value, flags).map_err(|(_, io_error)| {
        MapError::SyscallError {
            call: "bpf_map_update_elem".to_owned(),
            io_error,
        }
    })?;

    Ok(())
}

pub(crate) fn remove<K>(map: &mut MapData, key: &K) -> Result<(), MapError> {
    let fd = map.fd_or_err()?;
    bpf_map_delete_elem(fd, key)
        .map(|_| ())
        .map_err(|(_, io_error)| MapError::SyscallError {
            call: "bpf_map_delete_elem".to_owned(),
            io_error,
        })
}
