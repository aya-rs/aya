//! Hash map types.
use std::mem;

use crate::{
    maps::{Map, MapError},
    sys::{bpf_map_delete_elem, bpf_map_update_elem},
};

#[allow(clippy::module_inception)]
mod hash_map;
mod per_cpu_hash_map;

pub use hash_map::*;
pub use per_cpu_hash_map::*;

pub(crate) fn check_kv_size<K, V>(map: &Map) -> Result<(), MapError> {
    let size = mem::size_of::<K>();
    let expected = map.obj.def.key_size as usize;
    if size != expected {
        return Err(MapError::InvalidKeySize { size, expected });
    }
    let size = mem::size_of::<V>();
    let expected = map.obj.def.value_size as usize;
    if size != expected {
        return Err(MapError::InvalidValueSize { size, expected });
    };
    Ok(())
}

pub(crate) fn insert<K, V>(map: &mut Map, key: K, value: V, flags: u64) -> Result<(), MapError> {
    let fd = map.fd_or_err()?;
    bpf_map_update_elem(fd, &key, &value, flags).map_err(|(code, io_error)| {
        MapError::SyscallError {
            call: "bpf_map_update_elem".to_owned(),
            code,
            io_error,
        }
    })?;

    Ok(())
}

pub(crate) fn remove<K>(map: &mut Map, key: &K) -> Result<(), MapError> {
    let fd = map.fd_or_err()?;
    bpf_map_delete_elem(fd, key)
        .map(|_| ())
        .map_err(|(code, io_error)| MapError::SyscallError {
            call: "bpf_map_delete_elem".to_owned(),
            code,
            io_error,
        })
}
