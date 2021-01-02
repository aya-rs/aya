use std::{ffi::CString, io};
use thiserror::Error;

use crate::{obj, syscalls::bpf_create_map, RawFd};

mod hash_map;
pub use hash_map::*;

mod perf_map;
pub use perf_map::*;

#[derive(Error, Debug)]
pub enum MapError {
    #[error("invalid map type {map_type}")]
    InvalidMapType { map_type: u32 },

    #[error("invalid map name `{name}`")]
    InvalidName { name: String },

    #[error("the map `{name}` has not been created")]
    NotCreated { name: String },

    #[error("the map `{name}` has already been created")]
    AlreadyCreated { name: String },

    #[error("failed to create map `{name}`: {code}")]
    CreateFailed {
        name: String,
        code: i64,
        io_error: io::Error,
    },

    #[error("invalid key size {size}, expected {expected}")]
    InvalidKeySize { size: usize, expected: usize },

    #[error("invalid value size {size}, expected {expected}")]
    InvalidValueSize { size: usize, expected: usize },

    #[error("the BPF_MAP_UPDATE_ELEM syscall failed with code {code} io_error {io_error}")]
    UpdateElementFailed { code: i64, io_error: io::Error },

    #[error("the BPF_MAP_LOOKUP_ELEM syscall failed with code {code} io_error {io_error}")]
    LookupElementFailed { code: i64, io_error: io::Error },

    #[error("the BPF_MAP_DELETE_ELEM syscall failed with code {code} io_error {io_error}")]
    DeleteElementFailed { code: i64, io_error: io::Error },

    #[error(
        "the BPF_MAP_LOOKUP_AND_DELETE_ELEM syscall failed with code {code} io_error {io_error}"
    )]
    LookupAndDeleteElementFailed { code: i64, io_error: io::Error },

    #[error("the BPF_MAP_GET_NEXT_KEY syscall failed with code {code} io_error {io_error}")]
    GetNextKeyFailed { code: i64, io_error: io::Error },
}

#[derive(Debug)]
pub struct Map {
    pub(crate) obj: obj::Map,
    pub(crate) fd: Option<RawFd>,
}

impl Map {
    pub fn create(&mut self) -> Result<RawFd, MapError> {
        let name = self.obj.name.clone();
        if self.fd.is_some() {
            return Err(MapError::AlreadyCreated { name: name.clone() });
        }

        let c_name =
            CString::new(name.clone()).map_err(|_| MapError::InvalidName { name: name.clone() })?;

        let fd = bpf_create_map(&c_name, &self.obj.def).map_err(|(code, io_error)| {
            MapError::CreateFailed {
                name,
                code,
                io_error,
            }
        })? as RawFd;

        self.fd = Some(fd);

        Ok(fd)
    }

    pub(crate) fn fd_or_err(&self) -> Result<RawFd, MapError> {
        self.fd.ok_or_else(|| MapError::NotCreated {
            name: self.obj.name.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use libc::EFAULT;

    use crate::{
        bpf_map_def,
        generated::{bpf_cmd, bpf_map_type::BPF_MAP_TYPE_HASH},
        syscalls::{override_syscall, Syscall},
    };

    use super::*;

    fn new_obj_map(name: &str) -> obj::Map {
        obj::Map {
            name: name.to_string(),
            def: bpf_map_def {
                map_type: BPF_MAP_TYPE_HASH,
                key_size: 4,
                value_size: 4,
                max_entries: 1024,
                map_flags: 0,
            },
            section_index: 0,
            data: Vec::new(),
        }
    }

    fn new_map(name: &str) -> Map {
        Map {
            obj: new_obj_map(name),
            fd: None,
        }
    }

    #[test]
    fn test_create() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_CREATE,
                ..
            } => Ok(42),
            _ => Err((-1, io::Error::from_raw_os_error(EFAULT))),
        });

        let mut map = new_map("foo");
        assert!(matches!(map.create(), Ok(42)));
        assert_eq!(map.fd, Some(42));
        assert!(matches!(map.create(), Err(MapError::AlreadyCreated { .. })));
    }

    #[test]
    fn test_create_failed() {
        override_syscall(|_| {
            return Err((-42, io::Error::from_raw_os_error(EFAULT)));
        });

        let mut map = new_map("foo");
        let ret = map.create();
        assert!(matches!(ret, Err(MapError::CreateFailed { .. })));
        if let Err(MapError::CreateFailed {
            name,
            code,
            io_error,
        }) = ret
        {
            assert_eq!(name, "foo");
            assert_eq!(code, -42);
            assert_eq!(io_error.raw_os_error(), Some(EFAULT));
        }
        assert_eq!(map.fd, None);
    }
}
