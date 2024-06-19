//! A collection of ebpf feature helpers that can determine kernel capabilities.
//!
//! Basing kernel capabilities on kernel version is not sufficient since some
//! distros will backport ebpf functionality to older kernels.
//!

use std::mem::size_of;

use aya_obj::{generated::bpf_map_type, maps::LegacyMap, EbpfSectionKind, Map};
use thiserror::Error;

use crate::maps::{MapData, MapError};

/// An error ocurred working with a pinned BPF object.
#[derive(Error, Debug)]
pub enum FeatureError {
    /// An error ocurred making a syscall.
    #[error(transparent)]
    MapError(#[from] MapError),
}

/// Result type used for the feature helpers
pub type Result<T> = std::result::Result<T, FeatureError>;

fn probe_map_create(map_type: bpf_map_type) -> Result<bool> {

    let def = Map::Legacy(LegacyMap {
        def: aya_obj::maps::bpf_map_def {
             map_type: map_type as u32,
             key_size: size_of::<u32>() as u32,
             value_size: size_of::<u32>() as u32,
             max_entries: 1,
             map_flags: 0,
             id: 0,
             pinning: aya_obj::maps::PinningType::None,
        },
        section_index: 0,
        section_kind: EbpfSectionKind::Undefined,
        symbol_index: None,
        data: vec![],
    });

    let map = MapData::create(def, "", None);

    match map {
        Ok(_) => Ok(true),
        Err(e) => match e {
            MapError::CreateError { name: _, code: _, ref io_error } => match io_error.kind() {
                std::io::ErrorKind::InvalidInput => {
                    // InvalidInput is the return kind for unsupported map
                    Ok(false)
                }
                _ => Err(FeatureError::MapError(e))
            }
            _ => {
                Err(FeatureError::MapError(e))
            }
        }
    }
}

/// Returns `true` if `map_type` is supported.
///
/// # Example
///
/// ```no_run
/// use aya::features::is_map_type_supported;
///
/// if is_map_type_supported(bpf_map_type::BPF_MAP_TYPE_RINGBUF)? {
///     println!("Ringbuf is supported!");
/// }
/// ```
pub fn is_map_type_supported(map_type: bpf_map_type) -> Result<bool> {
    probe_map_create(map_type)
}

/// Returns `true` if the kernel supports `Ringbuf` (`BPF_MAP_TYPE_RINGBUF`).
///
/// # Example
///
/// ```no_run
/// use aya::features::is_map_type_ringbuf_supported;
///
/// if is_map_type_ringbuf_supported()? {
///     println!("Ringbuf is supported!");
/// }
/// ```
pub fn is_map_type_ringbuf_supported() -> Result<bool> {
    probe_map_create(bpf_map_type::BPF_MAP_TYPE_RINGBUF)
}

#[cfg(test)]
mod tests {
    use std::os::fd::IntoRawFd;

    use aya_obj::generated::bpf_cmd;

    use crate::sys::{override_syscall, Syscall};

    use super::*;

    #[test]
    fn test_probe_map_create_success() {
        override_syscall(|syscall| {
            match syscall {
                Syscall::Ebpf{cmd, attr} => {
                    assert_eq!(cmd, bpf_cmd::BPF_MAP_CREATE);

                    let u = unsafe { &mut attr.__bindgen_anon_1 };

                    assert_eq!(u.map_type, bpf_map_type::BPF_MAP_TYPE_RINGBUF as u32);
                    assert_eq!(u.key_size, size_of::<u32>() as u32);
                    assert_eq!(u.value_size, size_of::<u32>() as u32);
                }
                _ => {
                    panic!();
                }
            }

            let fd = std::fs::File::open("/dev/null").unwrap().into_raw_fd();
            Ok(fd as i64)
        });

        let supported = probe_map_create(bpf_map_type::BPF_MAP_TYPE_RINGBUF).unwrap();
        assert!(supported);
    }

    #[test]
    fn test_probe_map_create_failed() {
        override_syscall(|syscall| {
            match syscall {
                Syscall::Ebpf{cmd, attr} => {
                    assert_eq!(cmd, bpf_cmd::BPF_MAP_CREATE);

                    let u = unsafe { &mut attr.__bindgen_anon_1 };

                    assert_eq!(u.map_type, bpf_map_type::BPF_MAP_TYPE_RINGBUF as u32);
                    assert_eq!(u.key_size, size_of::<u32>() as u32);
                    assert_eq!(u.value_size, size_of::<u32>() as u32);
                }
                _ => {
                    panic!();
                }
            }

            Err((-1, std::io::Error::from_raw_os_error(libc::EINVAL)))
        });

        let supported = probe_map_create(bpf_map_type::BPF_MAP_TYPE_RINGBUF).unwrap();
        assert!(!supported);
    }

    #[test]
    fn test_probe_map_create_unknown_error() {
        override_syscall(|syscall| {
            match syscall {
                Syscall::Ebpf{cmd, attr} => {
                    assert_eq!(cmd, bpf_cmd::BPF_MAP_CREATE);

                    let u = unsafe { &mut attr.__bindgen_anon_1 };

                    assert_eq!(u.map_type, bpf_map_type::BPF_MAP_TYPE_RINGBUF as u32);
                    assert_eq!(u.key_size, size_of::<u32>() as u32);
                    assert_eq!(u.value_size, size_of::<u32>() as u32);
                }
                _ => {
                    panic!();
                }
            }

            Err((-1, std::io::Error::from_raw_os_error(libc::EPERM)))
        });

        assert!(probe_map_create(bpf_map_type::BPF_MAP_TYPE_RINGBUF).is_err());
    }
}