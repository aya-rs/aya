//! Metadata information about an eBPF map.

use std::{
    ffi::CString,
    num::NonZeroU32,
    os::fd::{AsFd as _, BorrowedFd},
    path::Path,
};

use aya_obj::generated::{bpf_map_info, bpf_map_type};

use super::{MapError, MapFd};
use crate::{
    sys::{
        bpf_get_object, bpf_map_get_fd_by_id, bpf_map_get_info_by_fd, iter_map_ids, SyscallError,
    },
    util::bytes_of_bpf_name,
    FEATURES,
};

/// Provides information about a loaded map, like name, id and size.
#[doc(alias = "bpf_map_info")]
#[derive(Debug)]
pub struct MapInfo(pub(crate) bpf_map_info);

impl MapInfo {
    pub(crate) fn new_from_fd(fd: BorrowedFd<'_>) -> Result<Self, MapError> {
        let info = bpf_map_get_info_by_fd(fd.as_fd())?;
        Ok(Self(info))
    }

    /// Loads map info from a map ID.
    ///
    /// Uses kernel v4.13 features.
    pub fn from_id(id: u32) -> Result<Self, MapError> {
        bpf_map_get_fd_by_id(id)
            .map_err(MapError::from)
            .and_then(|fd| Self::new_from_fd(fd.as_fd()))
    }

    /// The map type as defined by the linux kernel enum [`bpf_map_type`].
    ///
    /// Introduced in kernel v4.13.
    pub fn map_type(&self) -> bpf_map_type {
        bpf_map_type::try_from(self.0.type_).unwrap_or(bpf_map_type::__MAX_BPF_MAP_TYPE)
    }

    /// The unique ID for this map.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.13.
    pub fn id(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.0.id)
    }

    /// The key size for this map in bytes.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.13.
    pub fn key_size(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.0.key_size)
    }

    /// The value size for this map in bytes.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.13.
    pub fn value_size(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.0.value_size)
    }

    /// The maximum number of entries in this map.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.13.
    pub fn max_entries(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.0.max_entries)
    }

    /// The flags used in loading this map.
    ///
    /// Introduced in kernel v4.13.
    pub fn map_flags(&self) -> u32 {
        self.0.map_flags
    }

    /// The name of the map, limited to 16 bytes.
    ///
    /// Introduced in kernel v4.15.
    pub fn name(&self) -> &[u8] {
        bytes_of_bpf_name(&self.0.name)
    }

    /// The name of the map as a &str.
    ///
    /// `None` is returned if the name was not valid unicode or if field is not available.
    ///
    /// Introduced in kernel v4.15.
    pub fn name_as_str(&self) -> Option<&str> {
        let name = std::str::from_utf8(self.name()).ok();
        if let Some(name_str) = name {
            // Char in program name was introduced in the same commit as map name
            if FEATURES.bpf_name() || !name_str.is_empty() {
                return name;
            }
        }
        None
    }

    /// Returns a file descriptor referencing the map.
    ///
    /// The returned file descriptor can be closed at any time and doing so does
    /// not influence the life cycle of the map.
    ///
    /// Uses kernel v4.13 features.
    pub fn fd(&self) -> Result<MapFd, MapError> {
        let Self(info) = self;
        let fd = bpf_map_get_fd_by_id(info.id)?;
        Ok(MapFd::from_fd(fd))
    }

    /// Loads a map from a pinned path in bpffs.
    ///
    /// Uses kernel v4.4 and v4.13 features.
    pub fn from_pin<P: AsRef<Path>>(path: P) -> Result<Self, MapError> {
        use std::os::unix::ffi::OsStrExt as _;

        // TODO: avoid this unwrap by adding a new error variant.
        let path_string = CString::new(path.as_ref().as_os_str().as_bytes()).unwrap();
        let fd = bpf_get_object(&path_string).map_err(|(_, io_error)| SyscallError {
            call: "BPF_OBJ_GET",
            io_error,
        })?;

        Self::new_from_fd(fd.as_fd())
    }
}

/// Returns an iterator over all loaded bpf maps.
///
/// This differs from [`crate::Ebpf::maps`] since it will return all maps
/// listed on the host system and not only maps for a specific [`crate::Ebpf`] instance.
///
/// Uses kernel v4.13 features.
///
/// # Example
/// ```
/// # use aya::maps::loaded_maps;
///
/// for m in loaded_maps() {
///     match m {
///         Ok(map) => println!("{:?}", map.name_as_str()),
///         Err(e) => println!("Error iterating maps: {:?}", e),
///     }
/// }
/// ```
///
/// # Errors
///
/// Returns [`MapError::SyscallError`] if any of the syscalls required to either get
/// next map id, get the map fd, or the [`MapInfo`] fail. In cases where
/// iteration can't be performed, for example the caller does not have the necessary privileges,
/// a single item will be yielded containing the error that occurred.
pub fn loaded_maps() -> impl Iterator<Item = Result<MapInfo, MapError>> {
    iter_map_ids().map(|id| {
        let id = id?;
        MapInfo::from_id(id)
    })
}
