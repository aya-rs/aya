//! A struct_ops map for implementing kernel callbacks.
//!
//! Struct_ops maps are special maps that allow implementing kernel subsystem callbacks
//! (like tcp_congestion_ops, hid_bpf_ops, sched_ext_ops) in BPF programs.
//!
//! Unlike regular maps that store key-value pairs, struct_ops maps represent a registration
//! mechanism for kernel callbacks. The "value" is the struct_ops structure with program FDs
//! filled in at the appropriate offsets.

use std::{
    borrow::{Borrow, BorrowMut},
    os::fd::AsFd as _,
};

use aya_obj::maps::StructOpsFuncInfo;
use log::debug;

use crate::{
    maps::{MapData, MapError, MapFd},
    programs::links::FdLink,
    sys::{SyscallError, bpf_map_update_elem_ptr, bpf_struct_ops_link_create},
};

/// A struct_ops map that implements kernel callbacks.
///
/// Struct_ops maps are used to register BPF programs as implementations of kernel
/// callbacks like `hid_bpf_ops` for HID device handling or `sched_ext_ops` for
/// custom schedulers.
///
/// # Example
///
/// ```no_run
/// # #[derive(thiserror::Error, Debug)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     BtfError(#[from] aya::BtfError),
/// #     #[error(transparent)]
/// #     Map(#[from] aya::maps::MapError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Ebpf(#[from] aya::EbpfError),
/// # }
/// # let mut bpf = aya::Ebpf::load_file("ebpf_programs.o")?;
/// use aya::maps::StructOpsMap;
/// use aya::Btf;
///
/// // Get the struct_ops map
/// let struct_ops: StructOpsMap<_> = bpf.map("my_struct_ops").unwrap().try_into()?;
///
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_MAP_TYPE_STRUCT_OPS")]
pub struct StructOpsMap<T> {
    pub(crate) inner: T,
}

impl<T: Borrow<MapData>> StructOpsMap<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        let _map_type = data.obj.map_type();

        Ok(Self { inner: map })
    }

    /// Returns the file descriptor of the map.
    pub fn fd(&self) -> &MapFd {
        self.inner.borrow().fd()
    }

    /// Returns information about the function pointer fields in this struct_ops.
    ///
    /// Each entry contains:
    /// - `member_name`: The name of the function pointer field in the struct
    /// - `member_offset`: The byte offset where the program FD should be written
    /// - `prog_name`: The name of the BPF program that implements this callback
    pub fn func_info(&self) -> Option<&[StructOpsFuncInfo]> {
        let data = self.inner.borrow();
        if let aya_obj::Map::StructOps(m) = data.obj() {
            Some(&m.func_info)
        } else {
            None
        }
    }

    /// Returns the type name of this struct_ops (e.g., "hid_bpf_ops").
    pub fn type_name(&self) -> Option<&str> {
        let data = self.inner.borrow();
        if let aya_obj::Map::StructOps(m) = data.obj() {
            Some(&m.type_name)
        } else {
            None
        }
    }

    /// Returns whether this is a link-based struct_ops.
    pub fn is_link(&self) -> bool {
        let data = self.inner.borrow();
        if let aya_obj::Map::StructOps(m) = data.obj() {
            m.is_link
        } else {
            false
        }
    }
}

impl<T: BorrowMut<MapData>> StructOpsMap<T> {
    /// Sets a program FD at the specified offset in the struct data.
    ///
    /// This is an internal method used by [`Ebpf::load_struct_ops`] to fill in
    /// program FDs for function pointer fields. Users should call
    /// `load_struct_ops()` instead of this method directly.
    ///
    /// [`Ebpf::load_struct_ops`]: crate::Ebpf::load_struct_ops
    #[allow(dead_code)]
    pub(crate) fn set_prog_fd(&mut self, offset: u32, fd: i32) -> Result<(), MapError> {
        self.set_field_i32(offset, fd)
    }

    /// Internal helper to write bytes at an offset in the struct data.
    ///
    /// Handles the data_offset adjustment for struct_ops maps and bounds checking.
    fn write_bytes_at_offset(&mut self, offset: u32, bytes: &[u8]) -> Result<(), MapError> {
        let map_data = self.inner.borrow_mut();
        let obj = map_data.obj_mut();

        // Get the data_offset from the struct_ops map - this is the offset of the
        // actual ops struct within the kernel wrapper struct
        let data_offset = if let aya_obj::Map::StructOps(m) = obj {
            m.data_offset
        } else {
            0
        };

        let data = obj.data_mut();
        // Add data_offset to the user-provided offset
        let actual_offset = (data_offset + offset) as usize;
        if actual_offset + bytes.len() > data.len() {
            return Err(MapError::OutOfBounds {
                index: actual_offset as u32,
                max_entries: data.len() as u32,
            });
        }

        data[actual_offset..actual_offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// Sets an i32 field at the specified byte offset in the struct data.
    ///
    /// This is useful for setting fields like `hid_id` in HID-BPF struct_ops
    /// before registration.
    ///
    /// # Arguments
    ///
    /// * `offset` - The byte offset where the value should be written
    /// * `value` - The i32 value to write
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use aya::maps::StructOpsMap;
    /// # fn example(struct_ops: &mut StructOpsMap<aya::maps::MapData>) -> Result<(), aya::maps::MapError> {
    /// // Set hid_id at offset 0 before registration
    /// struct_ops.set_field_i32(0, 189)?; // hid_id = 189
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_field_i32(&mut self, offset: u32, value: i32) -> Result<(), MapError> {
        self.write_bytes_at_offset(offset, &value.to_ne_bytes())
    }

    /// Sets a u32 field at the specified byte offset in the struct data.
    ///
    /// # Arguments
    ///
    /// * `offset` - The byte offset where the value should be written
    /// * `value` - The u32 value to write
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use aya::maps::StructOpsMap;
    /// # fn example(struct_ops: &mut StructOpsMap<aya::maps::MapData>) -> Result<(), aya::maps::MapError> {
    /// // Set flags at offset 4
    /// struct_ops.set_field_u32(4, 0)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_field_u32(&mut self, offset: u32, value: u32) -> Result<(), MapError> {
        self.write_bytes_at_offset(offset, &value.to_ne_bytes())
    }
}

impl<T: Borrow<MapData>> StructOpsMap<T> {
    /// Registers the struct_ops by calling bpf_map_update_elem.
    ///
    /// This should be called after [`Ebpf::load_struct_ops`] has been called to load
    /// all associated BPF programs and fill their file descriptors into the struct data.
    ///
    /// [`Ebpf::load_struct_ops`]: crate::Ebpf::load_struct_ops
    pub fn register(&self) -> Result<(), MapError> {
        let data = self.inner.borrow();
        let key: u32 = 0;
        let fd = data.fd().as_fd();

        let data_offset = if let aya_obj::Map::StructOps(m) = data.obj() {
            m.data_offset
        } else {
            0
        };

        debug!(
            "registering struct_ops map: data_len={} data_offset={}",
            data.obj().data().len(),
            data_offset
        );

        // For struct_ops, we need to update the map with the struct data.
        // The struct data should already have program FDs filled in.
        // Use a mutable copy to avoid casting away const from immutable data.
        let mut value = data.obj().data().to_vec();
        bpf_map_update_elem_ptr(fd, &key, value.as_mut_ptr(), 0)
            .map_err(|io_error| SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            })
            .map_err(MapError::from)?;

        Ok(())
    }

    /// Attaches a link-based struct_ops by creating a BPF link.
    ///
    /// For struct_ops maps created with the `BPF_F_LINK` flag (from `.struct_ops.link` section),
    /// this method creates a BPF link that activates the struct_ops. This must be called
    /// after [`register()`](Self::register) has been called to update the map data.
    ///
    /// For non-link struct_ops (from `.struct_ops` section), calling [`register()`](Self::register)
    /// alone is sufficient - no link is needed.
    ///
    /// # Returns
    ///
    /// An `FdLink` that keeps the struct_ops active. When the link is dropped (or its
    /// file descriptor is closed), the struct_ops will be detached.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use aya::maps::StructOpsMap;
    /// # fn example(struct_ops: &StructOpsMap<aya::maps::MapData>) -> Result<(), aya::maps::MapError> {
    /// // First register the struct_ops data
    /// struct_ops.register()?;
    ///
    /// // For link-based struct_ops, create the link to activate
    /// if struct_ops.is_link() {
    ///     let _link = struct_ops.attach()?;
    ///     // Keep the link alive to maintain attachment
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn attach(&self) -> Result<FdLink, MapError> {
        let data = self.inner.borrow();
        let fd = data.fd().as_fd();

        debug!("creating struct_ops link for map");

        let link_fd = bpf_struct_ops_link_create(fd)
            .map_err(|io_error| SyscallError {
                call: "bpf_link_create",
                io_error,
            })
            .map_err(MapError::from)?;

        Ok(FdLink::new(link_fd))
    }
}

impl TryFrom<MapData> for StructOpsMap<MapData> {
    type Error = MapError;

    fn try_from(map: MapData) -> Result<Self, Self::Error> {
        Self::new(map)
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use assert_matches::assert_matches;
    use aya_obj::generated::{bpf_cmd, bpf_map_type::BPF_MAP_TYPE_ARRAY};
    use libc::EFAULT;

    use super::*;
    use crate::{
        maps::{Map, test_utils::new_map},
        sys::{SysResult, Syscall, override_syscall},
    };

    fn sys_error(value: i32) -> SysResult {
        Err((-1, io::Error::from_raw_os_error(value)))
    }

    /// Creates a new aya_obj::Map::StructOps with the given parameters.
    fn new_struct_ops_obj_map(
        type_name: &str,
        data_size: usize,
        is_link: bool,
        func_info: Vec<aya_obj::maps::StructOpsFuncInfo>,
        data_offset: u32,
    ) -> aya_obj::Map {
        aya_obj::Map::StructOps(aya_obj::maps::StructOpsMap {
            type_name: type_name.to_string(),
            btf_type_id: 1,
            section_index: 0,
            symbol_index: 0,
            data: vec![0u8; data_size],
            is_link,
            func_info,
            data_offset,
        })
    }

    /// Creates a basic struct_ops map for testing.
    fn new_basic_struct_ops_obj_map() -> aya_obj::Map {
        new_struct_ops_obj_map("test_ops", 64, false, vec![], 0)
    }

    #[test]
    fn test_try_from_ok() {
        let map = new_map(new_basic_struct_ops_obj_map());
        let map = Map::StructOps(map);
        assert!(StructOpsMap::try_from(&map).is_ok());
    }

    #[test]
    fn test_try_from_wrong_map() {
        let map = new_map(crate::maps::test_utils::new_obj_map::<u32>(BPF_MAP_TYPE_ARRAY));
        let map = Map::Array(map);

        assert_matches!(
            StructOpsMap::try_from(&map),
            Err(MapError::InvalidMapType { .. })
        );
    }

    #[test]
    fn test_func_info() {
        let func_info = vec![
            aya_obj::maps::StructOpsFuncInfo {
                member_name: "callback1".to_string(),
                member_offset: 8,
                prog_name: "my_prog1".to_string(),
            },
            aya_obj::maps::StructOpsFuncInfo {
                member_name: "callback2".to_string(),
                member_offset: 16,
                prog_name: "my_prog2".to_string(),
            },
        ];
        let map = new_map(new_struct_ops_obj_map("test_ops", 64, false, func_info, 0));
        let struct_ops = StructOpsMap::new(&map).unwrap();

        let info = struct_ops.func_info().unwrap();
        assert_eq!(info.len(), 2);
        assert_eq!(info[0].member_name, "callback1");
        assert_eq!(info[0].member_offset, 8);
        assert_eq!(info[0].prog_name, "my_prog1");
        assert_eq!(info[1].member_name, "callback2");
        assert_eq!(info[1].member_offset, 16);
        assert_eq!(info[1].prog_name, "my_prog2");
    }

    #[test]
    fn test_type_name() {
        let map = new_map(new_struct_ops_obj_map("hid_bpf_ops", 64, false, vec![], 0));
        let struct_ops = StructOpsMap::new(&map).unwrap();

        assert_eq!(struct_ops.type_name(), Some("hid_bpf_ops"));
    }

    #[test]
    fn test_is_link_true() {
        let map = new_map(new_struct_ops_obj_map("test_ops", 64, true, vec![], 0));
        let struct_ops = StructOpsMap::new(&map).unwrap();

        assert!(struct_ops.is_link());
    }

    #[test]
    fn test_is_link_false() {
        let map = new_map(new_struct_ops_obj_map("test_ops", 64, false, vec![], 0));
        let struct_ops = StructOpsMap::new(&map).unwrap();

        assert!(!struct_ops.is_link());
    }

    #[test]
    fn test_set_field_i32_ok() {
        let mut map = new_map(new_basic_struct_ops_obj_map());
        let mut struct_ops = StructOpsMap::new(&mut map).unwrap();

        assert!(struct_ops.set_field_i32(0, 42).is_ok());

        // Verify the value was written correctly
        let data = map.obj().data();
        let value = i32::from_ne_bytes(data[0..4].try_into().unwrap());
        assert_eq!(value, 42);
    }

    #[test]
    fn test_set_field_out_of_bounds() {
        let mut map = new_map(new_struct_ops_obj_map("test_ops", 16, false, vec![], 0));
        let mut struct_ops = StructOpsMap::new(&mut map).unwrap();

        // Try to write at offset 20, which exceeds the 16 byte data size
        assert_matches!(
            struct_ops.set_field_i32(20, 42),
            Err(MapError::OutOfBounds { .. })
        );
    }

    #[test]
    fn test_set_field_with_data_offset() {
        // Create a map with data_offset = 8
        let mut map = new_map(new_struct_ops_obj_map("test_ops", 64, false, vec![], 8));
        let mut struct_ops = StructOpsMap::new(&mut map).unwrap();

        // Write at user offset 0, which should go to actual offset 8
        assert!(struct_ops.set_field_i32(0, 99).is_ok());

        // Verify the value was written at the correct actual offset (8)
        let data = map.obj().data();
        let value_at_0 = i32::from_ne_bytes(data[0..4].try_into().unwrap());
        let value_at_8 = i32::from_ne_bytes(data[8..12].try_into().unwrap());
        assert_eq!(value_at_0, 0); // Should be unchanged
        assert_eq!(value_at_8, 99); // Should have the written value
    }

    #[test]
    fn test_set_field_with_data_offset_out_of_bounds() {
        // Create a map with data_offset = 60, data size = 64
        // Writing 4 bytes at user offset 4 would go to actual offset 64, which is out of bounds
        let mut map = new_map(new_struct_ops_obj_map("test_ops", 64, false, vec![], 60));
        let mut struct_ops = StructOpsMap::new(&mut map).unwrap();

        assert_matches!(
            struct_ops.set_field_i32(4, 42),
            Err(MapError::OutOfBounds { .. })
        );
    }

    #[test]
    fn test_register_ok() {
        let map = new_map(new_basic_struct_ops_obj_map());
        let struct_ops = StructOpsMap::new(&map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_UPDATE_ELEM,
                ..
            } => Ok(0),
            _ => sys_error(EFAULT),
        });

        assert!(struct_ops.register().is_ok());
    }

    #[test]
    fn test_register_syscall_error() {
        let map = new_map(new_basic_struct_ops_obj_map());
        let struct_ops = StructOpsMap::new(&map).unwrap();

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            struct_ops.register(),
            Err(MapError::SyscallError(SyscallError { call: "bpf_map_update_elem", io_error })) if io_error.raw_os_error() == Some(EFAULT)
        );
    }

    #[test]
    fn test_attach_ok() {
        let map = new_map(new_struct_ops_obj_map("test_ops", 64, true, vec![], 0));
        let struct_ops = StructOpsMap::new(&map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_LINK_CREATE,
                ..
            } => Ok(crate::MockableFd::mock_signed_fd().into()),
            _ => sys_error(EFAULT),
        });

        let link = struct_ops.attach();
        assert!(link.is_ok());
    }

    #[test]
    fn test_attach_syscall_error() {
        let map = new_map(new_struct_ops_obj_map("test_ops", 64, true, vec![], 0));
        let struct_ops = StructOpsMap::new(&map).unwrap();

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            struct_ops.attach(),
            Err(MapError::SyscallError(SyscallError { call: "bpf_link_create", io_error })) if io_error.raw_os_error() == Some(EFAULT)
        );
    }
}
