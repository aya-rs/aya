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

use log::debug;

use aya_obj::maps::StructOpsFuncInfo;

use crate::{
    maps::{MapData, MapError, MapFd},
    sys::{bpf_map_update_elem_ptr, SyscallError},
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
    /// This is used to fill in the program FDs for function pointer fields
    /// before registering the struct_ops.
    ///
    /// # Arguments
    ///
    /// * `offset` - The byte offset where the program FD should be written
    /// * `fd` - The file descriptor of the loaded BPF program
    pub fn set_prog_fd(&mut self, offset: u32, fd: i32) -> Result<(), MapError> {
        self.set_field_i32(offset, fd)
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
        if actual_offset + 4 > data.len() {
            return Err(MapError::OutOfBounds {
                index: actual_offset as u32,
                max_entries: data.len() as u32,
            });
        }

        data[actual_offset..actual_offset + 4].copy_from_slice(&value.to_ne_bytes());
        Ok(())
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
        if actual_offset + 4 > data.len() {
            return Err(MapError::OutOfBounds {
                index: actual_offset as u32,
                max_entries: data.len() as u32,
            });
        }

        data[actual_offset..actual_offset + 4].copy_from_slice(&value.to_ne_bytes());
        Ok(())
    }
}

impl<T: Borrow<MapData>> StructOpsMap<T> {
    /// Registers the struct_ops by calling bpf_map_update_elem.
    ///
    /// This should be called after all associated BPF programs have been loaded
    /// and their file descriptors have been filled into the struct data using
    /// [`set_prog_fd`](Self::set_prog_fd).
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

        // For struct_ops, we need to update the map with the struct data
        // The struct data should already have program FDs filled in
        bpf_map_update_elem_ptr(fd, &key, data.obj().data().as_ptr() as *mut u8, 0)
            .map_err(|io_error| SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            })
            .map_err(MapError::from)?;

        Ok(())
    }
}

impl TryFrom<MapData> for StructOpsMap<MapData> {
    type Error = MapError;

    fn try_from(map: MapData) -> Result<Self, Self::Error> {
        Self::new(map)
    }
}
