//! An array of eBPF program file descriptors used as a jump table.

use std::{
    convert::{AsMut, AsRef},
    os::unix::prelude::{AsRawFd, RawFd},
};

use crate::{
    maps::{check_bounds, check_kv_size, MapData, MapError, MapKeys},
    programs::ProgramFd,
    sys::{bpf_map_delete_elem, bpf_map_update_elem},
};

/// An array of eBPF program file descriptors used as a jump table.
///
/// eBPF programs can jump to other programs calling `bpf_tail_call(ctx,
/// prog_array, index)`. You can use [`ProgramArray`] to configure which
/// programs correspond to which jump indexes.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.2.
///
/// # Examples
/// ```no_run
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use aya::maps::ProgramArray;
/// use aya::programs::CgroupSkb;
///
/// let mut prog_array = ProgramArray::try_from(bpf.take_map("JUMP_TABLE").unwrap())?;
/// let prog_0: &CgroupSkb = bpf.program("example_prog_0").unwrap().try_into()?;
/// let prog_0_fd =  prog_0.fd().unwrap();
/// let prog_1: &CgroupSkb = bpf.program("example_prog_1").unwrap().try_into()?;
/// let prog_1_fd = prog_1.fd().unwrap();
/// let prog_2: &CgroupSkb = bpf.program("example_prog_2").unwrap().try_into()?;
/// let prog_2_fd = prog_2.fd().unwrap();
/// let flags = 0;
///
/// // bpf_tail_call(ctx, JUMP_TABLE, 0) will jump to prog_0
/// prog_array.set(0, prog_0_fd, flags);
///
/// // bpf_tail_call(ctx, JUMP_TABLE, 1) will jump to prog_1
/// prog_array.set(1, prog_1_fd, flags);
///
/// // bpf_tail_call(ctx, JUMP_TABLE, 2) will jump to prog_2
/// prog_array.set(2, prog_2_fd, flags);
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_PROG_ARRAY")]
pub struct ProgramArray<T> {
    inner: T,
}

impl<T: AsRef<MapData>> ProgramArray<T> {
    pub(crate) fn new(map: T) -> Result<ProgramArray<T>, MapError> {
        let data = map.as_ref();
        check_kv_size::<u32, RawFd>(data)?;

        let _fd = data.fd_or_err()?;

        Ok(ProgramArray { inner: map })
    }

    /// An iterator over the indices of the array that point to a program. The iterator item type
    /// is `Result<u32, MapError>`.
    pub fn indices(&self) -> MapKeys<'_, u32> {
        MapKeys::new(self.inner.as_ref())
    }
}

impl<T: AsMut<MapData>> ProgramArray<T> {
    /// Sets the target program file descriptor for the given index in the jump table.
    ///
    /// When an eBPF program calls `bpf_tail_call(ctx, prog_array, index)`, control
    /// flow will jump to `program`.
    pub fn set(&mut self, index: u32, program: ProgramFd, flags: u64) -> Result<(), MapError> {
        let data = self.inner.as_mut();
        check_bounds(data, index)?;
        let fd = data.fd_or_err()?;
        let prog_fd = program.as_raw_fd();

        bpf_map_update_elem(fd, Some(&index), &prog_fd, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                io_error,
            }
        })?;
        Ok(())
    }

    /// Clears the value at index in the jump table.
    ///
    /// Calling `bpf_tail_call(ctx, prog_array, index)` on an index that has been cleared returns an
    /// error.
    pub fn clear_index(&mut self, index: &u32) -> Result<(), MapError> {
        let data = self.inner.as_mut();
        check_bounds(data, *index)?;
        let fd = self.inner.as_mut().fd_or_err()?;

        bpf_map_delete_elem(fd, index)
            .map(|_| ())
            .map_err(|(_, io_error)| MapError::SyscallError {
                call: "bpf_map_delete_elem".to_owned(),
                io_error,
            })
    }
}
