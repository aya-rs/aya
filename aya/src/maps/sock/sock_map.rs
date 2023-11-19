//! An array of eBPF program file descriptors used as a jump table.

use std::{
    borrow::{Borrow, BorrowMut},
    os::fd::{AsFd as _, AsRawFd, RawFd},
};

use crate::{
    maps::{check_bounds, check_kv_size, sock::SockMapFd, MapData, MapError, MapFd, MapKeys},
    sys::{bpf_map_delete_elem, bpf_map_update_elem, SyscallError},
};

/// An array of TCP or UDP sockets.
///
/// A `SockMap` is used to store TCP or UDP sockets. eBPF programs can then be
/// attached to the map to inspect, filter or redirect network buffers on those
/// sockets.
///
/// A `SockMap` can also be used to redirect packets to sockets contained by the
/// map using `bpf_redirect_map()`, `bpf_sk_redirect_map()` etc.    
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.14.
///
/// # Examples
///
/// ```no_run
/// # #[derive(Debug, thiserror::Error)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     IO(#[from] std::io::Error),
/// #     #[error(transparent)]
/// #     Map(#[from] aya::maps::MapError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use aya::maps::SockMap;
/// use aya::programs::SkSkb;
///
/// let intercept_ingress = SockMap::try_from(bpf.map("INTERCEPT_INGRESS").unwrap())?;
/// let map_fd = intercept_ingress.fd().try_clone()?;
///
/// let prog: &mut SkSkb = bpf.program_mut("intercept_ingress_packet").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(&map_fd)?;
///
/// # Ok::<(), Error>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_SOCKMAP")]
pub struct SockMap<T> {
    pub(crate) inner: T,
}

impl<T: Borrow<MapData>> SockMap<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<u32, RawFd>(data)?;

        Ok(Self { inner: map })
    }

    /// An iterator over the indices of the array that point to a program. The iterator item type
    /// is `Result<u32, MapError>`.
    pub fn indices(&self) -> MapKeys<'_, u32> {
        MapKeys::new(self.inner.borrow())
    }

    /// Returns the map's file descriptor.
    ///
    /// The returned file descriptor can be used to attach programs that work with
    /// socket maps, like [`SkMsg`](crate::programs::SkMsg) and [`SkSkb`](crate::programs::SkSkb).
    pub fn fd(&self) -> &SockMapFd {
        let fd: &MapFd = self.inner.borrow().fd();
        // TODO(https://github.com/rust-lang/rfcs/issues/3066): avoid this unsafe.
        // SAFETY: `SockMapFd` is #[repr(transparent)] over `MapFd`.
        unsafe { std::mem::transmute(&fd) }
    }
}

impl<T: BorrowMut<MapData>> SockMap<T> {
    /// Stores a socket into the map.
    pub fn set<I: AsRawFd>(&mut self, index: u32, socket: &I, flags: u64) -> Result<(), MapError> {
        let data = self.inner.borrow_mut();
        let fd = data.fd().as_fd();
        check_bounds(data, index)?;
        bpf_map_update_elem(fd, Some(&index), &socket.as_raw_fd(), flags).map_err(
            |(_, io_error)| SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            },
        )?;
        Ok(())
    }

    /// Removes the socket stored at `index` from the map.
    pub fn clear_index(&mut self, index: &u32) -> Result<(), MapError> {
        let data = self.inner.borrow_mut();
        let fd = data.fd().as_fd();
        check_bounds(data, *index)?;
        bpf_map_delete_elem(fd, index)
            .map(|_| ())
            .map_err(|(_, io_error)| {
                SyscallError {
                    call: "bpf_map_delete_elem",
                    io_error,
                }
                .into()
            })
    }
}
