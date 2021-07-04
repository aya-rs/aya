use libc::{setsockopt, SOL_SOCKET};
use std::{
    io, mem,
    os::unix::prelude::{AsRawFd, RawFd},
};
use thiserror::Error;

use crate::{
    generated::{bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER, SO_ATTACH_BPF, SO_DETACH_BPF},
    programs::{load_program, Link, LinkRef, ProgramData, ProgramError},
};

/// The type returned when attaching a [`SocketFilter`] fails.
#[derive(Debug, Error)]
pub enum SocketFilterError {
    /// Setting the `SO_ATTACH_BPF` socket option failed.
    #[error("setsockopt SO_ATTACH_BPF failed")]
    SoAttachBpfError {
        #[source]
        io_error: io::Error,
    },
}

/// A program used to inspect and filter incoming packets on a socket.
///
/// [`SocketFilter`] programs are attached on sockets and can be used to inspect
/// and filter incoming packets.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.0.
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
/// # let mut bpf = aya::Bpf::load(&[], None)?;
/// use std::convert::TryInto;
/// use std::net::TcpStream;
/// use std::os::unix::io::AsRawFd;
/// use aya::programs::SocketFilter;
///
/// let mut client = TcpStream::connect("127.0.0.1:1234")?;
/// let prog: &mut SocketFilter = bpf.program_mut("filter_packets")?.try_into()?;
/// prog.load()?;
/// prog.attach(client.as_raw_fd())?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SOCKET_FILTER")]
pub struct SocketFilter {
    pub(crate) data: ProgramData,
}

impl SocketFilter {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::programs::Program::load).
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SOCKET_FILTER, &mut self.data)
    }

    /// Attaches the filter on the given socket.
    pub fn attach<T: AsRawFd>(&mut self, socket: T) -> Result<LinkRef, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let socket = socket.as_raw_fd();

        let ret = unsafe {
            setsockopt(
                socket,
                SOL_SOCKET,
                SO_ATTACH_BPF as i32,
                &prog_fd as *const _ as *const _,
                mem::size_of::<RawFd>() as u32,
            )
        };
        if ret < 0 {
            return Err(SocketFilterError::SoAttachBpfError {
                io_error: io::Error::last_os_error(),
            }
            .into());
        }

        Ok(self.data.link(SocketFilterLink {
            socket,
            prog_fd: Some(prog_fd),
        }))
    }
}

#[derive(Debug)]
struct SocketFilterLink {
    socket: RawFd,
    prog_fd: Option<RawFd>,
}

impl Link for SocketFilterLink {
    fn detach(&mut self) -> Result<(), ProgramError> {
        if let Some(fd) = self.prog_fd.take() {
            unsafe {
                setsockopt(
                    self.socket,
                    SOL_SOCKET,
                    SO_DETACH_BPF as i32,
                    &fd as *const _ as *const _,
                    mem::size_of::<RawFd>() as u32,
                );
            }
            Ok(())
        } else {
            Err(ProgramError::AlreadyDetached)
        }
    }
}

impl Drop for SocketFilterLink {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}
