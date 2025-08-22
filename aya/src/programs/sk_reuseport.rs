//! Socket load balancing with SO_REUSEPORT.
use std::{
    io, mem,
    os::fd::{AsFd, AsRawFd as _, RawFd},
};

use aya_obj::generated::{
    bpf_attach_type::BPF_SK_REUSEPORT_SELECT, bpf_prog_type::BPF_PROG_TYPE_SK_REUSEPORT,
};
use libc::{SOL_SOCKET, setsockopt};
use thiserror::Error;

use crate::programs::{Link, ProgramData, ProgramError, ProgramType, id_as_key, load_program};

/// SO_ATTACH_REUSEPORT_EBPF socket option constant.
const SO_ATTACH_REUSEPORT_EBPF: i32 = 52;

/// SO_DETACH_REUSEPORT_BPF socket option constant.
const SO_DETACH_REUSEPORT_BPF: i32 = 68;

/// The type returned when attaching a [`SkReuseport`] fails.
#[derive(Debug, Error)]
pub enum SkReuseportError {
    /// Setting the `SO_ATTACH_REUSEPORT_EBPF` socket option failed.
    #[error("setsockopt SO_ATTACH_REUSEPORT_EBPF failed")]
    SoAttachReuseportEbpfError {
        /// original [`io::Error`]
        #[source]
        io_error: io::Error,
    },
}

/// A program used to select a socket within a SO_REUSEPORT group.
///
/// [`SkReuseport`] programs are attached to sockets with SO_REUSEPORT set to
/// provide programmable socket selection when multiple sockets are listening
/// on the same port. The program decides which socket in the reuseport group
/// should handle an incoming connection or packet.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.19.
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
/// #     Ebpf(#[from] aya::EbpfError)
/// # }
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use std::net::TcpListener;
/// use aya::programs::SkReuseport;
///
/// let listener = TcpListener::bind("127.0.0.1:8080")?;
/// let program: &mut SkReuseport = bpf.program_mut("select_socket").unwrap().try_into()?;
/// program.load()?;
/// program.attach(listener)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SK_REUSEPORT")]
pub struct SkReuseport {
    pub(crate) data: ProgramData<SkReuseportLink>,
}

impl SkReuseport {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::SkReuseport;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(BPF_SK_REUSEPORT_SELECT);
        load_program(BPF_PROG_TYPE_SK_REUSEPORT, &mut self.data)
    }

    /// Attaches the program to the given socket.
    ///
    /// The returned value can be used to detach, see [SkReuseport::detach].
    pub fn attach<T: AsFd>(&mut self, socket: T) -> Result<SkReuseportLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let prog_fd = prog_fd.as_raw_fd();
        let socket = socket.as_fd();
        let socket = socket.as_raw_fd();

        let ret = unsafe {
            setsockopt(
                socket,
                SOL_SOCKET,
                SO_ATTACH_REUSEPORT_EBPF,
                &prog_fd as *const _ as *const _,
                mem::size_of::<RawFd>() as u32,
            )
        };
        if ret < 0 {
            return Err(SkReuseportError::SoAttachReuseportEbpfError {
                io_error: io::Error::last_os_error(),
            }
            .into());
        }

        self.data.links.insert(SkReuseportLink { socket, prog_fd })
    }

    /// Detaches the program.
    ///
    /// See [`Self::attach`].
    pub fn detach(&mut self, link_id: SkReuseportLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided `link_id`.
    ///
    /// The caller takes the responsibility of managing the lifetime of the link. When the returned
    /// [`SkReuseportLink`] is dropped, the link is detached.
    pub fn take_link(
        &mut self,
        link_id: SkReuseportLinkId,
    ) -> Result<SkReuseportLink, ProgramError> {
        self.data.links.forget(link_id)
    }
}

/// The type returned by [`SkReuseport::attach`]. Can be passed to [`SkReuseport::detach`].
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct SkReuseportLinkId(RawFd, RawFd);

/// A SkReuseport Link
#[derive(Debug)]
pub struct SkReuseportLink {
    socket: RawFd,
    prog_fd: RawFd,
}

impl Link for SkReuseportLink {
    type Id = SkReuseportLinkId;

    fn id(&self) -> Self::Id {
        SkReuseportLinkId(self.socket, self.prog_fd)
    }

    fn detach(self) -> Result<(), ProgramError> {
        unsafe {
            setsockopt(
                self.socket,
                SOL_SOCKET,
                SO_DETACH_REUSEPORT_BPF,
                &self.prog_fd as *const _ as *const _,
                mem::size_of::<RawFd>() as u32,
            );
        }
        Ok(())
    }
}

id_as_key!(SkReuseportLink, SkReuseportLinkId);
