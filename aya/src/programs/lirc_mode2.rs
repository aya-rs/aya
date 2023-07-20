//! Lirc programs.
use std::os::fd::{AsFd, AsRawFd, RawFd};

use crate::{
    generated::{bpf_attach_type::BPF_LIRC_MODE2, bpf_prog_type::BPF_PROG_TYPE_LIRC_MODE2},
    programs::{load_program, query, Link, ProgramData, ProgramError, ProgramInfo},
    sys::{bpf_prog_attach, bpf_prog_detach, bpf_prog_get_fd_by_id, bpf_prog_get_info_by_fd},
};

use libc::{close, dup};

/// A program used to decode IR into key events for a lirc device.
///
/// [`LircMode2`] programs can be used to inspect infrared pulses, spaces,
/// and timeouts received by a lirc IR receiver.
///
/// [lirc]: https://www.kernel.org/doc/html/latest/userspace-api/media/rc/lirc-dev.html
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.18.
///
/// # Examples
///
/// ```no_run
/// # #[derive(thiserror::Error, Debug)]
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
/// use std::fs::File;
/// use aya::programs::LircMode2;
///
/// let file = File::open("/dev/lirc0")?;
/// let mut bpf = aya::Bpf::load_file("imon_rsc.o")?;
/// let decoder: &mut LircMode2 = bpf.programs.get_mut("imon_rsc").unwrap().try_into().unwrap();
/// decoder.load(bpf.btf_fd.as_ref())?;
/// decoder.attach(file)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_LIRC_MODE2")]
pub struct LircMode2 {
    pub(crate) data: ProgramData<LircLink>,
}

impl LircMode2 {
    /// Loads the program inside the kernel.
    pub fn load(&mut self, btf_fd: Option<impl AsFd>) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_LIRC_MODE2, &mut self.data, btf_fd)
    }

    /// Attaches the program to the given lirc device.
    ///
    /// The returned value can be used to detach, see [LircMode2::detach].
    pub fn attach<T: AsRawFd>(&mut self, lircdev: T) -> Result<LircLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let lircdev_fd = lircdev.as_raw_fd();

        bpf_prog_attach(prog_fd, lircdev_fd, BPF_LIRC_MODE2).map_err(|(_, io_error)| {
            ProgramError::SyscallError {
                call: "bpf_prog_attach",
                io_error,
            }
        })?;

        self.data.links.insert(LircLink::new(prog_fd, lircdev_fd))
    }

    /// Detaches the program.
    ///
    /// See [LircMode2::attach].
    pub fn detach(&mut self, link_id: LircLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: LircLinkId) -> Result<LircLink, ProgramError> {
        self.data.take_link(link_id)
    }

    /// Queries the lirc device for attached programs.
    pub fn query<T: AsRawFd>(target_fd: T) -> Result<Vec<LircLink>, ProgramError> {
        let prog_ids = query(target_fd.as_raw_fd(), BPF_LIRC_MODE2, 0, &mut None)?;

        let mut prog_fds = Vec::with_capacity(prog_ids.len());

        for id in prog_ids {
            let fd = bpf_prog_get_fd_by_id(id).map_err(|io_error| ProgramError::SyscallError {
                call: "bpf_prog_get_fd_by_id",
                io_error,
            })?;

            prog_fds.push(fd as RawFd);
        }

        Ok(prog_fds
            .into_iter()
            .map(|prog_fd| LircLink::new(prog_fd, target_fd.as_raw_fd()))
            .collect())
    }
}

/// The type returned by [LircMode2::attach]. Can be passed to [LircMode2::detach].
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct LircLinkId(RawFd, RawFd);

#[derive(Debug)]
/// An LircMode2 Link
pub struct LircLink {
    prog_fd: RawFd,
    target_fd: RawFd,
}

impl LircLink {
    pub(crate) fn new(prog_fd: RawFd, target_fd: RawFd) -> LircLink {
        LircLink {
            prog_fd,
            target_fd: unsafe { dup(target_fd) },
        }
    }

    /// Get ProgramInfo from this link
    pub fn info(&self) -> Result<ProgramInfo, ProgramError> {
        match bpf_prog_get_info_by_fd(self.prog_fd) {
            Ok(info) => Ok(ProgramInfo(info)),
            Err(io_error) => Err(ProgramError::SyscallError {
                call: "bpf_prog_get_info_by_fd",
                io_error,
            }),
        }
    }
}

impl Link for LircLink {
    type Id = LircLinkId;

    fn id(&self) -> Self::Id {
        LircLinkId(self.prog_fd, self.target_fd)
    }

    fn detach(self) -> Result<(), ProgramError> {
        let _ = bpf_prog_detach(self.prog_fd, self.target_fd, BPF_LIRC_MODE2);
        unsafe { close(self.target_fd) };
        Ok(())
    }
}
