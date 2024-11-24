//! Lirc programs.
use std::os::fd::{AsFd, AsRawFd as _, RawFd};

use crate::{
    generated::{bpf_attach_type::BPF_LIRC_MODE2, bpf_prog_type::BPF_PROG_TYPE_LIRC_MODE2},
    programs::{
        load_program, query, CgroupAttachMode, Link, ProgramData, ProgramError, ProgramFd,
        ProgramInfo,
    },
    sys::{bpf_prog_attach, bpf_prog_detach, bpf_prog_get_fd_by_id, ProgQueryTarget},
};

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
/// #     Ebpf(#[from] aya::EbpfError)
/// # }
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use std::fs::File;
/// use aya::programs::LircMode2;
///
/// let file = File::open("/dev/lirc0")?;
/// let mut bpf = aya::Ebpf::load_file("imon_rsc.o")?;
/// let decoder: &mut LircMode2 = bpf.program_mut("imon_rsc").unwrap().try_into().unwrap();
/// decoder.load()?;
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
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_LIRC_MODE2, &mut self.data)
    }

    /// Attaches the program to the given lirc device.
    ///
    /// The returned value can be used to detach, see [LircMode2::detach].
    pub fn attach<T: AsFd>(&mut self, lircdev: T) -> Result<LircLinkId, ProgramError> {
        let prog_fd = self.fd()?;

        // The link is going to own this new file descriptor so we are
        // going to need a duplicate whose lifetime we manage. Let's
        // duplicate it prior to attaching it so the new file
        // descriptor is closed at drop in case it fails to attach.
        let prog_fd = prog_fd.try_clone()?;
        let lircdev_fd = lircdev.as_fd().try_clone_to_owned()?;
        let lircdev_fd = crate::MockableFd::from_fd(lircdev_fd);

        bpf_prog_attach(
            prog_fd.as_fd(),
            lircdev_fd.as_fd(),
            BPF_LIRC_MODE2,
            CgroupAttachMode::Single.into(),
        )?;

        self.data.links.insert(LircLink::new(prog_fd, lircdev_fd))
    }

    /// Detaches the program.
    ///
    /// See [LircMode2::attach].
    pub fn detach(&mut self, link_id: LircLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided `link_id`.
    ///
    /// The caller takes the responsibility of managing the lifetime of the
    /// link. When the returned [`LircLink`] is dropped, the link is detached.
    pub fn take_link(&mut self, link_id: LircLinkId) -> Result<LircLink, ProgramError> {
        self.data.take_link(link_id)
    }

    /// Queries the lirc device for attached programs.
    pub fn query<T: AsFd>(target_fd: T) -> Result<Vec<LircLink>, ProgramError> {
        let target_fd = target_fd.as_fd();
        let (_, prog_ids) = query(ProgQueryTarget::Fd(target_fd), BPF_LIRC_MODE2, 0, &mut None)?;

        prog_ids
            .into_iter()
            .map(|prog_id| {
                let prog_fd = bpf_prog_get_fd_by_id(prog_id)?;
                let target_fd = target_fd.try_clone_to_owned()?;
                let target_fd = crate::MockableFd::from_fd(target_fd);
                let prog_fd = ProgramFd(prog_fd);
                Ok(LircLink::new(prog_fd, target_fd))
            })
            .collect()
    }
}

/// The type returned by [LircMode2::attach]. Can be passed to [LircMode2::detach].
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct LircLinkId(RawFd, RawFd);

#[derive(Debug)]
/// An LircMode2 Link
pub struct LircLink {
    prog_fd: ProgramFd,
    target_fd: crate::MockableFd,
}

impl LircLink {
    pub(crate) fn new(prog_fd: ProgramFd, target_fd: crate::MockableFd) -> Self {
        Self { prog_fd, target_fd }
    }

    /// Get ProgramInfo from this link
    pub fn info(&self) -> Result<ProgramInfo, ProgramError> {
        let Self {
            prog_fd,
            target_fd: _,
        } = self;
        ProgramInfo::new_from_fd(prog_fd.as_fd())
    }
}

impl Link for LircLink {
    type Id = LircLinkId;

    fn id(&self) -> Self::Id {
        LircLinkId(self.prog_fd.as_fd().as_raw_fd(), self.target_fd.as_raw_fd())
    }

    fn detach(self) -> Result<(), ProgramError> {
        bpf_prog_detach(self.prog_fd.as_fd(), self.target_fd.as_fd(), BPF_LIRC_MODE2)
            .map_err(Into::into)
    }
}
