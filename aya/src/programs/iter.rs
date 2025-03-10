//! Iterators.
use std::{
    fs::File,
    os::fd::{AsFd, BorrowedFd},
};

use aya_obj::{
    btf::{Btf, BtfKind},
    generated::{
        bpf_attach_type::BPF_TRACE_ITER, bpf_link_type::BPF_LINK_TYPE_ITER,
        bpf_prog_type::BPF_PROG_TYPE_TRACING,
    },
};

use crate::{
    programs::{
        FdLink, LinkError, PerfLinkIdInner, PerfLinkInner, ProgramData, ProgramError, ProgramType,
        define_link_wrapper, load_program,
    },
    sys::{LinkTarget, SyscallError, bpf_create_iter, bpf_link_create, bpf_link_get_info_by_fd},
};

/// A BPF iterator which allows to dump data from the kernel-space into the
/// user-space.
///
/// It can be seen as an alternative to `/proc` filesystem as it offers more
/// flexibility about what information should be retrieved and how it should be
/// formatted.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.8.
///
/// # Example
///
/// ```no_run
/// use std::io::{BufRead, BufReader};
/// use aya::{programs::{Iter, ProgramError}, BtfError, Btf, Ebpf};
/// # let mut ebpf = Ebpf::load_file("ebpf_programs.o")?;
///
/// let btf = Btf::from_sys_fs()?;
/// let program: &mut Iter = ebpf.program_mut("iter_prog").unwrap().try_into()?;
/// program.load("task", &btf)?;
///
/// let link_id = program.attach()?;
/// let link = program.take_link(link_id)?;
/// let file = link.into_file()?;
/// let reader = BufReader::new(file);
///
/// let mut lines = reader.lines();
/// for line in lines {
///     let line = line?;
///     println!("{line}");
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct Iter {
    pub(crate) data: ProgramData<IterLink>,
}

impl Iter {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::Tracing;

    /// Loads the program inside the kernel.
    pub fn load(&mut self, iter_type: &str, btf: &Btf) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(BPF_TRACE_ITER);
        let type_name = format!("bpf_iter_{iter_type}");
        self.data.attach_btf_id =
            Some(btf.id_by_type_name_kind(type_name.as_str(), BtfKind::Func)?);
        load_program(BPF_PROG_TYPE_TRACING, &mut self.data)
    }

    /// Attaches the program.
    ///
    /// The returned value can be used to detach, see [`Self::detach`].
    pub fn attach(&mut self) -> Result<IterLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let link_fd = bpf_link_create(prog_fd, LinkTarget::Iter, BPF_TRACE_ITER, 0, None).map_err(
            |io_error| SyscallError {
                call: "bpf_link_create",
                io_error,
            },
        )?;

        self.data
            .links
            .insert(IterLink::new(PerfLinkInner::FdLink(FdLink::new(link_fd))))
    }
}

/// An iterator descriptor.
#[derive(Debug)]
pub struct IterFd {
    fd: crate::MockableFd,
}

impl AsFd for IterFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        let Self { fd } = self;
        fd.as_fd()
    }
}

impl TryFrom<IterLink> for FdLink {
    type Error = LinkError;

    fn try_from(value: IterLink) -> Result<Self, Self::Error> {
        if let PerfLinkInner::FdLink(fd) = value.into_inner() {
            Ok(fd)
        } else {
            Err(LinkError::InvalidLink)
        }
    }
}

impl TryFrom<FdLink> for IterLink {
    type Error = LinkError;

    fn try_from(fd_link: FdLink) -> Result<Self, Self::Error> {
        let info = bpf_link_get_info_by_fd(fd_link.fd.as_fd())?;
        if info.type_ == (BPF_LINK_TYPE_ITER as u32) {
            return Ok(Self::new(PerfLinkInner::FdLink(fd_link)));
        }
        Err(LinkError::InvalidLink)
    }
}

define_link_wrapper!(
    /// The link used by [`Iter`] programs.
    IterLink,
    /// The type returned by [`Iter::attach`]. Can be passed to [`Iter::detach`].
    IterLinkId,
    PerfLinkInner,
    PerfLinkIdInner,
    Iter,
);

impl IterLink {
    /// Converts [`IterLink`] into a [`File`] that can be used to retrieve the
    /// outputs of the iterator program.
    pub fn into_file(self) -> Result<File, LinkError> {
        if let PerfLinkInner::FdLink(fd) = self.into_inner() {
            let fd = bpf_create_iter(fd.fd.as_fd()).map_err(|io_error| {
                LinkError::SyscallError(SyscallError {
                    call: "bpf_iter_create",
                    io_error,
                })
            })?;
            Ok(fd.into_inner().into())
        } else {
            Err(LinkError::InvalidLink)
        }
    }
}
