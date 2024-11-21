//! Tracepoint programs.
use std::{fs, io, os::fd::AsFd as _, path::Path};

use thiserror::Error;

use crate::{
    generated::{bpf_link_type, bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT},
    programs::{
        define_link_wrapper, load_program,
        perf_attach::{perf_attach, PerfLinkIdInner, PerfLinkInner},
        utils::find_tracefs_path,
        FdLink, LinkError, ProgramData, ProgramError,
    },
    sys::{bpf_link_get_info_by_fd, perf_event_open_trace_point, SyscallError},
    VerifierLogLevel,
};

/// The type returned when attaching a [`TracePoint`] fails.
#[derive(Debug, Error)]
pub enum TracePointError {
    /// Error detaching from debugfs
    #[error("`{filename}`")]
    FileError {
        /// The file name
        filename: String,
        /// The [`io::Error`] returned from the file operation
        #[source]
        io_error: io::Error,
    },
}

/// Defines where to attach trace point
#[derive(Debug)]
pub struct TracePointAttachInfo {
    /// Category of trace point
    pub category: String,
    /// Name of trace point
    pub name: String,
}

/// A program that can be attached at a pre-defined kernel trace point.
///
/// The kernel provides a set of pre-defined trace points that eBPF programs can
/// be attached to. See `/sys/kernel/debug/tracing/events` for a list of which
/// events can be traced.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.7.
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::programs::TracePoint;
///
/// let prog: &mut TracePoint = bpf.program_mut("trace_context_switch").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach("sched", "sched_switch")?;
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_TRACEPOINT")]
pub struct TracePoint {
    pub(crate) data: ProgramData<TracePointLink>,
    pub(crate) expected_attach_info: Option<TracePointAttachInfo>,
}

impl TracePoint {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_TRACEPOINT, &mut self.data)
    }

    /// Attaches to a given trace point.
    ///
    /// For a list of the available event categories and names, see
    /// `/sys/kernel/debug/tracing/events`.
    ///
    /// The returned value can be used to detach, see [TracePoint::detach].
    pub fn attach(&mut self, category: &str, name: &str) -> Result<TracePointLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let tracefs = find_tracefs_path()?;
        let id = read_sys_fs_trace_point_id(tracefs, category, name.as_ref())?;
        let fd =
            perf_event_open_trace_point(id, None).map_err(|(_code, io_error)| SyscallError {
                call: "perf_event_open_trace_point",
                io_error,
            })?;

        let link = perf_attach(prog_fd, fd)?;
        self.data.links.insert(TracePointLink::new(link))
    }

    /// Returns the attach info of the trace point
    pub fn auto_attach(&mut self) -> Result<TracePointLinkId, ProgramError> {
        let attach_info = self
            .expected_attach_info
            .as_ref()
            .ok_or(ProgramError::CannotAutoAttach)?;
        let category = attach_info.category.clone();
        let name = attach_info.name.clone();

        self.attach(&category, &name)
    }

    /// Detaches from a trace point.
    ///
    /// See [TracePoint::attach].
    pub fn detach(&mut self, link_id: TracePointLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: TracePointLinkId) -> Result<TracePointLink, ProgramError> {
        self.data.take_link(link_id)
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(path: P) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self {
            data,
            expected_attach_info: None,
        })
    }
}

define_link_wrapper!(
    /// The link used by [TracePoint] programs.
    TracePointLink,
    /// The type returned by [TracePoint::attach]. Can be passed to [TracePoint::detach].
    TracePointLinkId,
    PerfLinkInner,
    PerfLinkIdInner
);

impl TryFrom<TracePointLink> for FdLink {
    type Error = LinkError;

    fn try_from(value: TracePointLink) -> Result<Self, Self::Error> {
        if let PerfLinkInner::FdLink(fd) = value.into_inner() {
            Ok(fd)
        } else {
            Err(LinkError::InvalidLink)
        }
    }
}

impl TryFrom<FdLink> for TracePointLink {
    type Error = LinkError;

    fn try_from(fd_link: FdLink) -> Result<Self, Self::Error> {
        let info = bpf_link_get_info_by_fd(fd_link.fd.as_fd())?;
        if info.type_ == (bpf_link_type::BPF_LINK_TYPE_TRACING as u32) {
            return Ok(Self::new(PerfLinkInner::FdLink(fd_link)));
        }
        Err(LinkError::InvalidLink)
    }
}

pub(crate) fn read_sys_fs_trace_point_id(
    tracefs: &Path,
    category: &str,
    name: &Path,
) -> Result<u32, TracePointError> {
    let file = tracefs.join("events").join(category).join(name).join("id");

    let id = fs::read_to_string(&file).map_err(|io_error| TracePointError::FileError {
        filename: file.display().to_string(),
        io_error,
    })?;
    let id = id
        .trim()
        .parse::<u32>()
        .map_err(|error| TracePointError::FileError {
            filename: file.display().to_string(),
            io_error: io::Error::new(io::ErrorKind::Other, error),
        })?;

    Ok(id)
}
