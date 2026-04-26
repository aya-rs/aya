//! Tracepoint programs.
use std::{
    fs, io,
    os::fd::AsFd as _,
    path::{Path, PathBuf},
};

use aya_obj::generated::{bpf_link_type, bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT};
use thiserror::Error;

use crate::{
    programs::{
        ProgramData, ProgramError, ProgramType, define_link_wrapper, impl_try_from_fdlink,
        impl_try_into_fdlink, load_program_without_attach_type,
        perf_attach::{PerfLinkIdInner, PerfLinkInner, perf_attach},
        perf_event::PerfEventScope,
        utils::find_tracefs_path,
    },
    sys::{SyscallError, perf_event_open_trace_point},
};

/// The type returned when attaching a [`TracePoint`] fails.
#[derive(Debug, Error)]
pub enum TracePointError {
    /// Error detaching from debugfs
    #[error("`{filename}`")]
    FileError {
        /// The file name
        filename: PathBuf,
        /// The [`io::Error`] returned from the file operation
        #[source]
        io_error: io::Error,
    },
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
}

impl TracePoint {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::TracePoint;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data } = self;
        load_program_without_attach_type(BPF_PROG_TYPE_TRACEPOINT, data)
    }

    /// Attaches to a given trace point.
    ///
    /// For a list of the available event categories and names, see
    /// `/sys/kernel/debug/tracing/events`.
    ///
    /// The returned value can be used to detach, see [`TracePoint::detach`].
    pub fn attach(&mut self, category: &str, name: &str) -> Result<TracePointLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let tracefs = find_tracefs_path()?;
        let id = read_sys_fs_trace_point_id(tracefs, category, name.as_ref())?;
        let perf_fd = perf_event_open_trace_point(
            id,
            // For all-processes attachment, perf_event_open requires an explicit
            // CPU. Use CPU 0 only to open the backing perf event.
            PerfEventScope::AllProcessesOneCpu { cpu: 0 },
        )
        .map_err(|io_error| SyscallError {
            call: "perf_event_open_trace_point",
            io_error,
        })?;

        let link = perf_attach(prog_fd, perf_fd, None /* cookie */)?;
        self.data.links.insert(TracePointLink::new(link))
    }
}

define_link_wrapper!(
    TracePointLink,
    TracePointLinkId,
    PerfLinkInner,
    PerfLinkIdInner,
    TracePoint,
);

impl_try_into_fdlink!(TracePointLink, PerfLinkInner);
impl_try_from_fdlink!(
    TracePointLink,
    PerfLinkInner,
    bpf_link_type::BPF_LINK_TYPE_PERF_EVENT
);

pub(crate) fn read_sys_fs_trace_point_id(
    tracefs: &Path,
    category: &str,
    name: &Path,
) -> Result<u64, TracePointError> {
    let filename = tracefs.join("events").join(category).join(name).join("id");

    let id = match fs::read_to_string(&filename) {
        Ok(id) => id,
        Err(io_error) => return Err(TracePointError::FileError { filename, io_error }),
    };
    let id = match id.trim().parse() {
        Ok(id) => id,
        Err(error) => {
            return Err(TracePointError::FileError {
                filename,
                io_error: io::Error::other(error),
            });
        }
    };

    Ok(id)
}
