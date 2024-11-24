//! Perf event programs.

use std::os::fd::AsFd as _;

pub use crate::generated::{
    perf_hw_cache_id, perf_hw_cache_op_id, perf_hw_cache_op_result_id, perf_hw_id, perf_sw_ids,
};
use crate::{
    generated::{
        bpf_link_type,
        bpf_prog_type::BPF_PROG_TYPE_PERF_EVENT,
        perf_type_id::{
            PERF_TYPE_BREAKPOINT, PERF_TYPE_HARDWARE, PERF_TYPE_HW_CACHE, PERF_TYPE_RAW,
            PERF_TYPE_SOFTWARE, PERF_TYPE_TRACEPOINT,
        },
    },
    programs::{
        links::define_link_wrapper,
        load_program, perf_attach,
        perf_attach::{PerfLinkIdInner, PerfLinkInner},
        FdLink, LinkError, ProgramData, ProgramError,
    },
    sys::{bpf_link_get_info_by_fd, perf_event_open, SyscallError},
};

/// The type of perf event
#[repr(u32)]
#[derive(Debug, Clone)]
pub enum PerfTypeId {
    /// PERF_TYPE_HARDWARE
    Hardware = PERF_TYPE_HARDWARE as u32,
    /// PERF_TYPE_SOFTWARE
    Software = PERF_TYPE_SOFTWARE as u32,
    /// PERF_TYPE_TRACEPOINT
    TracePoint = PERF_TYPE_TRACEPOINT as u32,
    /// PERF_TYPE_HW_CACHE
    HwCache = PERF_TYPE_HW_CACHE as u32,
    /// PERF_TYPE_RAW
    Raw = PERF_TYPE_RAW as u32,
    /// PERF_TYPE_BREAKPOINT
    Breakpoint = PERF_TYPE_BREAKPOINT as u32,
}

/// Sample Policy
#[derive(Debug, Clone)]
pub enum SamplePolicy {
    /// Period
    Period(u64),
    /// Frequency
    Frequency(u64),
}

/// The scope of a PerfEvent
#[derive(Debug, Clone)]
#[allow(clippy::enum_variant_names)]
pub enum PerfEventScope {
    /// Calling process, any cpu
    CallingProcessAnyCpu,
    /// calling process, one cpu
    CallingProcessOneCpu {
        /// cpu id
        cpu: u32,
    },
    /// one process, any cpu
    OneProcessAnyCpu {
        /// process id
        pid: u32,
    },
    /// one process, one cpu
    OneProcessOneCpu {
        /// cpu id
        cpu: u32,
        /// process id
        pid: u32,
    },
    /// all processes, one cpu
    AllProcessesOneCpu {
        /// cpu id
        cpu: u32,
    },
}

/// A program that can be attached at a perf event.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.9.
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
/// use aya::util::online_cpus;
/// use aya::programs::perf_event::{
///     perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK, PerfEvent, PerfEventScope, PerfTypeId, SamplePolicy,
/// };
///
/// let prog: &mut PerfEvent = bpf.program_mut("observe_cpu_clock").unwrap().try_into()?;
/// prog.load()?;
///
/// for cpu in online_cpus().map_err(|(_, error)| error)? {
///     prog.attach(
///         PerfTypeId::Software,
///         PERF_COUNT_SW_CPU_CLOCK as u64,
///         PerfEventScope::AllProcessesOneCpu { cpu },
///         SamplePolicy::Period(1000000),
///         true,
///     )?;
/// }
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_PERF_EVENT")]
pub struct PerfEvent {
    pub(crate) data: ProgramData<PerfEventLink>,
}

impl PerfEvent {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_PERF_EVENT, &mut self.data)
    }

    /// Attaches to the given perf event.
    ///
    /// The possible values and encoding of the `config` argument depends on the
    /// `perf_type`. See `perf_sw_ids`, `perf_hw_id`, `perf_hw_cache_id`,
    /// `perf_hw_cache_op_id` and `perf_hw_cache_op_result_id`.
    ///
    /// The `scope` argument determines which processes are sampled. If `inherit`
    /// is true, any new processes spawned by those processes will also
    /// automatically get sampled.
    ///
    /// The returned value can be used to detach, see [PerfEvent::detach].
    pub fn attach(
        &mut self,
        perf_type: PerfTypeId,
        config: u64,
        scope: PerfEventScope,
        sample_policy: SamplePolicy,
        inherit: bool,
    ) -> Result<PerfEventLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let (sample_period, sample_frequency) = match sample_policy {
            SamplePolicy::Period(period) => (period, None),
            SamplePolicy::Frequency(frequency) => (0, Some(frequency)),
        };
        let (pid, cpu) = match scope {
            PerfEventScope::CallingProcessAnyCpu => (0, -1),
            PerfEventScope::CallingProcessOneCpu { cpu } => (0, cpu as i32),
            PerfEventScope::OneProcessAnyCpu { pid } => (pid as i32, -1),
            PerfEventScope::OneProcessOneCpu { cpu, pid } => (pid as i32, cpu as i32),
            PerfEventScope::AllProcessesOneCpu { cpu } => (-1, cpu as i32),
        };
        let fd = perf_event_open(
            perf_type as u32,
            config,
            pid,
            cpu,
            sample_period,
            sample_frequency,
            false,
            inherit,
            0,
        )
        .map_err(|(_code, io_error)| SyscallError {
            call: "perf_event_open",
            io_error,
        })?;

        let link = perf_attach(prog_fd, fd)?;
        self.data.links.insert(PerfEventLink::new(link))
    }
}

impl TryFrom<PerfEventLink> for FdLink {
    type Error = LinkError;

    fn try_from(value: PerfEventLink) -> Result<Self, Self::Error> {
        if let PerfLinkInner::FdLink(fd) = value.into_inner() {
            Ok(fd)
        } else {
            Err(LinkError::InvalidLink)
        }
    }
}

impl TryFrom<FdLink> for PerfEventLink {
    type Error = LinkError;

    fn try_from(fd_link: FdLink) -> Result<Self, Self::Error> {
        let info = bpf_link_get_info_by_fd(fd_link.fd.as_fd())?;
        if info.type_ == (bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u32) {
            return Ok(Self::new(PerfLinkInner::FdLink(fd_link)));
        }
        Err(LinkError::InvalidLink)
    }
}

define_link_wrapper!(
    /// The link used by [PerfEvent] programs.
    PerfEventLink,
    /// The type returned by [PerfEvent::attach]. Can be passed to [PerfEvent::detach].
    PerfEventLinkId,
    PerfLinkInner,
    PerfLinkIdInner,
    PerfEvent,
);
