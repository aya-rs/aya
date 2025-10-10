//! Perf event programs.

use std::os::fd::AsFd as _;

use aya_obj::generated::{
    HW_BREAKPOINT_EMPTY, HW_BREAKPOINT_INVALID, HW_BREAKPOINT_LEN_1, HW_BREAKPOINT_LEN_2,
    HW_BREAKPOINT_LEN_3, HW_BREAKPOINT_LEN_4, HW_BREAKPOINT_LEN_5, HW_BREAKPOINT_LEN_6,
    HW_BREAKPOINT_LEN_7, HW_BREAKPOINT_LEN_8, HW_BREAKPOINT_R, HW_BREAKPOINT_RW, HW_BREAKPOINT_W,
    HW_BREAKPOINT_X, bpf_link_type,
    bpf_prog_type::BPF_PROG_TYPE_PERF_EVENT,
    perf_type_id::{
        PERF_TYPE_BREAKPOINT, PERF_TYPE_HARDWARE, PERF_TYPE_HW_CACHE, PERF_TYPE_RAW,
        PERF_TYPE_SOFTWARE, PERF_TYPE_TRACEPOINT,
    },
};
pub use aya_obj::generated::{
    perf_hw_cache_id, perf_hw_cache_op_id, perf_hw_cache_op_result_id, perf_hw_id, perf_sw_ids,
};

use crate::{
    programs::{
        FdLink, LinkError, ProgramData, ProgramError, ProgramType, impl_try_into_fdlink,
        links::define_link_wrapper,
        load_program,
        perf_attach::{PerfLinkIdInner, PerfLinkInner},
    },
    sys::{SyscallError, bpf_link_get_info_by_fd, perf_event_open},
};

/// The type of perf event
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
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
/// A hardware breakpoint configuration
#[derive(Debug, Clone)]
pub struct PerfBreakpoint {
    /// The address to set the breakpoint on
    pub address: u64,
    /// The breakpoint size. For HwBreakpointX this must be sizeof(long). For
    /// all other types it should be one of HwBreakpointLen1, HwBreakpointLen2,,
    /// HwBreakpointLen4 or HwBreakpointLen8.
    pub length: PerfBreakpointSize,
    /// The breakpoint type, one of HW_BREAKPOINT_{R,W,RW,X}
    pub type_: PerfBreakpointType,
}

/// Type of hardware breakpoint, determines if we break on read, write, or execute.
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum PerfBreakpointType {
    /// HW_BREAKPOINT_EMPTY
    HwBreakpointEmpty = HW_BREAKPOINT_EMPTY,
    /// HW_BREAKPOINT_R
    HwBreakpointR = HW_BREAKPOINT_R,
    /// HW_BREAKPOINT_W
    HwBreakpointW = HW_BREAKPOINT_W,
    /// HW_BREAKPOINT_RW
    HwBreakpointRW = HW_BREAKPOINT_RW,
    /// HW_BREAKPOINT_X
    HwBreakpointX = HW_BREAKPOINT_X,
    /// HW_BREAKPOINT_INVALID
    HwBreakpointInvalid = HW_BREAKPOINT_INVALID,
}

/// The size of the breakpoint being measured
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum PerfBreakpointSize {
    /// HW_BREAKPOINT_LEN_1
    HwBreakpointLen1 = HW_BREAKPOINT_LEN_1,
    /// HW_BREAKPOINT_LEN_2
    HwBreakpointLen2 = HW_BREAKPOINT_LEN_2,
    /// HW_BREAKPOINT_LEN_3
    HwBreakpointLen3 = HW_BREAKPOINT_LEN_3,
    /// HW_BREAKPOINT_LEN_4
    HwBreakpointLen4 = HW_BREAKPOINT_LEN_4,
    /// HW_BREAKPOINT_LEN_5
    HwBreakpointLen5 = HW_BREAKPOINT_LEN_5,
    /// HW_BREAKPOINT_LEN_6
    HwBreakpointLen6 = HW_BREAKPOINT_LEN_6,
    /// HW_BREAKPOINT_LEN_7
    HwBreakpointLen7 = HW_BREAKPOINT_LEN_7,
    /// HW_BREAKPOINT_LEN_8
    HwBreakpointLen8 = HW_BREAKPOINT_LEN_8,
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
///         None
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
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::PerfEvent;

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
    /// The `bp` option must be specified if `perf_type` is `Breakpoint`.
    ///
    /// The `scope` argument determines which processes are sampled. If
    /// `inherit` is true, any new processes spawned by those processes will
    /// also automatically get sampled.
    ///
    /// The returned value can be used to detach, see [PerfEvent::detach].
    pub fn attach(
        &mut self,
        perf_type: PerfTypeId,
        config: u64,
        scope: PerfEventScope,
        sample_policy: SamplePolicy,
        inherit: bool,
        bp: Option<PerfBreakpoint>,
    ) -> Result<PerfEventLinkId, ProgramError> {
        if matches!(perf_type, PerfTypeId::Breakpoint) && bp.is_none() {
            return Err(ProgramError::IncompleteBreakpoint);
        }
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
            matches!(perf_type, PerfTypeId::Breakpoint),
            inherit,
            0,
            bp,
        )
        .map_err(|io_error| SyscallError {
            call: "perf_event_open",
            io_error,
        })?;

        let link = crate::programs::perf_attach(prog_fd, fd, None /* cookie */)?;
        self.data.links.insert(PerfEventLink::new(link))
    }
}

impl_try_into_fdlink!(PerfEventLink, PerfLinkInner);

impl TryFrom<FdLink> for PerfEventLink {
    type Error = LinkError;

    fn try_from(fd_link: FdLink) -> Result<Self, Self::Error> {
        let info = bpf_link_get_info_by_fd(fd_link.fd.as_fd())?;
        if info.type_ == (bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u32) {
            return Ok(Self::new(PerfLinkInner::Fd(fd_link)));
        }
        Err(LinkError::InvalidLink)
    }
}

define_link_wrapper!(
    PerfEventLink,
    PerfEventLinkId,
    PerfLinkInner,
    PerfLinkIdInner,
    PerfEvent,
);
