//! Perf event programs.

use std::os::fd::AsFd as _;

use crate::{
    generated::{
        bpf_link_type,
        bpf_prog_type::BPF_PROG_TYPE_PERF_EVENT,
        perf_hw_cache_id, perf_hw_cache_op_id, perf_hw_cache_op_result_id, perf_hw_id, perf_sw_ids,
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

/// The type of perf event and their respective configuration.
#[doc(alias = "perf_type_id")]
#[derive(Debug, Clone)]
pub enum PerfEventConfig {
    /// The hardware event to report.
    #[doc(alias = "PERF_TYPE_HARDWARE")]
    Hardware(HardwareEvent),
    /// The software event to report.
    #[doc(alias = "PERF_TYPE_SOFTWARE")]
    Software(SoftwareEvent),
    /// The kernel trace point event to report.
    #[doc(alias = "PERF_TYPE_TRACEPOINT")]
    TracePoint {
        /// The ID of the tracing event. This can be obtained from
        /// `/sys/kernel/debug/tracing/events/*/*/id` if `ftrace` is enabled in the kernel.
        event_id: u64,
    },
    /// The hardware cache event to report.
    #[doc(alias = "PERF_TYPE_HW_CACHE")]
    HwCache {
        /// The hardware cache event.
        event: HwCacheEvent,
        /// The hardware cache operation.
        operation: HwCacheOp,
        /// The hardware cache result of interest.
        result: HwCacheResult,
    },
    /// The "raw" implementation-specific event to report.
    #[doc(alias = "PERF_TYPE_RAW")]
    Raw {
        /// The "raw" event value, which is not covered by the "generalized" events. This is CPU
        /// implementation defined events.
        event_id: u64,
    },
    /// A hardware breakpoint.
    ///
    /// Note: this variant is not fully implemented at the moment.
    // TODO: Variant not fully implemented due to additional `perf_event_attr` fields like
    //       `bp_type`, `bp_addr`, etc.
    #[doc(alias = "PERF_TYPE_BREAKPOINT")]
    Breakpoint,
    /// The dynamic PMU (Performance Monitor Unit) event to report.
    ///
    /// Available PMU's may be found under `/sys/bus/event_source/devices`.
    Pmu {
        /// The PMU type.
        ///
        /// This value can extracted from `/sys/bus/event_source/devices/*/type`.
        pmu_type: u32,
        /// The PMU config option.
        ///
        /// This value can extracted from `/sys/bus/event_source/devices/*/format/`, where the
        /// `config:<value>` indicates the bit position to set.
        ///
        /// For example, `config:3` => `config = 1 << 3`.
        config: u64,
    },
}

/// The "generalized" hardware CPU events provided by the kernel.
#[doc(alias = "perf_hw_id")]
#[derive(Debug, Clone, Copy)]
pub enum HardwareEvent {
    /// The total CPU cycles.
    #[doc(alias = "PERF_COUNT_HW_CPU_CYCLES")]
    CpuCycles = perf_hw_id::PERF_COUNT_HW_CPU_CYCLES as isize,
    /// Number of retired instructions.
    #[doc(alias = "PERF_COUNT_HW_INSTRUCTIONS")]
    Instructions = perf_hw_id::PERF_COUNT_HW_INSTRUCTIONS as isize,
    /// Number of cache accesses.
    #[doc(alias = "PERF_COUNT_HW_CACHE_REFERENCES")]
    CacheReferences = perf_hw_id::PERF_COUNT_HW_CACHE_REFERENCES as isize,
    /// Number of cache misses.
    #[doc(alias = "PERF_COUNT_HW_CACHE_MISSES")]
    CacheMisses = perf_hw_id::PERF_COUNT_HW_CACHE_MISSES as isize,
    /// Number of retired branch instructions.
    #[doc(alias = "PERF_COUNT_HW_BRANCH_INSTRUCTIONS")]
    BranchInstructions = perf_hw_id::PERF_COUNT_HW_BRANCH_INSTRUCTIONS as isize,
    /// Number of mispredicted branch instructions.
    #[doc(alias = "PERF_COUNT_HW_BRANCH_MISSES")]
    BranchMisses = perf_hw_id::PERF_COUNT_HW_BRANCH_MISSES as isize,
    /// Number of bus cycles.
    #[doc(alias = "PERF_COUNT_HW_BUS_CYCLES")]
    BusCycles = perf_hw_id::PERF_COUNT_HW_BUS_CYCLES as isize,
    /// Number of stalled cycles during issue.
    #[doc(alias = "PERF_COUNT_HW_STALLED_CYCLES_FRONTEND")]
    StalledCyclesFrontend = perf_hw_id::PERF_COUNT_HW_STALLED_CYCLES_FRONTEND as isize,
    /// Number of stalled cycles during retirement.
    #[doc(alias = "PERF_COUNT_HW_STALLED_CYCLES_BACKEND")]
    StalledCyclesBackend = perf_hw_id::PERF_COUNT_HW_STALLED_CYCLES_BACKEND as isize,
    /// The total CPU cycles, which is not affected by CPU frequency scaling.
    #[doc(alias = "PERF_COUNT_HW_REF_CPU_CYCLES")]
    RefCpuCycles = perf_hw_id::PERF_COUNT_HW_REF_CPU_CYCLES as isize,
}

/// The software-defined events provided by the kernel.
#[doc(alias = "perf_sw_ids")]
#[derive(Debug, Clone, Copy)]
pub enum SoftwareEvent {
    /// The CPU clock timer.
    #[doc(alias = "PERF_COUNT_SW_CPU_CLOCK")]
    CpuClock = perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as isize,
    /// The clock count specific to the task that is running.
    #[doc(alias = "PERF_COUNT_SW_TASK_CLOCK")]
    TaskClock = perf_sw_ids::PERF_COUNT_SW_TASK_CLOCK as isize,
    /// Number of page faults.
    #[doc(alias = "PERF_COUNT_SW_PAGE_FAULTS")]
    PageFaults = perf_sw_ids::PERF_COUNT_SW_PAGE_FAULTS as isize,
    /// Numer of context switches.
    #[doc(alias = "PERF_COUNT_SW_CONTEXT_SWITCHES")]
    ContextSwitches = perf_sw_ids::PERF_COUNT_SW_CONTEXT_SWITCHES as isize,
    /// Number of times the process has migrated to a new CPU.
    #[doc(alias = "PERF_COUNT_SW_CPU_MIGRATIONS")]
    CpuMigrations = perf_sw_ids::PERF_COUNT_SW_CPU_MIGRATIONS as isize,
    /// Number of minor page faults.
    #[doc(alias = "PERF_COUNT_SW_PAGE_FAULTS_MIN")]
    PageFaultsMin = perf_sw_ids::PERF_COUNT_SW_PAGE_FAULTS_MIN as isize,
    /// Number of major page faults.
    #[doc(alias = "PERF_COUNT_SW_PAGE_FAULTS_MAJ")]
    PageFaultsMaj = perf_sw_ids::PERF_COUNT_SW_PAGE_FAULTS_MAJ as isize,
    /// Number of alignment faults.
    #[doc(alias = "PERF_COUNT_SW_ALIGNMENT_FAULTS")]
    AlignmentFaults = perf_sw_ids::PERF_COUNT_SW_ALIGNMENT_FAULTS as isize,
    /// Number of emulation faults.
    #[doc(alias = "PERF_COUNT_SW_EMULATION_FAULTS")]
    EmulationFaults = perf_sw_ids::PERF_COUNT_SW_EMULATION_FAULTS as isize,
    /// Placeholder event that counts nothing.
    #[doc(alias = "PERF_COUNT_SW_DUMMY")]
    Dummy = perf_sw_ids::PERF_COUNT_SW_DUMMY as isize,
    /// Generates raw sample data from BPF.
    #[doc(alias = "PERF_COUNT_SW_BPF_OUTPUT")]
    BpfOutput = perf_sw_ids::PERF_COUNT_SW_BPF_OUTPUT as isize,
    /// Number of context switches to a task when switching to a different cgroup.
    #[doc(alias = "PERF_COUNT_SW_CGROUP_SWITCHES")]
    CgroupSwitches = perf_sw_ids::PERF_COUNT_SW_CGROUP_SWITCHES as isize,
}

/// The hardware CPU cache events.
#[doc(alias = "perf_hw_cache_id")]
#[derive(Debug, Clone, Copy)]
pub enum HwCacheEvent {
    /// Measures Level 1 data cache.
    #[doc(alias = "PERF_COUNT_HW_CACHE_L1D")]
    L1d = perf_hw_cache_id::PERF_COUNT_HW_CACHE_L1D as isize,
    /// Measures Level 1 data cache.
    #[doc(alias = "PERF_COUNT_HW_CACHE_L1I")]
    L1i = perf_hw_cache_id::PERF_COUNT_HW_CACHE_L1I as isize,
    /// Measures Last-level cache.
    #[doc(alias = "PERF_COUNT_HW_CACHE_LL")]
    Ll = perf_hw_cache_id::PERF_COUNT_HW_CACHE_LL as isize,
    /// Measures Data TLB (Translation Lookaside Buffer).
    #[doc(alias = "PERF_COUNT_HW_CACHE_DTLB")]
    Dtlb = perf_hw_cache_id::PERF_COUNT_HW_CACHE_DTLB as isize,
    /// Measures Instruction TLB (Translation Lookaside Buffer).
    #[doc(alias = "PERF_COUNT_HW_CACHE_ITLB")]
    Itlb = perf_hw_cache_id::PERF_COUNT_HW_CACHE_ITLB as isize,
    /// Measures branch prediction.
    #[doc(alias = "PERF_COUNT_HW_CACHE_BPU")]
    Bpu = perf_hw_cache_id::PERF_COUNT_HW_CACHE_BPU as isize,
    /// Measures local memory accesses.
    #[doc(alias = "PERF_COUNT_HW_CACHE_NODE")]
    Node = perf_hw_cache_id::PERF_COUNT_HW_CACHE_NODE as isize,
}

/// The hardware CPU cache operations.
#[doc(alias = "perf_hw_cache_op_id")]
#[derive(Debug, Clone, Copy)]
pub enum HwCacheOp {
    /// Read access.
    #[doc(alias = "PERF_COUNT_HW_CACHE_OP_READ")]
    Read = perf_hw_cache_op_id::PERF_COUNT_HW_CACHE_OP_READ as isize,
    /// Write access.
    #[doc(alias = "PERF_COUNT_HW_CACHE_OP_WRITE")]
    Write = perf_hw_cache_op_id::PERF_COUNT_HW_CACHE_OP_WRITE as isize,
    /// Prefetch access.
    #[doc(alias = "PERF_COUNT_HW_CACHE_OP_PREFETCH")]
    Prefetch = perf_hw_cache_op_id::PERF_COUNT_HW_CACHE_OP_PREFETCH as isize,
}

/// The hardware CPU cache result.
#[doc(alias = "perf_hw_cache_op_result_id")]
#[derive(Debug, Clone, Copy)]
pub enum HwCacheResult {
    /// Cache accesses.
    #[doc(alias = "PERF_COUNT_HW_CACHE_RESULT_ACCESS")]
    Access = perf_hw_cache_op_result_id::PERF_COUNT_HW_CACHE_RESULT_ACCESS as isize,
    /// Cache missed accesses.
    #[doc(alias = "PERF_COUNT_HW_CACHE_RESULT_MISS")]
    Miss = perf_hw_cache_op_result_id::PERF_COUNT_HW_CACHE_RESULT_MISS as isize,
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
/// use aya::{
///     util::online_cpus,
///     programs::perf_event::{
///         PerfEvent, PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent,
///     },
/// };
///
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// let prog: &mut PerfEvent = bpf.program_mut("observe_cpu_clock").unwrap().try_into()?;
/// prog.load()?;
///
/// let perf_type = PerfEventConfig::Software(SoftwareEvent::CpuClock);
/// for cpu in online_cpus().map_err(|(_, error)| error)? {
///     prog.attach(
///         perf_type.clone(),
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
    /// The [`perf_type`](PerfEventConfig) defines the event `type` and `config` of interest.
    /// The [`scope`](PerfEventScope) argument determines which processes are sampled.
    /// If `inherit` is `true`, any new processes spawned by those processes will also
    /// automatically get sampled.
    ///
    /// The returned value can be used to detach, see [PerfEvent::detach].
    pub fn attach(
        &mut self,
        perf_type: PerfEventConfig,
        scope: PerfEventScope,
        sample_policy: SamplePolicy,
        inherit: bool,
    ) -> Result<PerfEventLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();

        let (event_type, config) = match perf_type {
            PerfEventConfig::Pmu { pmu_type, config } => (pmu_type, config),
            // To handle `perf_type_id` event_type together
            _ => {
                let (event_type, config) = match perf_type {
                    PerfEventConfig::Hardware(hw_event) => (PERF_TYPE_HARDWARE, hw_event as u64),
                    PerfEventConfig::Software(sw_event) => (PERF_TYPE_SOFTWARE, sw_event as u64),
                    PerfEventConfig::TracePoint { event_id } => (PERF_TYPE_TRACEPOINT, event_id),
                    PerfEventConfig::HwCache {
                        event,
                        operation,
                        result,
                    } => (
                        PERF_TYPE_HW_CACHE,
                        (event as u64) | ((operation as u64) << 8) | ((result as u64) << 16),
                    ),
                    PerfEventConfig::Raw { event_id } => (PERF_TYPE_RAW, event_id),
                    PerfEventConfig::Breakpoint => (PERF_TYPE_BREAKPOINT, 0),
                    PerfEventConfig::Pmu { .. } => unreachable!(), // not possible due to earlier match
                };
                (event_type as u32, config)
            }
        };
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
            event_type,
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

    /// Detaches the program.
    ///
    /// See [PerfEvent::attach].
    pub fn detach(&mut self, link_id: PerfEventLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: PerfEventLinkId) -> Result<PerfEventLink, ProgramError> {
        self.data.take_link(link_id)
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
    PerfLinkIdInner
);
