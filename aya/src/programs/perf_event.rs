//! Perf event programs.

use std::os::fd::AsFd as _;

use aya_obj::generated::{
    HW_BREAKPOINT_LEN_1, HW_BREAKPOINT_LEN_2, HW_BREAKPOINT_LEN_4, HW_BREAKPOINT_LEN_8,
    bpf_link_type,
    bpf_prog_type::BPF_PROG_TYPE_PERF_EVENT,
    perf_hw_cache_id, perf_hw_cache_op_id, perf_hw_cache_op_result_id, perf_hw_id, perf_sw_ids,
    perf_type_id,
    perf_type_id::{
        PERF_TYPE_BREAKPOINT, PERF_TYPE_HARDWARE, PERF_TYPE_HW_CACHE, PERF_TYPE_RAW,
        PERF_TYPE_SOFTWARE, PERF_TYPE_TRACEPOINT,
    },
};

use crate::{
    programs::{
        FdLink, LinkError, ProgramData, ProgramError, ProgramType, impl_try_into_fdlink,
        links::define_link_wrapper,
        load_program,
        perf_attach::{PerfLinkIdInner, PerfLinkInner, perf_attach},
    },
    sys::{SyscallError, bpf_link_get_info_by_fd, perf_event_open},
};

/// The type of perf event and their respective configuration.
#[doc(alias = "perf_type_id")]
#[derive(Debug, Clone, Copy)]
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
    #[doc(alias = "PERF_TYPE_BREAKPOINT")]
    Breakpoint(BreakpointConfig),
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

macro_rules! impl_to_u32 {
    ($($t:ty, $fn:ident),*) => {
        $(const fn $fn(id: $t) -> u32 {
            const _: [(); 4] = [(); std::mem::size_of::<$t>()];
            id as u32
        })*
    };
}

impl_to_u32!(
    perf_hw_id,
    perf_hw_id_to_u32,
    perf_sw_ids,
    perf_sw_ids_to_u32,
    perf_hw_cache_id,
    perf_hw_cache_id_to_u32,
    perf_hw_cache_op_id,
    perf_hw_cache_op_id_to_u32,
    perf_hw_cache_op_result_id,
    perf_hw_cache_op_result_id_to_u32,
    perf_type_id,
    perf_type_id_to_u32
);

/// The "generalized" hardware CPU events provided by the kernel.
#[doc(alias = "perf_hw_id")]
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum HardwareEvent {
    /// The total CPU cycles.
    #[doc(alias = "PERF_COUNT_HW_CPU_CYCLES")]
    CpuCycles = perf_hw_id_to_u32(perf_hw_id::PERF_COUNT_HW_CPU_CYCLES),
    /// Number of retired instructions.
    #[doc(alias = "PERF_COUNT_HW_INSTRUCTIONS")]
    Instructions = perf_hw_id_to_u32(perf_hw_id::PERF_COUNT_HW_INSTRUCTIONS),
    /// Number of cache accesses.
    #[doc(alias = "PERF_COUNT_HW_CACHE_REFERENCES")]
    CacheReferences = perf_hw_id_to_u32(perf_hw_id::PERF_COUNT_HW_CACHE_REFERENCES),
    /// Number of cache misses.
    #[doc(alias = "PERF_COUNT_HW_CACHE_MISSES")]
    CacheMisses = perf_hw_id_to_u32(perf_hw_id::PERF_COUNT_HW_CACHE_MISSES),
    /// Number of retired branch instructions.
    #[doc(alias = "PERF_COUNT_HW_BRANCH_INSTRUCTIONS")]
    BranchInstructions = perf_hw_id_to_u32(perf_hw_id::PERF_COUNT_HW_BRANCH_INSTRUCTIONS),
    /// Number of mispredicted branch instructions.
    #[doc(alias = "PERF_COUNT_HW_BRANCH_MISSES")]
    BranchMisses = perf_hw_id_to_u32(perf_hw_id::PERF_COUNT_HW_BRANCH_MISSES),
    /// Number of bus cycles.
    #[doc(alias = "PERF_COUNT_HW_BUS_CYCLES")]
    BusCycles = perf_hw_id_to_u32(perf_hw_id::PERF_COUNT_HW_BUS_CYCLES),
    /// Number of stalled cycles during issue.
    #[doc(alias = "PERF_COUNT_HW_STALLED_CYCLES_FRONTEND")]
    StalledCyclesFrontend = perf_hw_id_to_u32(perf_hw_id::PERF_COUNT_HW_STALLED_CYCLES_FRONTEND),
    /// Number of stalled cycles during retirement.
    #[doc(alias = "PERF_COUNT_HW_STALLED_CYCLES_BACKEND")]
    StalledCyclesBackend = perf_hw_id_to_u32(perf_hw_id::PERF_COUNT_HW_STALLED_CYCLES_BACKEND),
    /// The total CPU cycles, which is not affected by CPU frequency scaling.
    #[doc(alias = "PERF_COUNT_HW_REF_CPU_CYCLES")]
    RefCpuCycles = perf_hw_id_to_u32(perf_hw_id::PERF_COUNT_HW_REF_CPU_CYCLES),
}

impl HardwareEvent {
    const fn into_primitive(self) -> u32 {
        const _: [(); 4] = [(); std::mem::size_of::<HardwareEvent>()];
        self as u32
    }
}

/// The software-defined events provided by the kernel.
#[doc(alias = "perf_sw_ids")]
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum SoftwareEvent {
    /// The CPU clock timer.
    #[doc(alias = "PERF_COUNT_SW_CPU_CLOCK")]
    CpuClock = perf_sw_ids_to_u32(perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK),
    /// The clock count specific to the task that is running.
    #[doc(alias = "PERF_COUNT_SW_TASK_CLOCK")]
    TaskClock = perf_sw_ids_to_u32(perf_sw_ids::PERF_COUNT_SW_TASK_CLOCK),
    /// Number of page faults.
    #[doc(alias = "PERF_COUNT_SW_PAGE_FAULTS")]
    PageFaults = perf_sw_ids_to_u32(perf_sw_ids::PERF_COUNT_SW_PAGE_FAULTS),
    /// Numer of context switches.
    #[doc(alias = "PERF_COUNT_SW_CONTEXT_SWITCHES")]
    ContextSwitches = perf_sw_ids_to_u32(perf_sw_ids::PERF_COUNT_SW_CONTEXT_SWITCHES),
    /// Number of times the process has migrated to a new CPU.
    #[doc(alias = "PERF_COUNT_SW_CPU_MIGRATIONS")]
    CpuMigrations = perf_sw_ids_to_u32(perf_sw_ids::PERF_COUNT_SW_CPU_MIGRATIONS),
    /// Number of minor page faults.
    #[doc(alias = "PERF_COUNT_SW_PAGE_FAULTS_MIN")]
    PageFaultsMin = perf_sw_ids_to_u32(perf_sw_ids::PERF_COUNT_SW_PAGE_FAULTS_MIN),
    /// Number of major page faults.
    #[doc(alias = "PERF_COUNT_SW_PAGE_FAULTS_MAJ")]
    PageFaultsMaj = perf_sw_ids_to_u32(perf_sw_ids::PERF_COUNT_SW_PAGE_FAULTS_MAJ),
    /// Number of alignment faults.
    #[doc(alias = "PERF_COUNT_SW_ALIGNMENT_FAULTS")]
    AlignmentFaults = perf_sw_ids_to_u32(perf_sw_ids::PERF_COUNT_SW_ALIGNMENT_FAULTS),
    /// Number of emulation faults.
    #[doc(alias = "PERF_COUNT_SW_EMULATION_FAULTS")]
    EmulationFaults = perf_sw_ids_to_u32(perf_sw_ids::PERF_COUNT_SW_EMULATION_FAULTS),
    /// Placeholder event that counts nothing.
    #[doc(alias = "PERF_COUNT_SW_DUMMY")]
    Dummy = perf_sw_ids_to_u32(perf_sw_ids::PERF_COUNT_SW_DUMMY),
    /// Generates raw sample data from BPF.
    #[doc(alias = "PERF_COUNT_SW_BPF_OUTPUT")]
    BpfOutput = perf_sw_ids_to_u32(perf_sw_ids::PERF_COUNT_SW_BPF_OUTPUT),
    /// Number of context switches to a task when switching to a different cgroup.
    #[doc(alias = "PERF_COUNT_SW_CGROUP_SWITCHES")]
    CgroupSwitches = perf_sw_ids_to_u32(perf_sw_ids::PERF_COUNT_SW_CGROUP_SWITCHES),
}

impl SoftwareEvent {
    const fn into_primitive(self) -> u32 {
        const _: [(); 4] = [(); std::mem::size_of::<SoftwareEvent>()];
        self as u32
    }
}

/// The hardware CPU cache events.
#[doc(alias = "perf_hw_cache_id")]
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum HwCacheEvent {
    /// Measures Level 1 data cache.
    #[doc(alias = "PERF_COUNT_HW_CACHE_L1D")]
    L1d = perf_hw_cache_id_to_u32(perf_hw_cache_id::PERF_COUNT_HW_CACHE_L1D),
    /// Measures Level 1 data cache.
    #[doc(alias = "PERF_COUNT_HW_CACHE_L1I")]
    L1i = perf_hw_cache_id_to_u32(perf_hw_cache_id::PERF_COUNT_HW_CACHE_L1I),
    /// Measures Last-level cache.
    #[doc(alias = "PERF_COUNT_HW_CACHE_LL")]
    Ll = perf_hw_cache_id_to_u32(perf_hw_cache_id::PERF_COUNT_HW_CACHE_LL),
    /// Measures Data TLB (Translation Lookaside Buffer).
    #[doc(alias = "PERF_COUNT_HW_CACHE_DTLB")]
    Dtlb = perf_hw_cache_id_to_u32(perf_hw_cache_id::PERF_COUNT_HW_CACHE_DTLB),
    /// Measures Instruction TLB (Translation Lookaside Buffer).
    #[doc(alias = "PERF_COUNT_HW_CACHE_ITLB")]
    Itlb = perf_hw_cache_id_to_u32(perf_hw_cache_id::PERF_COUNT_HW_CACHE_ITLB),
    /// Measures branch prediction.
    #[doc(alias = "PERF_COUNT_HW_CACHE_BPU")]
    Bpu = perf_hw_cache_id_to_u32(perf_hw_cache_id::PERF_COUNT_HW_CACHE_BPU),
    /// Measures local memory accesses.
    #[doc(alias = "PERF_COUNT_HW_CACHE_NODE")]
    Node = perf_hw_cache_id_to_u32(perf_hw_cache_id::PERF_COUNT_HW_CACHE_NODE),
}

impl HwCacheEvent {
    const fn into_primitive(self) -> u32 {
        const _: [(); 4] = [(); std::mem::size_of::<HwCacheEvent>()];
        self as u32
    }
}

/// The hardware CPU cache operations.
#[doc(alias = "perf_hw_cache_op_id")]
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum HwCacheOp {
    /// Read access.
    #[doc(alias = "PERF_COUNT_HW_CACHE_OP_READ")]
    Read = perf_hw_cache_op_id_to_u32(perf_hw_cache_op_id::PERF_COUNT_HW_CACHE_OP_READ),
    /// Write access.
    #[doc(alias = "PERF_COUNT_HW_CACHE_OP_WRITE")]
    Write = perf_hw_cache_op_id_to_u32(perf_hw_cache_op_id::PERF_COUNT_HW_CACHE_OP_WRITE),
    /// Prefetch access.
    #[doc(alias = "PERF_COUNT_HW_CACHE_OP_PREFETCH")]
    Prefetch = perf_hw_cache_op_id_to_u32(perf_hw_cache_op_id::PERF_COUNT_HW_CACHE_OP_PREFETCH),
}

impl HwCacheOp {
    const fn into_primitive(self) -> u32 {
        const _: [(); 4] = [(); std::mem::size_of::<HwCacheOp>()];
        self as u32
    }
}

/// The hardware CPU cache result.
#[doc(alias = "perf_hw_cache_op_result_id")]
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum HwCacheResult {
    /// Cache accesses.
    #[doc(alias = "PERF_COUNT_HW_CACHE_RESULT_ACCESS")]
    Access = perf_hw_cache_op_result_id_to_u32(
        perf_hw_cache_op_result_id::PERF_COUNT_HW_CACHE_RESULT_ACCESS,
    ),
    /// Cache missed accesses.
    #[doc(alias = "PERF_COUNT_HW_CACHE_RESULT_MISS")]
    Miss = perf_hw_cache_op_result_id_to_u32(
        perf_hw_cache_op_result_id::PERF_COUNT_HW_CACHE_RESULT_MISS,
    ),
}

impl HwCacheResult {
    const fn into_primitive(self) -> u32 {
        const _: [(); 4] = [(); std::mem::size_of::<HwCacheResult>()];
        self as u32
    }
}

/// Type of hardware breakpoint, determines if we break on read, write, or
/// execute, or if there should be no breakpoint on the given address.
#[derive(Debug, Clone, Copy)]
pub enum BreakpointConfig {
    /// HW_BREAKPOINT_EMPTY, no breakpoint.
    #[doc(alias = "HW_BREAKPOINT_EMPTY")]
    Empty {
        /// The size of the breakpoint being measured.
        size: PerfBreakpointSize,
        /// The address of the breakpoint.
        address: u64,
    },
    /// HW_BREAKPOINT_R, count when we read the memory location.
    #[doc(alias = "HW_BREAKPOINT_R")]
    Read {
        /// The size of the breakpoint being measured.
        size: PerfBreakpointSize,
        /// The address of the breakpoint.
        address: u64,
    },
    /// HW_BREAKPOINT_W, count when we write the memory location.
    #[doc(alias = "HW_BREAKPOINT_W")]
    Write {
        /// The size of the breakpoint being measured.
        size: PerfBreakpointSize,
        /// The address of the breakpoint.
        address: u64,
    },
    /// HW_BREAKPOINT_RW, count when we read or write the memory location.
    #[doc(alias = "HW_BREAKPOINT_RW")]
    ReadWrite {
        /// The size of the breakpoint being measured.
        size: PerfBreakpointSize,
        /// The address of the breakpoint.
        address: u64,
    },
    /// HW_BREAKPOINT_X, count when we execute code at the memory location.
    #[doc(alias = "HW_BREAKPOINT_X")]
    Execute {
        /// The address of the breakpoint.
        address: u64,
    },
}

/// The size of the breakpoint being observed in bytes.
#[repr(u64)]
#[derive(Debug, Clone, Copy)]
pub enum PerfBreakpointSize {
    /// HW_BREAKPOINT_LEN_1
    #[doc(alias = "HW_BREAKPOINT_LEN_1")]
    HwBreakpointLen1 = HW_BREAKPOINT_LEN_1 as u64,
    /// HW_BREAKPOINT_LEN_2
    #[doc(alias = "HW_BREAKPOINT_LEN_2")]
    HwBreakpointLen2 = HW_BREAKPOINT_LEN_2 as u64,
    /// HW_BREAKPOINT_LEN_4
    #[doc(alias = "HW_BREAKPOINT_LEN_4")]
    HwBreakpointLen4 = HW_BREAKPOINT_LEN_4 as u64,
    /// HW_BREAKPOINT_LEN_8
    #[doc(alias = "HW_BREAKPOINT_LEN_8")]
    HwBreakpointLen8 = HW_BREAKPOINT_LEN_8 as u64,
}

impl PerfBreakpointSize {
    pub(crate) const fn into_primitive(self) -> u64 {
        const _: [(); 8] = [(); std::mem::size_of::<PerfBreakpointSize>()];
        self as u64
    }

    pub(crate) const fn from_primitive(size: u64) -> Self {
        match size {
            n if n == Self::HwBreakpointLen1.into_primitive() => Self::HwBreakpointLen1,
            n if n == Self::HwBreakpointLen2.into_primitive() => Self::HwBreakpointLen2,
            n if n == Self::HwBreakpointLen4.into_primitive() => Self::HwBreakpointLen4,
            n if n == Self::HwBreakpointLen8.into_primitive() => Self::HwBreakpointLen8,
            _ => panic!("invalid hardware breakpoint size"),
        }
    }
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
///         perf_type,
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
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::PerfEvent;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_PERF_EVENT, &mut self.data)
    }

    /// Attaches to the given perf event.
    ///
    /// [`perf_config`](PerfEventConfig) defines the event `type` and `config` of
    /// interest.
    ///
    /// [`scope`](PerfEventScope) determines which processes are sampled. If
    /// `inherit` is `true`, any new processes spawned by those processes will
    /// also automatically be sampled.
    ///
    /// The returned value can be used to detach, see [PerfEvent::detach].
    pub fn attach(
        &mut self,
        perf_config: PerfEventConfig,
        scope: PerfEventScope,
        sample_policy: SamplePolicy,
        inherit: bool,
    ) -> Result<PerfEventLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();

        let mut breakpoint = None;
        let (perf_type, config) = match perf_config {
            PerfEventConfig::Pmu { pmu_type, config } => (pmu_type, config),
            PerfEventConfig::Hardware(hw_event) => (
                perf_type_id_to_u32(PERF_TYPE_HARDWARE),
                u64::from(hw_event.into_primitive()),
            ),
            PerfEventConfig::Software(sw_event) => (
                perf_type_id_to_u32(PERF_TYPE_SOFTWARE),
                u64::from(sw_event.into_primitive()),
            ),
            PerfEventConfig::TracePoint { event_id } => {
                (perf_type_id_to_u32(PERF_TYPE_TRACEPOINT), event_id)
            }
            PerfEventConfig::HwCache {
                event,
                operation,
                result,
            } => (
                perf_type_id_to_u32(PERF_TYPE_HW_CACHE),
                u64::from(event.into_primitive())
                    | (u64::from(operation.into_primitive()) << 8)
                    | (u64::from(result.into_primitive()) << 16),
            ),
            PerfEventConfig::Raw { event_id } => (perf_type_id_to_u32(PERF_TYPE_RAW), event_id),
            PerfEventConfig::Breakpoint(config) => {
                breakpoint = Some(config);
                (perf_type_id_to_u32(PERF_TYPE_BREAKPOINT), 0)
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
            perf_type,
            config,
            pid,
            cpu,
            sample_period,
            sample_frequency,
            inherit,
            0,
            breakpoint,
        )
        .map_err(|io_error| SyscallError {
            call: "perf_event_open",
            io_error,
        })?;

        let link = perf_attach(prog_fd, fd, None /* cookie */)?;
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
