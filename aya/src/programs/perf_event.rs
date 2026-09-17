//! Perf event programs and groups.

use std::{
    io, iter,
    os::fd::{AsFd as _, BorrowedFd},
};

use aya_obj::generated::{
    HW_BREAKPOINT_LEN_1, HW_BREAKPOINT_LEN_2, HW_BREAKPOINT_LEN_4, HW_BREAKPOINT_LEN_8,
    HW_BREAKPOINT_R, HW_BREAKPOINT_RW, HW_BREAKPOINT_W, bpf_link_type,
    bpf_prog_type::BPF_PROG_TYPE_PERF_EVENT, perf_hw_cache_id, perf_hw_cache_op_id,
    perf_hw_cache_op_result_id, perf_hw_id, perf_sw_ids, perf_type_id,
};
use thiserror::Error;

use crate::{
    MockableFd,
    programs::{
        ProgramData, ProgramError, ProgramType, impl_try_from_fdlink, impl_try_into_fdlink,
        links::define_link_wrapper,
        load_program_without_attach_type,
        perf_attach::{PerfLinkIdInner, PerfLinkInner, perf_attach},
    },
    sys::{
        PerfEventIoctlRequest, SyscallError, perf_event_ioctl, perf_event_open,
        perf_event_open_group_member, perf_event_read,
    },
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
        $(pub(crate) const fn $fn(id: $t) -> u32 {
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
    pub(crate) const fn into_primitive(self) -> u32 {
        const _: [(); 4] = [(); size_of::<HardwareEvent>()];
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
    /// Number of context switches.
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
    pub(crate) const fn into_primitive(self) -> u32 {
        const _: [(); 4] = [(); size_of::<SoftwareEvent>()];
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
    pub(crate) const fn into_primitive(self) -> u32 {
        const _: [(); 4] = [(); size_of::<HwCacheEvent>()];
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
    pub(crate) const fn into_primitive(self) -> u32 {
        const _: [(); 4] = [(); size_of::<HwCacheOp>()];
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
    pub(crate) const fn into_primitive(self) -> u32 {
        const _: [(); 4] = [(); size_of::<HwCacheResult>()];
        self as u32
    }
}

/// The breakpoint type.
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum PerfBreakpointType {
    /// `HW_BREAKPOINT_R`, trigger when we read the memory location.
    #[doc(alias = "HW_BREAKPOINT_R")]
    Read = HW_BREAKPOINT_R,
    /// `HW_BREAKPOINT_W`, trigger when we write the memory location.
    #[doc(alias = "HW_BREAKPOINT_W")]
    Write = HW_BREAKPOINT_W,
    /// `HW_BREAKPOINT_RW`, trigger when we read or write the memory location.
    #[doc(alias = "HW_BREAKPOINT_RW")]
    ReadWrite = HW_BREAKPOINT_RW,
}

impl PerfBreakpointType {
    pub(crate) const fn into_primitive(self) -> u32 {
        const _: [(); 4] = [(); size_of::<PerfBreakpointType>()];
        self as u32
    }
}

/// The number of bytes covered by a data breakpoint.
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum PerfBreakpointLength {
    /// `HW_BREAKPOINT_LEN_1`
    #[doc(alias = "HW_BREAKPOINT_LEN_1")]
    Len1 = HW_BREAKPOINT_LEN_1,
    /// `HW_BREAKPOINT_LEN_2`
    #[doc(alias = "HW_BREAKPOINT_LEN_2")]
    Len2 = HW_BREAKPOINT_LEN_2,
    /// `HW_BREAKPOINT_LEN_4`
    #[doc(alias = "HW_BREAKPOINT_LEN_4")]
    Len4 = HW_BREAKPOINT_LEN_4,
    /// `HW_BREAKPOINT_LEN_8`
    #[doc(alias = "HW_BREAKPOINT_LEN_8")]
    Len8 = HW_BREAKPOINT_LEN_8,
}

impl PerfBreakpointLength {
    pub(crate) const fn into_primitive(self) -> u32 {
        const _: [(); 4] = [(); size_of::<PerfBreakpointLength>()];
        self as u32
    }
}

/// Type of hardware breakpoint, determines if we break on read, write, or
/// execute, or if there should be no breakpoint on the given address.
#[derive(Debug, Clone, Copy)]
pub enum BreakpointConfig {
    /// A memory access breakpoint.
    Data {
        /// The type of the breakpoint.
        r#type: PerfBreakpointType,
        /// The address of the breakpoint.
        address: u64,
        /// The contiguous byte window to monitor starting at `address`.
        length: PerfBreakpointLength,
    },
    /// A code execution breakpoint.
    #[doc(alias = "HW_BREAKPOINT_X")]
    Instruction {
        /// The address of the breakpoint.
        address: u64,
    },
}

/// Sample Policy
#[derive(Debug, Clone, Copy)]
pub enum SamplePolicy {
    /// Period
    Period(u64),
    /// Frequency
    Frequency(u64),
}

/// Wakeup Policy
#[derive(Debug, Clone, Copy)]
pub(crate) enum WakeupPolicy {
    /// Every N events
    Events(u32),
    /// Every N bytes
    #[expect(dead_code, reason = "TODO")]
    Watermark(u32),
}

/// The scope of a [`PerfEvent`].
#[derive(Debug, Clone, Copy)]
pub enum PerfEventScope {
    /// calling process
    CallingProcess {
        /// cpu id or any cpu if None
        cpu: Option<u32>,
    },
    /// one process
    OneProcess {
        /// process id
        pid: u32,
        /// cpu id or any cpu if None
        cpu: Option<u32>,
    },
    /// all processes, one cpu
    AllProcessesOneCpu {
        /// cpu id
        cpu: u32,
    },
}

/// An error returned when opening a [`PerfEventGroup`].
#[derive(Debug, Error)]
#[error("failed to open perf event at index {event_index}: {io_error}")]
pub struct PerfEventGroupOpenError {
    /// The index of the event that failed to open. Zero identifies the group
    /// leader, and subsequent indices identify members in iteration order.
    pub event_index: usize,
    /// The error returned by `perf_event_open`.
    #[source]
    pub io_error: io::Error,
}

/// A simultaneous reading from a [`PerfEventGroup`].
///
/// `enabled_nanos` and `running_nanos` can differ when the kernel multiplexes
/// the group. If `running_nanos` is nonzero, each counter can be normalized as
/// `u128::from(value) * u128::from(enabled_nanos) / u128::from(running_nanos)`.
/// A zero `running_nanos` means that the group was never scheduled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfEventGroupRead<'a> {
    /// Counter values in the same order as the configurations passed to
    /// [`PerfEventGroup::open`].
    pub values: &'a [u64],
    /// Duration in nanoseconds for which the group was enabled.
    pub enabled_nanos: u64,
    /// Duration in nanoseconds for which the group was running.
    pub running_nanos: u64,
}

/// A group of perf events scheduled together by the kernel.
///
/// The kernel attempts to schedule every event in a group simultaneously.
/// This is useful when values will be compared, such as instructions per
/// cycle, because every counter covers the same execution intervals. The
/// group is disabled when it is opened and when it is dropped.
///
/// # Example
///
/// ```no_run
/// use aya::programs::perf_event::{
///     HardwareEvent, PerfEventConfig, PerfEventGroup, PerfEventScope,
/// };
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut group = PerfEventGroup::open(
///     PerfEventConfig::Hardware(HardwareEvent::CpuCycles),
///     [PerfEventConfig::Hardware(HardwareEvent::Instructions)],
///     PerfEventScope::CallingProcess { cpu: None },
/// )?;
///
/// group.reset()?;
/// group.enable()?;
/// // Run the workload being measured.
/// group.disable()?;
///
/// let read = group.read()?;
/// println!("cycles: {}, instructions: {}", read.values[0], read.values[1]);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct PerfEventGroup {
    leader: MockableFd,
    members: Box<[MockableFd]>,
    read_buffer: Box<[u64]>,
}

impl Drop for PerfEventGroup {
    fn drop(&mut self) {
        let _unused: Result<(), io::Error> = self.disable();
    }
}

impl PerfEventGroup {
    /// Opens a perf event group for `scope`.
    ///
    /// `leader` becomes the group leader. The remaining configurations are
    /// added as siblings in iteration order.
    ///
    /// The group is opened disabled. Call [`PerfEventGroup::enable`] to start
    /// counting.
    ///
    /// # Errors
    ///
    /// Returns [`PerfEventGroupOpenError`] if `perf_event_open` fails. The
    /// error identifies which event failed to open.
    pub fn open(
        leader: PerfEventConfig,
        members: impl IntoIterator<Item = PerfEventConfig>,
        scope: PerfEventScope,
    ) -> Result<Self, PerfEventGroupOpenError> {
        let leader = perf_event_open_group_member(leader, scope, None).map_err(|io_error| {
            PerfEventGroupOpenError {
                event_index: 0,
                io_error,
            }
        })?;
        let members = members
            .into_iter()
            .enumerate()
            .map(|(index, config)| {
                perf_event_open_group_member(config, scope, Some(leader.as_fd())).map_err(
                    |io_error| PerfEventGroupOpenError {
                        event_index: index + 1,
                        io_error,
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();

        let read_buffer = vec![0; members.len() + 4].into_boxed_slice();
        Ok(Self {
            leader,
            members,
            read_buffer,
        })
    }

    /// Returns the file descriptors for the leader followed by every group
    /// member in the order supplied to [`PerfEventGroup::open`].
    ///
    /// These descriptors can be inserted into a
    /// [`PerfEventArray`](crate::maps::PerfEventArray) with
    /// [`PerfEventArray::set`](crate::maps::PerfEventArray::set).
    pub fn events(&self) -> impl Iterator<Item = BorrowedFd<'_>> {
        iter::once(self.leader.as_fd()).chain(self.members.iter().map(|event| event.as_fd()))
    }

    /// Enables every event in the group.
    ///
    /// # Errors
    ///
    /// Returns the error from the `PERF_EVENT_IOC_ENABLE` ioctl.
    pub fn enable(&self) -> io::Result<()> {
        perf_event_ioctl(
            self.leader.as_fd(),
            PerfEventIoctlRequest::Enable { group: true },
        )
    }

    /// Disables every event in the group.
    ///
    /// Disabling preserves the accumulated counter values.
    ///
    /// # Errors
    ///
    /// Returns the error from the `PERF_EVENT_IOC_DISABLE` ioctl.
    pub fn disable(&self) -> io::Result<()> {
        perf_event_ioctl(
            self.leader.as_fd(),
            PerfEventIoctlRequest::Disable { group: true },
        )
    }

    /// Resets every counter value in the group to zero.
    ///
    /// This does not reset [`PerfEventGroupRead::enabled_nanos`] or
    /// [`PerfEventGroupRead::running_nanos`].
    ///
    /// # Errors
    ///
    /// Returns the error from the `PERF_EVENT_IOC_RESET` ioctl.
    pub fn reset(&self) -> io::Result<()> {
        perf_event_ioctl(
            self.leader.as_fd(),
            PerfEventIoctlRequest::Reset { group: true },
        )
    }

    /// Reads every counter in the group.
    ///
    /// # Errors
    ///
    /// Returns an error if `read` fails or the kernel returns an unexpected
    /// number of counters.
    pub fn read(&mut self) -> io::Result<PerfEventGroupRead<'_>> {
        perf_event_read(self.leader.as_fd(), &mut self.read_buffer)?;

        let ([event_count, enabled_nanos, running_nanos], values) = self
            .read_buffer
            .split_first_chunk::<3>()
            .expect("read buffer always contains a complete header by construction");
        let event_count = usize::try_from(*event_count).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("perf event group returned an invalid event count: {error}"),
            )
        })?;
        if event_count != values.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "perf event group returned {event_count} counters, expected {}",
                    values.len()
                ),
            ));
        }

        Ok(PerfEventGroupRead {
            values,
            enabled_nanos: *enabled_nanos,
            running_nanos: *running_nanos,
        })
    }
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
        let Self { data } = self;
        load_program_without_attach_type(BPF_PROG_TYPE_PERF_EVENT, data)
    }

    /// Attaches to the given perf event.
    ///
    /// If `inherit` is `true`, any new processes spawned by those processes
    /// will also automatically be sampled.
    ///
    /// The returned value can be used to detach, see [`Self::detach`].
    pub fn attach(
        &mut self,
        config: PerfEventConfig,
        scope: PerfEventScope,
        sample_policy: SamplePolicy,
        inherit: bool,
    ) -> Result<PerfEventLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();

        let perf_fd = perf_event_open(
            config,
            scope,
            sample_policy,
            WakeupPolicy::Events(1),
            inherit,
            0,
        )
        .map_err(|io_error| SyscallError {
            call: "perf_event_open",
            io_error,
        })?;

        let link = perf_attach(prog_fd, perf_fd, None /* cookie */)?;
        self.data.links.insert(PerfEventLink::new(link))
    }
}

impl_try_into_fdlink!(PerfEventLink, PerfLinkInner);
impl_try_from_fdlink!(
    PerfEventLink,
    PerfLinkInner,
    bpf_link_type::BPF_LINK_TYPE_PERF_EVENT
);

define_link_wrapper!(
    PerfEventLink,
    PerfEventLinkId,
    PerfLinkInner,
    PerfLinkIdInner,
    PerfEvent,
);
