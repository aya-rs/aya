//! Perf event programs.

use std::os::fd::{AsFd as _, OwnedFd};

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
    sys::{
        self, bpf_link_get_info_by_fd, SyscallError,
    },
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

/// Fields included in the event samples
#[derive(Debug, Clone)]
pub struct SampleType(u64);

/// "Wake up" overflow notification policy.
/// Overflows are generated only by sampling events.
#[derive(Debug, Clone)]
pub enum WakeUpPolicy {
    /// Wake up after n events
    WakeupEvents(u32),
    /// Wake up after n bytes
    WakeupWatermark(u32),
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
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use aya::util::online_cpus;
/// use aya::programs::perf_event::{
///     perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK, PerfEvent, PerfEventScope, PerfTypeId, SamplePolicy,
/// };
///
/// let prog: &mut PerfEvent = bpf.program_mut("observe_cpu_clock").unwrap().try_into()?;
/// prog.load()?;
///
/// for cpu in online_cpus()? {
///     prog.attach(
///         PerfTypeId::Software,
///         PERF_COUNT_SW_CPU_CLOCK as u64,
///         PerfEventScope::AllProcessesOneCpu { cpu },
///         SamplePolicy::Period(1000000),
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
    /// The returned value can be used to detach, see [PerfEvent::detach].
    pub fn attach(
        &mut self,
        perf_type: PerfTypeId,
        config: u64,
        scope: PerfEventScope,
        sample_policy: SamplePolicy,
    ) -> Result<PerfEventLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();

        let sampling = Some((sample_policy, SampleType(PERF_TYPE_RAW as u64)));
        let event_fd = perf_event_open(perf_type as u32, config, scope, sampling, None, 0)?;

        let link = perf_attach(prog_fd, event_fd)?;
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

/// Performs a call to `perf_event_open` and returns the event's file descriptor.
/// 
/// # Arguments
/// 
/// * `perf_type` - the type of event, see [`crate::generated::perf_type_id`] for a list of types. Note that this list is non-exhaustive, because PMUs (Performance Monitoring Units) can be added to the system. Their ids can be read from the sysfs (see the kernel documentation on perf_event_open).
/// * `config` - the event that we want to open
/// * `scope` - which process and cpu to monitor (logical cpu, not physical socket)
/// * `sampling` - if not None, enables the sampling mode with the given parameters
/// * `wakeup` - if not None, sets up the wake-up for the overflow notifications
/// * `flags` - various flags combined with a binary OR (for ex. `FLAG_A | FLAG_B`), zero means no flag
pub fn perf_event_open(
    perf_type: u32,
    config: u64,
    scope: PerfEventScope,
    sampling: Option<(SamplePolicy, SampleType)>,
    wakeup: Option<WakeUpPolicy>,
    flags: u32,
) -> Result<OwnedFd, SyscallError> {
    let mut attr = sys::init_perf_event_attr();

    // Fill in the attributes
    attr.type_ = perf_type;
    attr.config = config;
    match sampling {
        Some((SamplePolicy::Frequency(f), SampleType(t))) => {
            attr.set_freq(1);
            attr.__bindgen_anon_1.sample_freq = f;
            attr.sample_type = t;
        }
        Some((SamplePolicy::Period(p), SampleType(t))) => {
            attr.__bindgen_anon_1.sample_period = p;
            attr.sample_type = t;
        }
        None => (),
    };
    match wakeup {
        Some(WakeUpPolicy::WakeupEvents(n)) => {
            attr.__bindgen_anon_2.wakeup_events = n;
        }
        Some(WakeUpPolicy::WakeupWatermark(n)) => {
            attr.set_watermark(1);
            attr.__bindgen_anon_2.wakeup_watermark = n;
        }
        None => (),
    };

    let (pid, cpu) = match scope {
        PerfEventScope::CallingProcessAnyCpu => (0, -1),
        PerfEventScope::CallingProcessOneCpu { cpu } => (0, cpu as i32),
        PerfEventScope::OneProcessAnyCpu { pid } => (pid as i32, -1),
        PerfEventScope::OneProcessOneCpu { cpu, pid } => (pid as i32, cpu as i32),
        PerfEventScope::AllProcessesOneCpu { cpu } => (-1, cpu as i32),
    };

    sys::perf_event_sys(attr, pid, cpu, flags).map_err(|(_, io_error)| SyscallError {
        call: "perf_event_open",
        io_error,
    })
}
