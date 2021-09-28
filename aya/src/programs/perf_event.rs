//! Perf event programs.
use crate::{generated::bpf_prog_type::BPF_PROG_TYPE_PERF_EVENT, sys::perf_event_open};

use crate::generated::perf_type_id::{
    PERF_TYPE_BREAKPOINT, PERF_TYPE_HARDWARE, PERF_TYPE_HW_CACHE, PERF_TYPE_RAW,
    PERF_TYPE_SOFTWARE, PERF_TYPE_TRACEPOINT,
};

pub use crate::generated::{
    perf_hw_cache_id, perf_hw_cache_op_id, perf_hw_cache_op_result_id, perf_hw_id, perf_sw_ids,
};

use super::{load_program, perf_attach, LinkRef, ProgramData, ProgramError};

#[repr(u32)]
#[derive(Debug, Clone)]
pub enum PerfTypeId {
    Hardware = PERF_TYPE_HARDWARE as u32,
    Software = PERF_TYPE_SOFTWARE as u32,
    TracePoint = PERF_TYPE_TRACEPOINT as u32,
    HwCache = PERF_TYPE_HW_CACHE as u32,
    Raw = PERF_TYPE_RAW as u32,
    Breakpoint = PERF_TYPE_BREAKPOINT as u32,
}

#[derive(Debug, Clone)]
pub enum SamplePolicy {
    Period(u64),
    Frequency(u64),
}

#[derive(Debug, Clone)]
#[allow(clippy::enum_variant_names)]
pub enum PerfEventScope {
    CallingProcessAnyCpu,
    CallingProcessOneCpu { cpu: u32 },
    OneProcessAnyCpu { pid: u32 },
    OneProcessOneCpu { cpu: u32, pid: u32 },
    AllProcessesOneCpu { cpu: u32 },
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
/// use std::convert::TryInto;
/// use aya::util::online_cpus;
/// use aya::programs::perf_event::{
///     perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK, PerfEvent, PerfEventScope, PerfTypeId, SamplePolicy,
/// };
///
/// let prog: &mut PerfEvent = bpf.program_mut("observe_cpu_clock")?.try_into()?;
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
    pub(crate) data: ProgramData,
}

impl PerfEvent {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::programs::Program::load).
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_PERF_EVENT, &mut self.data)
    }

    /// Attaches to the given perf event.
    ///
    /// The possible values and encoding of the `config` argument depends on the
    /// `perf_type`. See `perf_sw_ids`, `perf_hw_id`, `perf_hw_cache_id`,
    /// `perf_hw_cache_op_id` and `perf_hw_cache_op_result_id`.
    pub fn attach(
        &mut self,
        perf_type: PerfTypeId,
        config: u64,
        scope: PerfEventScope,
        sample_policy: SamplePolicy,
    ) -> Result<LinkRef, ProgramError> {
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
            0,
        )
        .map_err(|(_code, io_error)| ProgramError::SyscallError {
            call: "perf_event_open".to_owned(),
            io_error,
        })? as i32;

        perf_attach(&mut self.data, fd)
    }
}
