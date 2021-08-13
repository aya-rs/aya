use crate::{generated::bpf_prog_type::BPF_PROG_TYPE_PERF_EVENT, sys::perf_event_open};

pub use crate::generated::perf_type_id;

use super::{load_program, perf_attach, LinkRef, ProgramData, ProgramError};

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
/// TODO: Explain the different types of perf events and how to get a list.
/// Maybe just link to the man page of `perf list`.
/// (But it's not clear to me how to translate those strings into numbers.)
///
/// # Minimum kernel version
///
/// TODO: minimum kernel version?
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
/// # let mut bpf = aya::Bpf::load(&[], None)?;
/// use std::convert::TryInto;
/// use aya::programs::{PerfEvent, PerfEventScope, SamplePolicy };
/// use aya::util::online_cpus;
///
/// let prog: &mut PerfEvent = bpf.program_mut("observe_cpu_clock")?.try_into()?;
/// prog.load()?;
///
/// for cpu in online_cpus()? {
///     prog.attach(
///         1, /* PERF_TYPE_SOFTWARE */
///         0, /* PERF_COUNT_SW_CPU_CLOCK */
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

    /// Attaches to a given perf event.
    pub fn attach(
        &mut self,
        perf_type: u32, // perf_type_id
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
            perf_type,
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
