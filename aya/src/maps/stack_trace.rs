//! A hash map of kernel or user space stack traces.
//!
//! See [`StackTraceMap`] for documentation and examples.
use std::{borrow::Borrow, fs, io, mem, path::Path, str::FromStr};

use crate::{
    maps::{IterableMap, MapData, MapError, MapIter, MapKeys},
    sys::{bpf_map_lookup_elem_ptr, SyscallError},
};

/// A hash map of kernel or user space stack traces.
///
/// Stack trace maps can be used to store stack traces captured by eBPF programs, which can be
/// useful for profiling, to associate a trace to an event, etc. You can capture traces calling
/// `stack_id = bpf_get_stackid(ctx, map, flags)` from eBPF, and then you can retrieve the traces
/// from their stack ids.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.6.
///  
/// # Examples
///
/// ```no_run
/// # #[derive(thiserror::Error, Debug)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     IO(#[from] std::io::Error),
/// #     #[error(transparent)]
/// #     Map(#[from] aya::maps::MapError),
/// #     #[error(transparent)]
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let bpf = aya::Bpf::load(&[])?;
/// use aya::maps::StackTraceMap;
/// use aya::util::kernel_symbols;
///
/// let mut stack_traces = StackTraceMap::try_from(bpf.map("STACK_TRACES").unwrap())?;
/// // load kernel symbols from /proc/kallsyms
/// let ksyms = kernel_symbols()?;
///
/// // NOTE: you typically send stack_ids from eBPF to user space using other maps
/// let stack_id = 1234;
/// let mut stack_trace = stack_traces.get(&stack_id, 0)?;
///
/// // here we resolve symbol names using kernel symbols. If this was a user space stack (for
/// // example captured from a uprobe), you'd have to load the symbols using some other mechanism
/// // (eg loading the target binary debuginfo)
/// for frame in stack_trace.frames() {
///     if let Some(sym) = ksyms.range(..=frame.ip).next_back().map(|(_, s)| s) {
///         println!(
///             "{:#x} {}",
///             frame.ip,
///             sym
///         );
///     } else {
///         println!(
///             "{:#x}",
///             frame.ip
///         );
///     }
/// }
///
/// # Ok::<(), Error>(())
/// ```
///
#[derive(Debug)]
#[doc(alias = "BPF_MAP_TYPE_STACK_TRACE")]
pub struct StackTraceMap<T> {
    inner: T,
    max_stack_depth: usize,
}

impl<T: Borrow<MapData>> StackTraceMap<T> {
    pub(crate) fn new(map: T) -> Result<StackTraceMap<T>, MapError> {
        let data = map.borrow();
        let expected = mem::size_of::<u32>();
        let size = data.obj.key_size() as usize;
        if size != expected {
            return Err(MapError::InvalidKeySize { size, expected });
        }

        let max_stack_depth =
            sysctl::<usize>("kernel/perf_event_max_stack").map_err(|io_error| SyscallError {
                call: "sysctl",
                io_error,
            })?;
        let size = data.obj.value_size() as usize;
        if size > max_stack_depth * mem::size_of::<u64>() {
            return Err(MapError::InvalidValueSize { size, expected });
        }
        let _fd = data.fd_or_err()?;

        Ok(StackTraceMap {
            inner: map,
            max_stack_depth,
        })
    }

    /// Returns the stack trace with the given stack_id.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::KeyNotFound`] if there is no stack trace with the
    /// given `stack_id`, or [`MapError::SyscallError`] if `bpf_map_lookup_elem` fails.
    pub fn get(&self, stack_id: &u32, flags: u64) -> Result<StackTrace, MapError> {
        let fd = self.inner.borrow().fd_or_err()?;

        let mut frames = vec![0; self.max_stack_depth];
        bpf_map_lookup_elem_ptr(fd, Some(stack_id), frames.as_mut_ptr(), flags)
            .map_err(|(_, io_error)| SyscallError {
                call: "bpf_map_lookup_elem",
                io_error,
            })?
            .ok_or(MapError::KeyNotFound)?;

        let frames = frames
            .into_iter()
            .take_while(|ip| *ip != 0)
            .map(|ip| StackFrame { ip })
            .collect::<Vec<_>>();

        Ok(StackTrace {
            id: *stack_id,
            frames,
        })
    }

    /// An iterator visiting all (`stack_id`, `stack_trace`) pairs in arbitrary order. The
    /// iterator item type is `Result<(u32, StackTrace), MapError>`.
    pub fn iter(&self) -> MapIter<'_, u32, StackTrace, Self> {
        MapIter::new(self)
    }

    /// An iterator visiting all the stack_ids in arbitrary order. The iterator element
    /// type is `Result<u32, MapError>`.
    pub fn stack_ids(&self) -> MapKeys<'_, u32> {
        MapKeys::new(self.inner.borrow())
    }
}

impl<T: Borrow<MapData>> IterableMap<u32, StackTrace> for StackTraceMap<T> {
    fn map(&self) -> &MapData {
        self.inner.borrow()
    }

    fn get(&self, index: &u32) -> Result<StackTrace, MapError> {
        self.get(index, 0)
    }
}

impl<'a, T: Borrow<MapData>> IntoIterator for &'a StackTraceMap<T> {
    type Item = Result<(u32, StackTrace), MapError>;
    type IntoIter = MapIter<'a, u32, StackTrace, StackTraceMap<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// A kernel or user space stack trace.
///
/// See the [`StackTraceMap`] documentation for examples.
pub struct StackTrace {
    /// The stack trace id as returned by `bpf_get_stackid()`.
    pub id: u32,
    frames: Vec<StackFrame>,
}

impl StackTrace {
    /// Returns the frames in this stack trace.
    pub fn frames(&self) -> &[StackFrame] {
        &self.frames
    }
}

/// A stack frame.
pub struct StackFrame {
    /// The instruction pointer of this frame.
    pub ip: u64,
}

fn sysctl<T: FromStr>(key: &str) -> Result<T, io::Error> {
    let val = fs::read_to_string(Path::new("/proc/sys").join(key))?;
    val.trim()
        .parse::<T>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, val))
}
