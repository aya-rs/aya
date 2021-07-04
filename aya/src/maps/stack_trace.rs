//! A hash map of kernel or user space stack traces.
//!
//! See [`StackTraceMap`] for documentation and examples.
use std::{
    collections::BTreeMap, convert::TryFrom, fs, io, mem, ops::Deref, path::Path, str::FromStr,
};

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_STACK_TRACE,
    maps::{IterableMap, Map, MapError, MapIter, MapKeys, MapRef, MapRefMut},
    sys::bpf_map_lookup_elem_ptr,
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
/// # let bpf = aya::Bpf::load(&[], None)?;
/// use aya::maps::StackTraceMap;
/// use aya::util::kernel_symbols;
/// use std::convert::TryFrom;
///
/// let mut stack_traces = StackTraceMap::try_from(bpf.map("STACK_TRACES")?)?;
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
/// for frame in stack_trace.resolve(&ksyms).frames() {
///     println!(
///         "{:#x} {}",
///         frame.ip,
///         frame
///             .symbol_name
///             .as_ref()
///             .unwrap_or(&"[unknown symbol name]".to_owned())
///     );
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

impl<T: Deref<Target = Map>> StackTraceMap<T> {
    fn new(map: T) -> Result<StackTraceMap<T>, MapError> {
        let map_type = map.obj.def.map_type;
        if map_type != BPF_MAP_TYPE_STACK_TRACE as u32 {
            return Err(MapError::InvalidMapType {
                map_type: map_type as u32,
            });
        }
        let expected = mem::size_of::<u32>();
        let size = map.obj.def.key_size as usize;
        if size != expected {
            return Err(MapError::InvalidKeySize { size, expected });
        }

        let max_stack_depth =
            sysctl::<usize>("kernel/perf_event_max_stack").map_err(|io_error| {
                MapError::SyscallError {
                    call: "sysctl".to_owned(),
                    code: -1,
                    io_error,
                }
            })?;
        let size = map.obj.def.value_size as usize;
        if size > max_stack_depth * mem::size_of::<u64>() {
            return Err(MapError::InvalidValueSize { size, expected });
        }
        let _fd = map.fd_or_err()?;

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
        let fd = self.inner.fd_or_err()?;

        let mut frames = vec![0; self.max_stack_depth];
        bpf_map_lookup_elem_ptr(fd, stack_id, frames.as_mut_ptr(), flags)
            .map_err(|(code, io_error)| MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                code,
                io_error,
            })?
            .ok_or(MapError::KeyNotFound)?;

        let frames = frames
            .drain(..)
            .take_while(|ip| *ip != 0)
            .map(|ip| StackFrame {
                ip,
                symbol_name: None,
            })
            .collect::<Vec<_>>();

        Ok(StackTrace {
            id: *stack_id,
            frames,
        })
    }

    /// An iterator visiting all (`stack_id`, `stack_trace`) pairs in arbitrary order. The
    /// iterator item type is `Result<(u32, StackTrace), MapError>`.
    pub fn iter(&self) -> MapIter<'_, u32, StackTrace> {
        MapIter::new(self)
    }

    /// An iterator visiting all the stack_ids in arbitrary order. The iterator element
    /// type is `Result<u32, MapError>`.
    pub fn stack_ids(&self) -> MapKeys<'_, u32> {
        MapKeys::new(&self.inner)
    }
}

impl<T: Deref<Target = Map>> IterableMap<u32, StackTrace> for StackTraceMap<T> {
    fn map(&self) -> &Map {
        &self.inner
    }

    unsafe fn get(&self, index: &u32) -> Result<StackTrace, MapError> {
        self.get(index, 0)
    }
}

impl TryFrom<MapRef> for StackTraceMap<MapRef> {
    type Error = MapError;

    fn try_from(a: MapRef) -> Result<StackTraceMap<MapRef>, MapError> {
        StackTraceMap::new(a)
    }
}

impl TryFrom<MapRefMut> for StackTraceMap<MapRefMut> {
    type Error = MapError;

    fn try_from(a: MapRefMut) -> Result<StackTraceMap<MapRefMut>, MapError> {
        StackTraceMap::new(a)
    }
}

impl<'a, T: Deref<Target = Map>> IntoIterator for &'a StackTraceMap<T> {
    type Item = Result<(u32, StackTrace), MapError>;
    type IntoIter = MapIter<'a, u32, StackTrace>;

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
    /// Resolves symbol names using the given symbol map.
    ///
    /// You can use [`util::kernel_symbols()`](crate::util::kernel_symbols) to load kernel symbols. For
    /// user-space traces you need to provide the symbols, for example loading
    /// them from debug info.
    pub fn resolve(&mut self, symbols: &BTreeMap<u64, String>) -> &StackTrace {
        for frame in self.frames.iter_mut() {
            frame.symbol_name = symbols
                .range(..=frame.ip)
                .next_back()
                .map(|(_, s)| s.clone())
        }

        self
    }

    /// Returns the frames in this stack trace.
    pub fn frames(&self) -> &[StackFrame] {
        &self.frames
    }
}

/// A stack frame.
pub struct StackFrame {
    /// The instruction pointer of this frame.
    pub ip: u64,
    /// The symbol name corresponding to the start of this frame.
    ///
    /// Set to `Some()` if the frame address can be found in the symbols passed
    /// to [`StackTrace::resolve`].
    pub symbol_name: Option<String>,
}

fn sysctl<T: FromStr>(key: &str) -> Result<T, io::Error> {
    let val = fs::read_to_string(Path::new("/proc/sys").join(key))?;
    val.trim()
        .parse::<T>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, val))
}
