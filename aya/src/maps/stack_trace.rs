//! A hash map of kernel or user space stack traces.
//!
//! See [`StackTraceMap`] for documentation and examples.

use std::{
    borrow::{Borrow, BorrowMut},
    os::fd::AsFd as _,
};

use aya_obj::generated::BPF_F_STACK_BUILD_ID;

use crate::{
    maps::{IterableMap, MapData, MapError, MapIter, MapKeys, hash_map},
    sys::{SyscallError, bpf_map_lookup_elem_ptr},
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
/// #     Ebpf(#[from] aya::EbpfError)
/// # }
/// # let bpf = aya::Ebpf::load(&[])?;
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
    pub(crate) inner: T,
    max_stack_depth: usize,
}

impl<T: Borrow<MapData>> StackTraceMap<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();

        let key_size = data.obj.key_size() as usize;
        let expected_key = size_of::<u32>();
        if key_size != expected_key {
            return Err(MapError::InvalidKeySize {
                size: key_size,
                expected: expected_key,
            });
        }

        // BPF_F_STACK_BUILD_ID switches stack entries to
        // `struct bpf_stack_build_id` (32 bytes), which `get` decodes as
        // `[u64]` and would silently corrupt. Reject it.
        let flags = data.obj.map_flags();
        if flags & BPF_F_STACK_BUILD_ID != 0 {
            return Err(MapError::UnsupportedMapFlags {
                flags,
                reason: "StackTraceMap does not support bpf_stack_build_id entries",
            });
        }

        let value_size = data.obj.value_size() as usize;
        let expected_stride = size_of::<u64>();
        if value_size == 0 || !value_size.is_multiple_of(expected_stride) {
            return Err(MapError::InvalidValueSize {
                size: value_size,
                expected: expected_stride,
            });
        }
        let max_stack_depth = value_size / expected_stride;

        Ok(Self {
            inner: map,
            max_stack_depth,
        })
    }

    /// Returns the stack trace with the given `stack_id`.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::KeyNotFound`] if there is no stack trace with the
    /// given `stack_id`, or [`MapError::SyscallError`] if `bpf_map_lookup_elem` fails.
    pub fn get(&self, stack_id: &u32, flags: u64) -> Result<StackTrace, MapError> {
        let fd = self.inner.borrow().fd().as_fd();

        let mut frames = vec![0; self.max_stack_depth];
        bpf_map_lookup_elem_ptr(fd, Some(stack_id), frames.as_mut_ptr(), flags)
            .map_err(|io_error| SyscallError {
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

    /// An iterator visiting all the `stack_ids` in arbitrary order. The iterator element
    /// type is `Result<u32, MapError>`.
    pub fn stack_ids(&self) -> MapKeys<'_, u32> {
        MapKeys::new(self.inner.borrow())
    }
}

impl<T: Borrow<MapData>> IterableMap<u32, StackTrace> for StackTraceMap<T> {
    fn map(&self) -> &MapData {
        self.inner.borrow()
    }

    fn get(&self, key: &u32) -> Result<StackTrace, MapError> {
        self.get(key, 0)
    }
}

impl<'a, T: Borrow<MapData>> IntoIterator for &'a StackTraceMap<T> {
    type Item = Result<(u32, StackTrace), MapError>;
    type IntoIter = MapIter<'a, u32, StackTrace, StackTraceMap<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T: BorrowMut<MapData>> StackTraceMap<T> {
    /// Removes the stack trace with the given `stack_id`.
    pub fn remove(&mut self, stack_id: &u32) -> Result<(), MapError> {
        hash_map::remove(self.inner.borrow_mut(), stack_id)
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
