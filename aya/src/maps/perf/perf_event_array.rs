//! A map that can be used to receive events from eBPF programs using the linux [`perf`] API
//!
//! [`perf`]: https://perf.wiki.kernel.org/index.php/Main_Page.

use std::{
    borrow::{Borrow, BorrowMut},
    ops::{ControlFlow, Deref as _},
    os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd},
    path::Path,
    sync::Arc,
};

use crate::{
    maps::{
        MapData, MapError, PinError,
        perf::{PerfBuffer, PerfBufferError, PerfEvent},
    },
    sys::bpf_map_update_elem,
    util::page_size,
};

/// A ring buffer that can receive events from eBPF programs.
///
/// [`PerfEventArrayBuffer`] is a ring buffer that can receive events from eBPF
/// programs that use `bpf_perf_event_output()`. It's returned by [`PerfEventArray::open`].
///
/// See the [`PerfEventArray` documentation](PerfEventArray) for an overview of how to use
/// perf buffers.
pub struct PerfEventArrayBuffer<T> {
    _map: Arc<T>,
    buf: PerfBuffer,
}

impl<T: BorrowMut<MapData>> PerfEventArrayBuffer<T> {
    /// Returns true if the buffer contains events that haven't been read.
    pub fn readable(&self) -> bool {
        self.buf.readable()
    }

    /// Processes events available in the buffer with `f`.
    ///
    /// For each available event, `f` receives the accumulator and event:
    /// * [`ControlFlow::Continue(next)`](ControlFlow::Continue) keeps draining with `next`.
    /// * [`ControlFlow::Break(break_value)`](ControlFlow::Break) stops early and returns `break_value`.
    ///
    /// If the buffer is fully drained, returns [`ControlFlow::Continue`]
    /// containing the final accumulator.
    ///
    /// The slices in [`PerfEvent::Sample`] are borrowed directly from the perf
    /// ring buffer; the borrow is bounded by the closure invocation. The
    /// kernel-visible `data_tail` is advanced once at the end of the call,
    /// amortizing the `SeqCst` store across the drain.
    pub fn try_fold<B, C, F>(&mut self, init: C, f: F) -> ControlFlow<B, C>
    where
        F: FnMut(C, PerfEvent<'_>) -> ControlFlow<B, C>,
    {
        self.buf.try_fold(init, f)
    }

    /// Processes events available in the buffer with `f`.
    ///
    /// For each available event, `f` receives the accumulator and event, and
    /// returns the next accumulator. Unlike [`PerfEventArrayBuffer::try_fold`],
    /// this function cannot short-circuit: it always processes events until the
    /// buffer is fully drained, then returns the final accumulator.
    pub fn fold<C, F>(&mut self, init: C, f: F) -> C
    where
        F: FnMut(C, PerfEvent<'_>) -> C,
    {
        self.buf.fold(init, f)
    }

    /// Processes events available in the buffer with `f`.
    pub fn for_each<F>(&mut self, f: F)
    where
        F: FnMut(PerfEvent<'_>),
    {
        self.buf.for_each(f)
    }
}

impl<T: BorrowMut<MapData>> AsFd for PerfEventArrayBuffer<T> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.buf.as_fd()
    }
}

impl<T: BorrowMut<MapData>> AsRawFd for PerfEventArrayBuffer<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.as_fd().as_raw_fd()
    }
}

/// A map that can be used to receive events from eBPF programs using the linux [`perf`] API.
///
/// Each element of a [`PerfEventArray`] is a separate [`PerfEventArrayBuffer`] which can be used
/// to receive events sent by eBPF programs that use `bpf_perf_event_output()`.
///
/// To receive events you need to:
/// * call [`PerfEventArray::open`]
/// * poll the returned [`PerfEventArrayBuffer`] to be notified when events are
///   inserted in the buffer
/// * drain events with [`PerfEventArrayBuffer::for_each`] (or [`fold`]/[`try_fold`])
///
/// [`fold`]: PerfEventArrayBuffer::fold
/// [`try_fold`]: PerfEventArrayBuffer::try_fold
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.3.
///
/// # Examples
///
/// A common way to use a perf array is to have one perf buffer for each
/// available CPU:
///
/// ```no_run
/// # use aya::maps::perf::{PerfEvent, PerfEventArrayBuffer};
/// # use aya::maps::MapData;
/// # use std::borrow::BorrowMut;
/// # struct Poll<T> { _t: std::marker::PhantomData<T> };
/// # impl<T: BorrowMut<MapData>> Poll<T> {
/// #    fn poll_readable(&self) -> &mut [PerfEventArrayBuffer<T>] {
/// #        &mut []
/// #    }
/// # }
/// # fn poll_buffers<T: BorrowMut<MapData>>(bufs: Vec<PerfEventArrayBuffer<T>>) -> Poll<T> {
/// #    Poll { _t: std::marker::PhantomData }
/// # }
/// # #[derive(thiserror::Error, Debug)]
/// # enum Error {
/// #    #[error(transparent)]
/// #    IO(#[from] std::io::Error),
/// #    #[error(transparent)]
/// #    Map(#[from] aya::maps::MapError),
/// #    #[error(transparent)]
/// #    Ebpf(#[from] aya::EbpfError),
/// #    #[error(transparent)]
/// #    PerfBuf(#[from] aya::maps::perf::PerfBufferError),
/// # }
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::maps::PerfEventArray;
/// use aya::util::online_cpus;
///
/// let mut perf_array = PerfEventArray::try_from(bpf.map_mut("EVENTS").unwrap())?;
///
/// // eBPF programs are going to write to the EVENTS perf array, using the id of the CPU they're
/// // running on as the array index.
/// let mut perf_buffers = Vec::new();
/// for cpu_id in online_cpus().map_err(|(_, error)| error)? {
///     // this perf buffer will receive events generated on the CPU with id cpu_id
///     perf_buffers.push(perf_array.open(cpu_id, None)?);
/// }
///
/// // poll the buffers to know when they have queued events
/// let poll = poll_buffers(perf_buffers);
/// loop {
///     for perf_buf in poll.poll_readable() {
///         perf_buf.for_each(|event| match event {
///             PerfEvent::Sample { head, tail } => {
///                 // process the sample bytes (`tail` is empty unless the sample wraps)
///             }
///             PerfEvent::Lost { count } => {
///                 // record the dropped-events counter
///             }
///         });
///     }
/// }
///
/// # Ok::<(), Error>(())
/// ```
///
/// # Polling and avoiding lost events
///
/// In the example above the implementation of `poll_buffers()` and `poll.poll_readable()` is not
/// given. [`PerfEventArrayBuffer`] implements the [`AsRawFd`] trait, so you can implement polling
/// using any crate that can poll file descriptors, like [epoll], [mio] etc.
///
/// Perf buffers are internally implemented as ring buffers. If your eBPF programs produce large
/// amounts of data, in order not to lose events you might want to process each
/// [`PerfEventArrayBuffer`] on a different thread.
///
/// [`perf`]: https://perf.wiki.kernel.org/index.php/Main_Page
/// [epoll]: https://docs.rs/epoll
/// [mio]: https://docs.rs/mio
#[doc(alias = "BPF_MAP_TYPE_PERF_EVENT_ARRAY")]
pub struct PerfEventArray<T> {
    map: Arc<T>,
    page_size: usize,
}

impl<T: Borrow<MapData>> PerfEventArray<T> {
    #[expect(
        clippy::unnecessary_wraps,
        reason = "keeps constructor signatures consistent across map types"
    )]
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        Ok(Self {
            map: Arc::new(map),
            page_size: page_size(),
        })
    }

    /// Pins the map to a BPF filesystem.
    ///
    /// When a map is pinned it will remain loaded until the corresponding file
    /// is deleted. All parent directories in the given `path` must already exist.
    pub fn pin<P: AsRef<Path>>(&self, path: P) -> Result<(), PinError> {
        let data: &MapData = self.map.deref().borrow();
        data.pin(path)
    }

    pub(crate) fn map_data(&self) -> &MapData {
        self.map.deref().borrow()
    }
}

impl<T: BorrowMut<MapData>> PerfEventArray<T> {
    /// Opens the perf buffer at the given index.
    ///
    /// The returned buffer will receive all the events eBPF programs send at the given index.
    pub fn open(
        &mut self,
        index: u32,
        page_count: Option<usize>,
    ) -> Result<PerfEventArrayBuffer<T>, PerfBufferError> {
        // FIXME: keep track of open buffers

        let map_data: &MapData = self.map.deref().borrow();
        let map_fd = map_data.fd().as_fd();
        let buf = PerfBuffer::open(index, self.page_size, page_count.unwrap_or(2))?;
        bpf_map_update_elem(map_fd, Some(&index), &buf.as_fd().as_raw_fd(), 0)?;

        Ok(PerfEventArrayBuffer {
            buf,
            _map: Arc::clone(&self.map),
        })
    }
}
