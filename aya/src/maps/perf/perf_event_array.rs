//! A map that can be used to receive events from eBPF programs using the linux [`perf`] API
//!
//! [`perf`]: https://perf.wiki.kernel.org/index.php/Main_Page.

use std::{
    borrow::{Borrow, BorrowMut},
    ops::Deref as _,
    os::fd::{AsFd, AsRawFd as _},
    path::Path,
    sync::Arc,
};

use crate::maps::{MapData, MapError, PinError, check_bounds, hash_map};

/// A map that can be used to receive events from eBPF programs using the linux [`perf`] API.
///
/// Each element of a [`PerfEventArray`] can contain either a perf buffer used
/// by `bpf_perf_event_output()` or a perf event read by
/// `bpf_perf_event_read_value()`.
///
/// To receive events you need to:
/// * call [`PerfEventArrayBuffer::open`](super::PerfEventArrayBuffer::open)
/// * insert the buffer into the map with [`PerfEventArray::set`]
/// * poll the returned [`PerfEventArrayBuffer`](super::PerfEventArrayBuffer) to
///   be notified when events are inserted in the buffer
/// * drain events with [`PerfEventArrayBuffer::for_each`](super::PerfEventArrayBuffer::for_each)
///   (or [`fold`]/[`try_fold`])
///
/// [`fold`]: super::PerfEventArrayBuffer::fold
/// [`try_fold`]: super::PerfEventArrayBuffer::try_fold
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
/// # struct Poll;
/// # impl Poll {
/// #    fn poll_readable(&self) -> &mut [PerfEventArrayBuffer] {
/// #        &mut []
/// #    }
/// # }
/// # fn poll_buffers(bufs: Vec<PerfEventArrayBuffer>) -> Poll {
/// #    Poll
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
///     let perf_buffer = PerfEventArrayBuffer::open(cpu_id, 2)?;
///     perf_array.set(cpu_id, &perf_buffer)?;
///     perf_buffers.push(perf_buffer);
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
/// given. [`PerfEventArrayBuffer`](super::PerfEventArrayBuffer) implements the
/// [`AsRawFd`](std::os::fd::AsRawFd) trait, so you can implement polling
/// using any crate that can poll file descriptors, like [epoll], [mio] etc.
///
/// Perf buffers are internally implemented as ring buffers. If your eBPF programs produce large
/// amounts of data, in order not to lose events you might want to process each
/// [`PerfEventArrayBuffer`](super::PerfEventArrayBuffer) on a different thread.
///
/// [`perf`]: https://perf.wiki.kernel.org/index.php/Main_Page
/// [epoll]: https://docs.rs/epoll
/// [mio]: https://docs.rs/mio
#[doc(alias = "BPF_MAP_TYPE_PERF_EVENT_ARRAY")]
pub struct PerfEventArray<T> {
    map: Arc<T>,
}

impl<T: Borrow<MapData>> PerfEventArray<T> {
    #[expect(
        clippy::unnecessary_wraps,
        reason = "keeps constructor signatures consistent across map types"
    )]
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        Ok(Self { map: Arc::new(map) })
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
    /// Stores `event` at `index`.
    ///
    /// The map retains its own reference to the perf event, so the supplied
    /// file descriptor can be closed after this method succeeds. The event
    /// remains in the map until it is replaced, removed with
    /// [`PerfEventArray::unset`], or the map is closed.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, or
    /// [`MapError::SyscallError`] if `bpf_map_update_elem` fails.
    pub fn set(&mut self, index: u32, event: &impl AsFd) -> Result<(), MapError> {
        let map_data = self.map.deref().borrow();
        check_bounds(map_data, index)?;
        hash_map::insert(map_data, &index, &event.as_fd().as_raw_fd(), 0)
    }

    /// Removes the perf event stored at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, or
    /// [`MapError::SyscallError`] if `bpf_map_delete_elem` fails.
    pub fn unset(&mut self, index: u32) -> Result<(), MapError> {
        let map_data = self.map.deref().borrow();
        check_bounds(map_data, index)?;
        hash_map::remove(map_data, &index)
    }
}
