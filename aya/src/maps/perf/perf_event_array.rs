//! A map that can be used to receive events from eBPF programs using the linux [`perf`] API
//!
//! [`perf`]: https://perf.wiki.kernel.org/index.php/Main_Page.
use std::{
    convert::TryFrom,
    ops::DerefMut,
    os::unix::io::{AsRawFd, RawFd},
    sync::Arc,
};

use bytes::BytesMut;
use libc::{sysconf, _SC_PAGESIZE};

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    maps::{
        perf::{Events, PerfBuffer, PerfBufferError},
        Map, MapError, MapRefMut,
    },
    sys::bpf_map_update_elem,
};

/// A ring buffer that can receive events from eBPF programs.
///
/// [`PerfEventArrayBuffer`] is a ring buffer that can receive events from eBPF
/// programs that use `bpf_perf_event_output()`. It's returned by [`PerfEventArray::open`].
///
/// See the [`PerfEventArray` documentation](PerfEventArray) for an overview of how to use
/// perf buffers.
pub struct PerfEventArrayBuffer<T: DerefMut<Target = Map>> {
    _map: Arc<T>,
    buf: PerfBuffer,
}

impl<T: DerefMut<Target = Map>> PerfEventArrayBuffer<T> {
    /// Returns true if the buffer contains events that haven't been read.
    pub fn readable(&self) -> bool {
        self.buf.readable()
    }

    /// Reads events from the buffer.
    ///
    /// This method reads events into the provided slice of buffers, filling
    /// each buffer in order stopping when there are no more events to read or
    /// all the buffers have been filled.
    ///
    /// Returns the number of events read and the number of events lost. Events
    /// are lost when user space doesn't read events fast enough and the ring
    /// buffer fills up.
    ///
    /// # Errors
    ///
    /// [`PerfBufferError::NoBuffers`] is returned when `out_bufs` is empty.
    ///
    /// [`PerfBufferError::MoreSpaceNeeded { size }`](PerfBufferError) is returned when the size of the events is
    /// bigger than the size of the out_bufs provided.
    pub fn read_events(&mut self, out_bufs: &mut [BytesMut]) -> Result<Events, PerfBufferError> {
        self.buf.read_events(out_bufs)
    }
}

impl<T: DerefMut<Target = Map>> AsRawFd for PerfEventArrayBuffer<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.buf.as_raw_fd()
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
/// * call [`PerfEventArrayBuffer::read_events`] to read the events
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
/// # use aya::maps::perf::PerfEventArrayBuffer;
/// # use aya::maps::Map;
/// # use std::ops::DerefMut;
/// # struct Poll<T> { _t: std::marker::PhantomData<T> };
/// # impl<T: DerefMut<Target=Map>> Poll<T> {
/// #    fn poll_readable(&self) -> &mut [PerfEventArrayBuffer<T>] {
/// #        &mut []
/// #    }
/// # }
/// # fn poll_buffers<T: DerefMut<Target=Map>>(bufs: Vec<PerfEventArrayBuffer<T>>) -> Poll<T> {
/// #    Poll { _t: std::marker::PhantomData }
/// # }
/// # #[derive(thiserror::Error, Debug)]
/// # enum Error {
/// #    #[error(transparent)]
/// #    IO(#[from] std::io::Error),
/// #    #[error(transparent)]
/// #    Map(#[from] aya::maps::MapError),
/// #    #[error(transparent)]
/// #    Bpf(#[from] aya::BpfError),
/// #    #[error(transparent)]
/// #    PerfBuf(#[from] aya::maps::perf::PerfBufferError),
/// # }
/// # let bpf = aya::Bpf::load(&[], None)?;
/// use aya::maps::PerfEventArray;
/// use aya::util::online_cpus;
/// use std::convert::{TryFrom, TryInto};
/// use bytes::BytesMut;
///
/// let mut perf_array = PerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
///
/// // eBPF programs are going to write to the EVENTS perf array, using the id of the CPU they're
/// // running on as the array index.
/// let mut perf_buffers = Vec::new();
/// for cpu_id in online_cpus()? {
///     // this perf buffer will receive events generated on the CPU with id cpu_id
///     perf_buffers.push(perf_array.open(cpu_id, None)?);
/// }
///
/// let mut out_bufs = [BytesMut::with_capacity(1024)];
///
/// // poll the buffers to know when they have queued events
/// let poll = poll_buffers(perf_buffers);
/// loop {
///     for read_buf in poll.poll_readable() {
///         read_buf.read_events(&mut out_bufs)?;
///         // process out_bufs
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
/// # Async
///
/// If you are using [tokio] or [async-std], you should use `AsyncPerfEventArray` which
/// efficiently integrates with those and provides a nicer `Future` based API.
///
/// [`perf`]: https://perf.wiki.kernel.org/index.php/Main_Page
/// [epoll]: https://docs.rs/epoll
/// [mio]: https://docs.rs/mio
/// [tokio]: https://docs.rs/tokio
/// [async-std]: https://docs.rs/async-std
#[doc(alias = "BPF_MAP_TYPE_PERF_EVENT_ARRAY")]
pub struct PerfEventArray<T: DerefMut<Target = Map>> {
    map: Arc<T>,
    page_size: usize,
}

impl<T: DerefMut<Target = Map>> PerfEventArray<T> {
    pub(crate) fn new(map: T) -> Result<PerfEventArray<T>, MapError> {
        let map_type = map.obj.def.map_type;
        if map_type != BPF_MAP_TYPE_PERF_EVENT_ARRAY as u32 {
            return Err(MapError::InvalidMapType {
                map_type: map_type as u32,
            });
        }
        let _fd = map.fd_or_err()?;

        Ok(PerfEventArray {
            map: Arc::new(map),
            // Safety: libc
            page_size: unsafe { sysconf(_SC_PAGESIZE) } as usize,
        })
    }

    /// Opens the perf buffer at the given index.
    ///
    /// The returned buffer will receive all the events eBPF programs send at the given index.
    pub fn open(
        &mut self,
        index: u32,
        page_count: Option<usize>,
    ) -> Result<PerfEventArrayBuffer<T>, PerfBufferError> {
        // FIXME: keep track of open buffers

        // this cannot fail as new() checks that the fd is open
        let map_fd = self.map.fd_or_err().unwrap();
        let buf = PerfBuffer::open(index, self.page_size, page_count.unwrap_or(2))?;
        bpf_map_update_elem(map_fd, &index, &buf.as_raw_fd(), 0)
            .map_err(|(_, io_error)| io_error)?;

        Ok(PerfEventArrayBuffer {
            buf,
            _map: self.map.clone(),
        })
    }
}

impl TryFrom<MapRefMut> for PerfEventArray<MapRefMut> {
    type Error = MapError;

    fn try_from(a: MapRefMut) -> Result<PerfEventArray<MapRefMut>, MapError> {
        PerfEventArray::new(a)
    }
}
