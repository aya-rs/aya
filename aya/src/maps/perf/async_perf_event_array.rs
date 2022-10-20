use bytes::BytesMut;
use std::{
    convert::AsMut,
    os::unix::prelude::{AsRawFd, RawFd},
};

#[cfg(all(not(feature = "async_tokio"), feature = "async_std"))]
use async_io::Async;

#[cfg(feature = "async_tokio")]
use tokio::io::unix::AsyncFd;

use crate::maps::{
    perf::{Events, PerfBufferError, PerfEventArray, PerfEventArrayBuffer},
    MapData, MapError,
};

/// A `Future` based map that can be used to receive events from eBPF programs using the linux
/// [`perf`](https://perf.wiki.kernel.org/index.php/Main_Page) API.
///
/// This is the async version of [`PerfEventArray`], which provides integration
/// with [tokio](https://docs.rs/tokio) and [async-std](https:/docs.rs/async-std) and a nice `Future` based API.
///
/// To receive events you need to:
/// * call [`AsyncPerfEventArray::open`]
/// * call [`AsyncPerfEventArrayBuffer::read_events`] to read the events
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.3.
///
/// # Examples
///
/// ```no_run
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
/// # #[cfg(feature = "async_tokio")]
/// # async fn try_main() -> Result<(), Error> {
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
/// use aya::util::online_cpus;
/// use futures::future;
/// use bytes::BytesMut;
/// use tokio::task; // or async_std::task
///
/// // try to convert the PERF_ARRAY map to an AsyncPerfEventArray
/// let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("PERF_ARRAY").unwrap())?;
///
/// for cpu_id in online_cpus()? {
///     // open a separate perf buffer for each cpu
///     let mut buf = perf_array.open(cpu_id, None)?;
///
///     // process each perf buffer in a separate task
///     task::spawn(async move {
///         let mut buffers = (0..10)
///             .map(|_| BytesMut::with_capacity(1024))
///             .collect::<Vec<_>>();
///
///         loop {
///             // wait for events
///             let events = buf.read_events(&mut buffers).await?;
///
///             // events.read contains the number of events that have been read,
///             // and is always <= buffers.len()
///             for i in 0..events.read {
///                 let buf = &mut buffers[i];
///                 // process buf
///             }
///         }
///
///         Ok::<_, PerfBufferError>(())
///     });
/// }
///
/// # Ok(())
/// # }
/// ```
#[doc(alias = "BPF_MAP_TYPE_PERF_EVENT_ARRAY")]
pub struct AsyncPerfEventArray<T> {
    perf_map: PerfEventArray<T>,
}

impl<T: AsMut<MapData> + AsRef<MapData>> AsyncPerfEventArray<T> {
    /// Opens the perf buffer at the given index.
    ///
    /// The returned buffer will receive all the events eBPF programs send at the given index.
    pub fn open(
        &mut self,
        index: u32,
        page_count: Option<usize>,
    ) -> Result<AsyncPerfEventArrayBuffer<T>, PerfBufferError> {
        let buf = self.perf_map.open(index, page_count)?;
        let fd = buf.as_raw_fd();
        Ok(AsyncPerfEventArrayBuffer {
            buf,

            #[cfg(feature = "async_tokio")]
            async_fd: AsyncFd::new(fd)?,

            #[cfg(all(not(feature = "async_tokio"), feature = "async_std"))]
            async_fd: Async::new(fd)?,
        })
    }
}

impl<T: AsRef<MapData>> AsyncPerfEventArray<T> {
    pub(crate) fn new(map: T) -> Result<AsyncPerfEventArray<T>, MapError> {
        Ok(AsyncPerfEventArray {
            perf_map: PerfEventArray::new(map)?,
        })
    }
}

/// A `Future` based ring buffer that can receive events from eBPF programs.
///
/// [`AsyncPerfEventArrayBuffer`] is a ring buffer that can receive events from eBPF programs that
/// use `bpf_perf_event_output()`. It's returned by [`AsyncPerfEventArray::open`].
///
/// See the [`AsyncPerfEventArray` documentation](AsyncPerfEventArray) for an overview of how to
/// use perf buffers.
pub struct AsyncPerfEventArrayBuffer<T> {
    buf: PerfEventArrayBuffer<T>,

    #[cfg(feature = "async_tokio")]
    async_fd: AsyncFd<RawFd>,

    #[cfg(all(not(feature = "async_tokio"), feature = "async_std"))]
    async_fd: Async<RawFd>,
}

#[cfg(any(feature = "async_tokio"))]
impl<T: AsMut<MapData> + AsRef<MapData>> AsyncPerfEventArrayBuffer<T> {
    /// Reads events from the buffer.
    ///
    /// This method reads events into the provided slice of buffers, filling
    /// each buffer in order stopping when there are no more events to read or
    /// all the buffers have been filled.
    ///
    /// Returns the number of events read and the number of events lost. Events
    /// are lost when user space doesn't read events fast enough and the ring
    /// buffer fills up.
    pub async fn read_events(
        &mut self,
        buffers: &mut [BytesMut],
    ) -> Result<Events, PerfBufferError> {
        loop {
            let mut guard = self.async_fd.readable_mut().await?;

            match self.buf.read_events(buffers) {
                Ok(events) if events.read > 0 || events.lost > 0 => return Ok(events),
                Ok(_) => {
                    guard.clear_ready();
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(all(not(feature = "async_tokio"), feature = "async_std"))]
impl<T: AsMut<MapData> + AsRef<MapData>> AsyncPerfEventArrayBuffer<T> {
    /// Reads events from the buffer.
    ///
    /// This method reads events into the provided slice of buffers, filling
    /// each buffer in order stopping when there are no more events to read or
    /// all the buffers have been filled.
    ///
    /// Returns the number of events read and the number of events lost. Events
    /// are lost when user space doesn't read events fast enough and the ring
    /// buffer fills up.
    pub async fn read_events(
        &mut self,
        buffers: &mut [BytesMut],
    ) -> Result<Events, PerfBufferError> {
        loop {
            if !self.buf.readable() {
                let _ = self.async_fd.readable().await?;
            }

            match self.buf.read_events(buffers) {
                Ok(events) if events.read > 0 || events.lost > 0 => return Ok(events),
                Ok(_) => continue,
                Err(e) => return Err(e),
            }
        }
    }
}
