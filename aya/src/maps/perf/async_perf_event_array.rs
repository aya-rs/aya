use std::{
    borrow::{Borrow, BorrowMut},
    path::Path,
};

// See https://doc.rust-lang.org/cargo/reference/features.html#mutually-exclusive-features.
//
// We should eventually split async functionality out into separate crates "aya-async-tokio" and
// "async-async-std". Presently we arbitrarily choose tokio over async-std when both are requested.
#[cfg(all(not(feature = "async_tokio"), feature = "async_std"))]
use async_io::Async;
use bytes::BytesMut;
#[cfg(feature = "async_tokio")]
use tokio::io::unix::AsyncFd;

use crate::maps::{
    perf::{Events, PerfBufferError, PerfEventArray, PerfEventArrayBuffer},
    MapData, MapError, PinError,
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
/// #    Ebpf(#[from] aya::EbpfError),
/// #    #[error(transparent)]
/// #    PerfBuf(#[from] aya::maps::perf::PerfBufferError),
/// # }
/// # #[cfg(feature = "async_tokio")]
/// # async fn try_main() -> Result<(), Error> {
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
/// use aya::util::online_cpus;
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

impl<T: BorrowMut<MapData>> AsyncPerfEventArray<T> {
    /// Opens the perf buffer at the given index.
    ///
    /// The returned buffer will receive all the events eBPF programs send at the given index.
    pub fn open(
        &mut self,
        index: u32,
        page_count: Option<usize>,
    ) -> Result<AsyncPerfEventArrayBuffer<T>, PerfBufferError> {
        let Self { perf_map } = self;
        let buf = perf_map.open(index, page_count)?;
        #[cfg(feature = "async_tokio")]
        let buf = AsyncFd::new(buf)?;
        #[cfg(all(not(feature = "async_tokio"), feature = "async_std"))]
        let buf = Async::new(buf)?;
        Ok(AsyncPerfEventArrayBuffer { buf })
    }

    /// Pins the map to a BPF filesystem.
    ///
    /// When a map is pinned it will remain loaded until the corresponding file
    /// is deleted. All parent directories in the given `path` must already exist.
    pub fn pin<P: AsRef<Path>>(&self, path: P) -> Result<(), PinError> {
        self.perf_map.pin(path)
    }
}

impl<T: Borrow<MapData>> AsyncPerfEventArray<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        Ok(Self {
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
pub struct AsyncPerfEventArrayBuffer<T: BorrowMut<MapData>> {
    #[cfg(not(any(feature = "async_tokio", feature = "async_std")))]
    buf: PerfEventArrayBuffer<T>,

    #[cfg(feature = "async_tokio")]
    buf: AsyncFd<PerfEventArrayBuffer<T>>,

    #[cfg(all(not(feature = "async_tokio"), feature = "async_std"))]
    buf: Async<PerfEventArrayBuffer<T>>,
}

impl<T: BorrowMut<MapData>> AsyncPerfEventArrayBuffer<T> {
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
        let Self { buf } = self;
        loop {
            #[cfg(feature = "async_tokio")]
            let mut guard = buf.readable_mut().await?;
            #[cfg(feature = "async_tokio")]
            let buf = guard.get_inner_mut();

            #[cfg(all(not(feature = "async_tokio"), feature = "async_std"))]
            let buf = {
                if !buf.get_ref().readable() {
                    buf.readable().await?;
                }
                unsafe { buf.get_mut() }
            };

            let events = buf.read_events(buffers)?;
            const EMPTY: Events = Events { read: 0, lost: 0 };
            if events != EMPTY {
                break Ok(events);
            }

            #[cfg(feature = "async_tokio")]
            guard.clear_ready();
        }
    }
}
