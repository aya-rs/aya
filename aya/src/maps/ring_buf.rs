//! A [ring buffer map][ringbuf] that may be used to receive events from eBPF programs.
//! As of Linux 5.8, this is the preferred way to transfer per-event data from eBPF
//! programs to userspace.
//!
//! [ringbuf]: https://www.kernel.org/doc/html/latest/bpf/ringbuf.html

use std::{
    borrow::Borrow,
    ffi::{c_int, c_void},
    fmt::{self, Debug, Formatter},
    io, mem,
    ops::Deref,
    os::fd::{AsFd as _, AsRawFd, BorrowedFd, RawFd},
    ptr,
    ptr::NonNull,
    slice,
    sync::atomic::{AtomicU32, AtomicUsize, Ordering},
};

use libc::{munmap, off_t, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE};

use crate::{
    generated::{BPF_RINGBUF_BUSY_BIT, BPF_RINGBUF_DISCARD_BIT, BPF_RINGBUF_HDR_SZ},
    maps::{MapData, MapError},
    sys::{mmap, SyscallError},
    util::page_size,
};

/// A map that can be used to receive events from eBPF programs.
///
/// This is similar to [`crate::maps::PerfEventArray`], but different in a few ways:
/// * It's shared across all CPUs, which allows a strong ordering between events.
/// * Data notifications are delivered precisely instead of being sampled for every N events; the
///   eBPF program can also control notification delivery if sampling is desired for performance
///   reasons. By default, a notification will be sent if the consumer is caught up at the time of
///   committing. The eBPF program can use the `BPF_RB_NO_WAKEUP` or `BPF_RB_FORCE_WAKEUP` flags to
///   control this behavior.
/// * On the eBPF side, it supports the reverse-commit pattern where the event can be directly
///   written into the ring without copying from a temporary location.
/// * Dropped sample notifications go to the eBPF program as the return value of `reserve`/`output`,
///   and not the userspace reader. This might require extra code to handle, but allows for more
///   flexible schemes to handle dropped samples.
///
/// To receive events you need to:
/// * Construct [`RingBuf`] using [`RingBuf::try_from`].
/// * Call [`RingBuf::next`] to poll events from the [`RingBuf`].
///
/// To receive async notifications of data availability, you may construct an
/// [`tokio::io::unix::AsyncFd`] from the [`RingBuf`]'s file descriptor and poll it for readiness.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.8.
///
/// # Examples
///
/// ```no_run
/// # struct PollFd<T>(T);
/// # fn poll_fd<T>(t: T) -> PollFd<T> { PollFd(t) }
/// # impl<T> PollFd<T> {
/// #     fn readable(&mut self) -> Guard<'_, T> { Guard(self) }
/// # }
/// # struct Guard<'a, T>(&'a mut PollFd<T>);
/// # impl<T> Guard<'_, T> {
/// #     fn inner_mut(&mut self) -> &mut T {
/// #         let Guard(PollFd(t)) = self;
/// #         t
/// #     }
/// #     fn clear_ready(&mut self) {}
/// # }
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::maps::RingBuf;
/// use std::convert::TryFrom;
///
/// let ring_buf = RingBuf::try_from(bpf.map_mut("ARRAY").unwrap()).unwrap();
/// let mut poll = poll_fd(ring_buf);
/// loop {
///     let mut guard = poll.readable();
///     let ring_buf = guard.inner_mut();
///     while let Some(item) = ring_buf.next() {
///         println!("Received: {:?}", item);
///     }
///     guard.clear_ready();
/// }
/// # Ok::<(), aya::EbpfError>(())
/// ```
///
/// # Polling
///
/// In the example above the implementations of poll(), poll.readable(), guard.inner_mut(), and
/// guard.clear_ready() are not given. RingBuf implements the AsRawFd trait, so you can implement
/// polling using any crate that can poll file descriptors, like epoll, mio etc. The above example
/// API is motivated by that of [`tokio::io::unix::AsyncFd`].
#[doc(alias = "BPF_MAP_TYPE_RINGBUF")]
pub struct RingBuf<T> {
    map: T,
    consumer: ConsumerPos,
    producer: ProducerData,
}

impl<T: Borrow<MapData>> RingBuf<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data: &MapData = map.borrow();
        let page_size = page_size();
        let map_fd = data.fd().as_fd();
        let byte_size = data.def.max_entries();
        let consumer_metadata = ConsumerMetadata::new(map_fd, 0, page_size)?;
        let consumer = ConsumerPos::new(consumer_metadata);
        let producer = ProducerData::new(map_fd, page_size, page_size, byte_size)?;
        Ok(Self {
            map,
            consumer,
            producer,
        })
    }
}

impl<T> RingBuf<T> {
    /// Try to take a new entry from the ringbuf.
    ///
    /// Returns `Some(item)` if the ringbuf is not empty. Returns `None` if the ringbuf is empty, in
    /// which case the caller may register for availability notifications through `epoll` or other
    /// APIs. Only one RingBufItem may be outstanding at a time.
    //
    // This is not an implementation of `Iterator` because we need to be able to refer to the
    // lifetime of the iterator in the returned `RingBufItem`. If the Iterator::Item leveraged GATs,
    // one could imagine an implementation of `Iterator` that would work. GATs are stabilized in
    // Rust 1.65, but there's not yet a trait that the community seems to have standardized around.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<RingBufItem<'_>> {
        let Self {
            consumer, producer, ..
        } = self;
        producer.next(consumer)
    }
}

/// Access to the RawFd can be used to construct an AsyncFd for use with epoll.
impl<T: Borrow<MapData>> AsRawFd for RingBuf<T> {
    fn as_raw_fd(&self) -> RawFd {
        let Self {
            map,
            consumer: _,
            producer: _,
        } = self;
        map.borrow().fd().as_fd().as_raw_fd()
    }
}

/// The current outstanding item read from the ringbuf.
pub struct RingBufItem<'a> {
    data: &'a [u8],
    consumer: &'a mut ConsumerPos,
}

impl Deref for RingBufItem<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let Self { data, .. } = self;
        data
    }
}

impl Drop for RingBufItem<'_> {
    fn drop(&mut self) {
        let Self { consumer, data } = self;
        consumer.consume(data.len())
    }
}

impl Debug for RingBufItem<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self {
            data,
            consumer:
                ConsumerPos {
                    pos,
                    metadata: ConsumerMetadata { mmap: _ },
                },
        } = self;
        // In general Relaxed here is sufficient, for debugging, it certainly is.
        f.debug_struct("RingBufItem")
            .field("pos", pos)
            .field("len", &data.len())
            .finish()
    }
}

struct ConsumerMetadata {
    mmap: MMap,
}

impl ConsumerMetadata {
    fn new(fd: BorrowedFd<'_>, offset: usize, page_size: usize) -> Result<Self, MapError> {
        let mmap = MMap::new(
            fd,
            page_size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            offset.try_into().unwrap(),
        )?;
        Ok(Self { mmap })
    }
}

impl AsRef<AtomicUsize> for ConsumerMetadata {
    fn as_ref(&self) -> &AtomicUsize {
        let Self {
            mmap: MMap { ptr, .. },
        } = self;
        unsafe { ptr.cast::<AtomicUsize>().as_ref() }
    }
}

struct ConsumerPos {
    pos: usize,
    metadata: ConsumerMetadata,
}

impl ConsumerPos {
    fn new(metadata: ConsumerMetadata) -> Self {
        // Load the initial value of the consumer position. SeqCst is used to be safe given we don't
        // have any claims about memory synchronization performed by some previous writer.
        let pos = metadata.as_ref().load(Ordering::SeqCst);
        Self { pos, metadata }
    }

    fn consume(&mut self, len: usize) {
        let Self { pos, metadata } = self;

        // TODO: Use primitive method when https://github.com/rust-lang/rust/issues/88581 is stabilized.
        fn next_multiple_of(n: usize, multiple: usize) -> usize {
            match n % multiple {
                0 => n,
                rem => n + (multiple - rem),
            }
        }
        *pos += next_multiple_of(usize::try_from(BPF_RINGBUF_HDR_SZ).unwrap() + len, 8);

        // Write operation needs to be properly ordered with respect to the producer committing new
        // data to the ringbuf. The producer uses xchg (SeqCst) to commit new data [1]. The producer
        // reads the consumer offset after clearing the busy bit on a new entry [2]. By using SeqCst
        // here we ensure that either a subsequent read by the consumer to consume messages will see
        // an available message, or the producer in the kernel will see the updated consumer offset
        // that is caught up.
        //
        // [1]: https://github.com/torvalds/linux/blob/2772d7df/kernel/bpf/ringbuf.c#L487-L488
        // [2]: https://github.com/torvalds/linux/blob/2772d7df/kernel/bpf/ringbuf.c#L494
        metadata.as_ref().store(*pos, Ordering::SeqCst);
    }
}

struct ProducerData {
    mmap: MMap,

    // Offset in the mmap where the data starts.
    data_offset: usize,

    // A cache of the value of the producer position. It is used to avoid re-reading the producer
    // position when we know there is more data to consume.
    pos_cache: usize,

    // A bitmask which truncates u32 values to the domain of valid offsets in the ringbuf.
    mask: u32,
}

impl ProducerData {
    fn new(
        fd: BorrowedFd<'_>,
        offset: usize,
        page_size: usize,
        byte_size: u32,
    ) -> Result<Self, MapError> {
        // The producer pages have one page of metadata and then the data pages, all mapped
        // read-only. Note that the length of the mapping includes the data pages twice as the
        // kernel will map them two time consecutively to avoid special handling of entries that
        // cross over the end of the ring buffer.
        //
        // The kernel diagram below shows the layout of the ring buffer. It references "meta pages",
        // but we only map exactly one producer meta page read-only. The consumer meta page is mapped
        // read-write elsewhere, and is taken into consideration via the offset parameter.
        //
        // From kernel/bpf/ringbuf.c[0]:
        //
        // Each data page is mapped twice to allow "virtual"
        // continuous read of samples wrapping around the end of ring
        // buffer area:
        // ------------------------------------------------------
        // | meta pages |  real data pages  |  same data pages  |
        // ------------------------------------------------------
        // |            | 1 2 3 4 5 6 7 8 9 | 1 2 3 4 5 6 7 8 9 |
        // ------------------------------------------------------
        // |            | TA             DA | TA             DA |
        // ------------------------------------------------------
        //                               ^^^^^^^
        //                                  |
        // Here, no need to worry about special handling of wrapped-around
        // data due to double-mapped data pages. This works both in kernel and
        // when mmap()'ed in user-space, simplifying both kernel and
        // user-space implementations significantly.
        //
        // [0]: https://github.com/torvalds/linux/blob/3f01e9fe/kernel/bpf/ringbuf.c#L108-L124
        let len = page_size + 2 * usize::try_from(byte_size).unwrap();
        let mmap = MMap::new(fd, len, PROT_READ, MAP_SHARED, offset.try_into().unwrap())?;

        // byte_size is required to be a power of two multiple of page_size (which implicitly is a
        // power of 2), so subtracting one will create a bitmask for values less than byte_size.
        debug_assert!(byte_size.is_power_of_two());
        let mask = byte_size - 1;
        Ok(Self {
            mmap,
            data_offset: page_size,
            pos_cache: 0,
            mask,
        })
    }

    fn next<'a>(&'a mut self, consumer: &'a mut ConsumerPos) -> Option<RingBufItem<'a>> {
        let Self {
            ref mmap,
            data_offset,
            pos_cache,
            mask,
        } = self;
        let pos = unsafe { mmap.ptr.cast().as_ref() };
        let mmap_data = mmap.as_ref();
        let data_pages = mmap_data.get(*data_offset..).unwrap_or_else(|| {
            panic!(
                "offset {} out of bounds, data len {}",
                data_offset,
                mmap_data.len()
            )
        });
        while data_available(pos, pos_cache, consumer) {
            match read_item(data_pages, *mask, consumer) {
                Item::Busy => return None,
                Item::Discard { len } => consumer.consume(len),
                Item::Data(data) => return Some(RingBufItem { data, consumer }),
            }
        }
        return None;

        enum Item<'a> {
            Busy,
            Discard { len: usize },
            Data(&'a [u8]),
        }

        fn data_available(
            producer: &AtomicUsize,
            cache: &mut usize,
            consumer: &ConsumerPos,
        ) -> bool {
            let ConsumerPos { pos: consumer, .. } = consumer;
            if consumer == cache {
                // This value is written using Release by the kernel [1], and should be read with
                // Acquire to ensure that the prior writes to the entry header are visible.
                //
                // [1]: https://github.com/torvalds/linux/blob/eb26cbb1/kernel/bpf/ringbuf.c#L447-L448
                *cache = producer.load(Ordering::Acquire);
            }

            // Note that we don't compare the order of the values because the producer position may
            // overflow u32 and wrap around to 0. Instead we just compare equality and assume that
            // the consumer position is always logically less than the producer position.
            //
            // Note also that the kernel, at the time of writing [1], doesn't seem to handle this
            // overflow correctly at all, and it's not clear that one can produce events after the
            // producer position has wrapped around.
            //
            // [1]: https://github.com/torvalds/linux/blob/4b810bf0/kernel/bpf/ringbuf.c#L434-L440
            consumer != cache
        }

        fn read_item<'data>(data: &'data [u8], mask: u32, pos: &ConsumerPos) -> Item<'data> {
            let ConsumerPos { pos, .. } = pos;
            let offset = pos & usize::try_from(mask).unwrap();
            let must_get_data = |offset, len| {
                data.get(offset..offset + len).unwrap_or_else(|| {
                    panic!("{:?} not in {:?}", offset..offset + len, 0..data.len())
                })
            };
            let header_ptr =
                must_get_data(offset, mem::size_of::<AtomicU32>()).as_ptr() as *const AtomicU32;
            // Pair the kernel's SeqCst write (implies Release) [1] with an Acquire load. This
            // ensures data written by the producer will be visible.
            //
            // [1]: https://github.com/torvalds/linux/blob/eb26cbb1/kernel/bpf/ringbuf.c#L488
            let header = unsafe { &*header_ptr }.load(Ordering::Acquire);
            if header & BPF_RINGBUF_BUSY_BIT != 0 {
                Item::Busy
            } else {
                let len = usize::try_from(header & mask).unwrap();
                if header & BPF_RINGBUF_DISCARD_BIT != 0 {
                    Item::Discard { len }
                } else {
                    let data_offset = offset + usize::try_from(BPF_RINGBUF_HDR_SZ).unwrap();
                    let data = must_get_data(data_offset, len);
                    Item::Data(data)
                }
            }
        }
    }
}

// MMap corresponds to a memory-mapped region.
//
// The data is unmapped in Drop.
struct MMap {
    ptr: NonNull<c_void>,
    len: usize,
}

// Needed because NonNull<T> is !Send and !Sync out of caution that the data
// might be aliased unsafely.
unsafe impl Send for MMap {}
unsafe impl Sync for MMap {}

impl MMap {
    fn new(
        fd: BorrowedFd<'_>,
        len: usize,
        prot: c_int,
        flags: c_int,
        offset: off_t,
    ) -> Result<Self, MapError> {
        match unsafe { mmap(ptr::null_mut(), len, prot, flags, fd, offset) } {
            MAP_FAILED => Err(MapError::SyscallError(SyscallError {
                call: "mmap",
                io_error: io::Error::last_os_error(),
            })),
            ptr => Ok(Self {
                ptr: NonNull::new(ptr).ok_or(
                    // This should never happen, but to be paranoid, and so we never need to talk
                    // about a null pointer, we check it anyway.
                    MapError::SyscallError(SyscallError {
                        call: "mmap",
                        io_error: io::Error::new(
                            io::ErrorKind::Other,
                            "mmap returned null pointer",
                        ),
                    }),
                )?,
                len,
            }),
        }
    }
}

impl AsRef<[u8]> for MMap {
    fn as_ref(&self) -> &[u8] {
        let Self { ptr, len } = self;
        unsafe { slice::from_raw_parts(ptr.as_ptr().cast(), *len) }
    }
}

impl Drop for MMap {
    fn drop(&mut self) {
        let Self { ptr, len } = *self;
        unsafe { munmap(ptr.as_ptr(), len) };
    }
}
