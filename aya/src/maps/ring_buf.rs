//! A [ring buffer map][ringbuf] that may be used to receive events from eBPF programs.
//! As of Linux 5.8, this is the preferred way to transfer per-event data from eBPF
//! programs to userspace.
//!
//! [ringbuf]: https://www.kernel.org/doc/html/latest/bpf/ringbuf.html

use std::{
    borrow::Borrow,
    fmt::{self, Debug, Formatter},
    ops::{ControlFlow, Deref},
    os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd},
    sync::atomic::{AtomicU32, AtomicUsize, Ordering},
};

use aya_obj::generated::{BPF_RINGBUF_BUSY_BIT, BPF_RINGBUF_DISCARD_BIT, BPF_RINGBUF_HDR_SZ};
use libc::{MAP_SHARED, PROT_READ, PROT_WRITE};

use crate::{
    maps::{MapData, MapError},
    util::{MMap, page_size},
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
/// * On the eBPF side, it supports the reserve-commit pattern where the event can be directly
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
///         println!("received: {:?}", item);
///     }
///     guard.clear_ready();
/// }
/// # Ok::<(), aya::EbpfError>(())
/// ```
///
/// # Polling
///
/// In the example above the implementations of poll(), poll.readable(), guard.inner_mut(), and
/// guard.clear_ready() are not given. RingBuf implements [`AsRawFd`], so you can implement polling
/// using any crate that can poll file descriptors, like epoll, mio etc. The above example API is
/// motivated by that of [`tokio::io::unix::AsyncFd`].
///
/// [`tokio::io::unix::AsyncFd`]: https://docs.rs/tokio/latest/tokio/io/unix/struct.AsyncFd.html
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
        let byte_size = data.obj.max_entries();
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
    #[expect(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<RingBufItem<'_>> {
        let Self {
            consumer, producer, ..
        } = self;
        producer.next(consumer)
    }

    /// Drain available entries from the ringbuf in a single batch.
    ///
    /// The callback is invoked once per entry with a borrowed slice into the mmap.
    /// Do not retain the slice outside the callback; the backing storage can be
    /// overwritten after the batch completes and the consumer position is committed.
    pub fn drain<F>(&mut self, f: F) -> DrainStats
    where
        F: FnMut(&[u8]),
    {
        self.drain_with_limit(usize::MAX, usize::MAX, f)
    }

    /// Drain up to `max_items` entries or `max_bytes` total bytes, whichever comes first.
    ///
    /// This performs a single consumer position update after the batch.
    ///
    /// If at least one item is available, the first item is always processed even if doing so
    /// would exceed `max_items` or `max_bytes`. In that case, the returned [`DrainStats`] may
    /// report totals that are greater than the specified limits. Discarded items count toward
    /// `max_bytes`.
    pub fn drain_with_limit<F>(&mut self, max_items: usize, max_bytes: usize, f: F) -> DrainStats
    where
        F: FnMut(&[u8]),
    {
        let Self {
            consumer, producer, ..
        } = self;
        producer.drain(consumer, max_items, max_bytes, f)
    }

    /// Drain available entries until `f` returns [`ControlFlow::Break`].
    ///
    /// Discarded entries are still skipped and counted in the returned [`DrainStats`].
    ///
    /// If `f` breaks, the current entry is considered consumed and the updated consumer
    /// position is committed before returning.
    pub fn drain_while<F, B>(&mut self, f: F) -> ControlFlow<B, DrainStats>
    where
        F: FnMut(&[u8]) -> ControlFlow<B>,
    {
        let Self {
            consumer, producer, ..
        } = self;
        producer.drain_while(consumer, f)
    }

    /// Drain available entries with minimal accounting overhead.
    ///
    /// Returns the number of data entries passed to `f`. Discarded entries are skipped and
    /// committed but not counted.
    pub fn drain_fast<F>(&mut self, f: F) -> usize
    where
        F: FnMut(&[u8]),
    {
        let Self {
            consumer, producer, ..
        } = self;
        producer.drain_fast(consumer, f)
    }
}

impl<T: Borrow<MapData>> AsFd for RingBuf<T> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        let Self {
            map,
            consumer: _,
            producer: _,
        } = self;
        map.borrow().fd().as_fd()
    }
}

impl<T: Borrow<MapData>> AsRawFd for RingBuf<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.as_fd().as_raw_fd()
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

/// Stats returned by [`RingBuf::drain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainStats {
    /// Number of entries read.
    pub read: usize,
    /// Number of discarded entries skipped.
    pub discarded: usize,
    /// Total bytes processed (payload size, not including headers).
    pub bytes: usize,
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
        unsafe { self.mmap.ptr().cast::<AtomicUsize>().as_ref() }
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

    fn advance(&mut self, len: usize) {
        let Self { pos, .. } = self;
        *pos += item_advance(len);
    }

    fn commit(&self) {
        let Self { pos, metadata } = self;
        metadata.as_ref().store(*pos, Ordering::SeqCst);
    }

    fn consume(&mut self, len: usize) {
        self.advance(len);

        // Write operation needs to be properly ordered with respect to the producer committing new
        // data to the ringbuf. The producer uses xchg (SeqCst) to commit new data [1]. The producer
        // reads the consumer offset after clearing the busy bit on a new entry [2]. By using SeqCst
        // here we ensure that either a subsequent read by the consumer to consume messages will see
        // an available message, or the producer in the kernel will see the updated consumer offset
        // that is caught up.
        //
        // [1]: https://github.com/torvalds/linux/blob/2772d7df/kernel/bpf/ringbuf.c#L487-L488
        // [2]: https://github.com/torvalds/linux/blob/2772d7df/kernel/bpf/ringbuf.c#L494
        self.commit();
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

        // The producer position may be non-zero if the map is being loaded from a pin, or the map
        // has been used previously; load the initial value of the producer position from the mmap.
        let pos_cache = load_producer_pos(&mmap);

        // byte_size is required to be a power of two multiple of page_size (which implicitly is a
        // power of 2), so subtracting one will create a bitmask for values less than byte_size.
        debug_assert!(byte_size.is_power_of_two());
        let mask = byte_size - 1;
        Ok(Self {
            mmap,
            data_offset: page_size,
            pos_cache,
            mask,
        })
    }

    fn next<'a>(&'a mut self, consumer: &'a mut ConsumerPos) -> Option<RingBufItem<'a>> {
        let &mut Self {
            ref mmap,
            ref mut data_offset,
            ref mut pos_cache,
            ref mut mask,
        } = self;
        let mmap_data = mmap.as_ref();
        let data_pages = mmap_data.get(*data_offset..).unwrap_or_else(|| {
            panic!(
                "offset {} out of bounds, data len {}",
                data_offset,
                mmap_data.len()
            )
        });
        while data_available(mmap, pos_cache, consumer.pos) {
            match read_item(data_pages, *mask, consumer.pos) {
                Item::Busy => return None,
                Item::Discard { len } => consumer.consume(len),
                Item::Data(data) => return Some(RingBufItem { data, consumer }),
            }
        }
        return None;
    }

    fn drain<F>(
        &mut self,
        consumer: &mut ConsumerPos,
        max_items: usize,
        max_bytes: usize,
        f: F,
    ) -> DrainStats
    where
        F: FnMut(&[u8]),
    {
        self.drain_impl::<_, true>(consumer, max_items, max_bytes, f)
    }

    fn drain_impl<F, const TRACK_BYTES: bool>(
        &mut self,
        consumer: &mut ConsumerPos,
        max_items: usize,
        max_bytes: usize,
        mut f: F,
    ) -> DrainStats
    where
        F: FnMut(&[u8]),
    {
        let &mut Self {
            ref mmap,
            ref mut data_offset,
            ref mut pos_cache,
            ref mut mask,
        } = self;
        let mmap_data = mmap.as_ref();
        let data_pages = mmap_data.get(*data_offset..).unwrap_or_else(|| {
            panic!(
                "offset {} out of bounds, data len {}",
                data_offset,
                mmap_data.len()
            )
        });

        let start_pos = consumer.pos;
        let mut stats = DrainStats {
            read: 0,
            discarded: 0,
            bytes: 0,
        };
        let mut processed = 0usize;

        while data_available(mmap, pos_cache, consumer.pos) {
            if processed >= max_items {
                break;
            }

            match read_item(data_pages, *mask, consumer.pos) {
                Item::Busy => break,
                Item::Discard { len } => {
                    if TRACK_BYTES && stats.bytes + len > max_bytes && processed > 0 {
                        break;
                    }
                    stats.discarded += 1;
                    if TRACK_BYTES {
                        stats.bytes += len;
                    }
                    processed += 1;
                    consumer.advance(len);
                }
                Item::Data(data) => {
                    let len = data.len();
                    if TRACK_BYTES && stats.bytes + len > max_bytes && processed > 0 {
                        break;
                    }
                    f(data);
                    stats.read += 1;
                    if TRACK_BYTES {
                        stats.bytes += len;
                    }
                    processed += 1;
                    consumer.advance(len);
                }
            }
        }

        if consumer.pos != start_pos {
            consumer.commit();
        }
        stats
    }

    fn drain_while<F, B>(
        &mut self,
        consumer: &mut ConsumerPos,
        mut f: F,
    ) -> ControlFlow<B, DrainStats>
    where
        F: FnMut(&[u8]) -> ControlFlow<B>,
    {
        let &mut Self {
            ref mmap,
            ref mut data_offset,
            ref mut pos_cache,
            ref mut mask,
        } = self;
        let mmap_data = mmap.as_ref();
        let data_pages = mmap_data.get(*data_offset..).unwrap_or_else(|| {
            panic!(
                "offset {} out of bounds, data len {}",
                data_offset,
                mmap_data.len()
            )
        });

        let start_pos = consumer.pos;
        let mut stats = DrainStats {
            read: 0,
            discarded: 0,
            bytes: 0,
        };

        while data_available(mmap, pos_cache, consumer.pos) {
            match read_item(data_pages, *mask, consumer.pos) {
                Item::Busy => break,
                Item::Discard { len } => {
                    stats.discarded += 1;
                    stats.bytes += len;
                    consumer.advance(len);
                }
                Item::Data(data) => {
                    let len = data.len();
                    stats.read += 1;
                    stats.bytes += len;
                    consumer.advance(len);
                    if let ControlFlow::Break(value) = f(data) {
                        if consumer.pos != start_pos {
                            consumer.commit();
                        }
                        return ControlFlow::Break(value);
                    }
                }
            }
        }

        if consumer.pos != start_pos {
            consumer.commit();
        }
        ControlFlow::Continue(stats)
    }

    fn drain_fast<F>(&mut self, consumer: &mut ConsumerPos, mut f: F) -> usize
    where
        F: FnMut(&[u8]),
    {
        let &mut Self {
            ref mmap,
            ref mut data_offset,
            ref mut pos_cache,
            ref mut mask,
        } = self;
        let mmap_data = mmap.as_ref();
        let data_pages = mmap_data.get(*data_offset..).unwrap_or_else(|| {
            panic!(
                "offset {} out of bounds, data len {}",
                data_offset,
                mmap_data.len()
            )
        });

        let start_pos = consumer.pos;
        let mut read = 0usize;

        while data_available(mmap, pos_cache, consumer.pos) {
            match read_item(data_pages, *mask, consumer.pos) {
                Item::Busy => break,
                Item::Discard { len } => {
                    consumer.advance(len);
                }
                Item::Data(data) => {
                    f(data);
                    read += 1;
                    consumer.advance(data.len());
                }
            }
        }

        if consumer.pos != start_pos {
            consumer.commit();
        }
        read
    }
}

enum Item<'a> {
    Busy,
    Discard { len: usize },
    Data(&'a [u8]),
}

fn data_available(producer: &MMap, producer_cache: &mut usize, consumer: usize) -> bool {
    // Refresh the producer position cache if it appears that the consumer is caught up
    // with the producer position.
    if consumer == *producer_cache {
        *producer_cache = load_producer_pos(producer);
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
    consumer != *producer_cache
}

fn read_item<'data>(data: &'data [u8], mask: u32, pos: usize) -> Item<'data> {
    let offset = pos & usize::try_from(mask).unwrap();
    let must_get_data = |offset, len| {
        data.get(offset..offset + len)
            .unwrap_or_else(|| panic!("{:?} not in {:?}", offset..offset + len, 0..data.len()))
    };
    let header_ptr: *const AtomicU32 = must_get_data(offset, size_of::<AtomicU32>())
        .as_ptr()
        .cast();
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

// Loads the producer position from the shared memory mmap.
fn load_producer_pos(producer: &MMap) -> usize {
    // This value is written using Release by the kernel [1], and should be read with
    // Acquire to ensure that the prior writes to the entry header are visible.
    //
    // [1]: https://github.com/torvalds/linux/blob/eb26cbb1/kernel/bpf/ringbuf.c#L447-L448
    unsafe { producer.ptr().cast::<AtomicUsize>().as_ref() }.load(Ordering::Acquire)
}

fn item_advance(len: usize) -> usize {
    (usize::try_from(BPF_RINGBUF_HDR_SZ).unwrap() + len).next_multiple_of(8)
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use super::*;
    use crate::sys::{clear_test_mmap_ret_queue, push_test_mmap_ret};

    struct TestRingBuf {
        _consumer_buf: Box<[u8]>,
        _producer_buf: Box<[u8]>,
        consumer: ConsumerPos,
        producer: ProducerData,
    }

    impl TestRingBuf {
        fn new(entries: &[Entry]) -> Self {
            let page_size = 64;
            let byte_size = 128;
            let mut consumer_buf = vec![0u8; page_size].into_boxed_slice();
            let mut producer_buf = vec![0u8; page_size + 2 * byte_size].into_boxed_slice();

            unsafe {
                (consumer_buf.as_mut_ptr() as *mut AtomicUsize).write(AtomicUsize::new(0));
                (producer_buf.as_mut_ptr() as *mut AtomicUsize).write(AtomicUsize::new(0));
            }

            let mut offset = 0;
            for entry in entries {
                offset = write_entry(
                    &mut producer_buf,
                    page_size,
                    offset,
                    entry.len,
                    entry.discard,
                    entry.fill,
                );
            }

            unsafe {
                let producer_pos = producer_buf.as_mut_ptr() as *mut AtomicUsize;
                (*producer_pos).store(offset, Ordering::Release);
            }

            clear_test_mmap_ret_queue();
            push_test_mmap_ret(consumer_buf.as_mut_ptr().cast());
            push_test_mmap_ret(producer_buf.as_mut_ptr().cast());

            let fd = unsafe { BorrowedFd::borrow_raw(crate::MockableFd::mock_signed_fd()) };
            let consumer_metadata = ConsumerMetadata::new(fd, 0, page_size).unwrap();
            let consumer = ConsumerPos::new(consumer_metadata);
            let producer = ProducerData::new(fd, page_size, page_size, byte_size as u32).unwrap();

            Self {
                _consumer_buf: consumer_buf,
                _producer_buf: producer_buf,
                consumer,
                producer,
            }
        }
    }

    struct Entry {
        len: usize,
        discard: bool,
        fill: u8,
    }

    fn write_entry(
        buf: &mut [u8],
        data_offset: usize,
        offset: usize,
        len: usize,
        discard: bool,
        fill: u8,
    ) -> usize {
        let header_offset = data_offset + offset;
        let mut header = len as u32;
        if discard {
            header |= BPF_RINGBUF_DISCARD_BIT;
        }
        unsafe {
            ptr::write_unaligned(buf.as_mut_ptr().add(header_offset).cast::<u32>(), header);
            let data_start = header_offset + usize::try_from(BPF_RINGBUF_HDR_SZ).unwrap();
            ptr::write_bytes(buf.as_mut_ptr().add(data_start), fill, len);
        }
        offset + item_advance(len)
    }

    #[test]
    fn drain_empty_returns_zero() {
        let mut ring = TestRingBuf::new(&[]);
        let stats = ring
            .producer
            .drain(&mut ring.consumer, usize::MAX, usize::MAX, |_| {
                panic!("no items should be produced")
            });
        assert_eq!(
            stats,
            DrainStats {
                read: 0,
                discarded: 0,
                bytes: 0
            }
        );
        let committed = ring.consumer.metadata.as_ref().load(Ordering::SeqCst);
        assert_eq!(committed, 0);
    }

    #[test]
    fn drain_respects_max_items() {
        let mut ring = TestRingBuf::new(&[
            Entry {
                len: 8,
                discard: false,
                fill: 0xAA,
            },
            Entry {
                len: 8,
                discard: false,
                fill: 0xBB,
            },
        ]);
        let mut seen = 0usize;
        let stats = ring
            .producer
            .drain(&mut ring.consumer, 1, usize::MAX, |_| seen += 1);
        assert_eq!(seen, 1);
        assert_eq!(
            stats,
            DrainStats {
                read: 1,
                discarded: 0,
                bytes: 8
            }
        );
        let committed = ring.consumer.metadata.as_ref().load(Ordering::SeqCst);
        assert_eq!(committed, item_advance(8));
    }

    #[test]
    fn drain_allows_first_item_over_max_bytes() {
        let mut ring = TestRingBuf::new(&[Entry {
            len: 8,
            discard: false,
            fill: 0xCC,
        }]);
        let stats = ring
            .producer
            .drain(&mut ring.consumer, usize::MAX, 0, |_| {});
        assert_eq!(
            stats,
            DrainStats {
                read: 1,
                discarded: 0,
                bytes: 8
            }
        );
    }

    #[test]
    fn discarded_counts_toward_byte_budget() {
        let mut ring = TestRingBuf::new(&[
            Entry {
                len: 8,
                discard: true,
                fill: 0,
            },
            Entry {
                len: 8,
                discard: false,
                fill: 0xDD,
            },
        ]);
        let stats = ring
            .producer
            .drain(&mut ring.consumer, usize::MAX, 8, |_| {});
        assert_eq!(
            stats,
            DrainStats {
                read: 0,
                discarded: 1,
                bytes: 8
            }
        );
    }

    #[test]
    fn drain_while_breaks_early() {
        let mut ring = TestRingBuf::new(&[
            Entry {
                len: 8,
                discard: false,
                fill: 0x11,
            },
            Entry {
                len: 8,
                discard: false,
                fill: 0x22,
            },
            Entry {
                len: 8,
                discard: false,
                fill: 0x33,
            },
        ]);
        let mut calls = 0usize;
        let out = ring.producer.drain_while(&mut ring.consumer, |_| {
            calls += 1;
            if calls == 2 {
                ControlFlow::Break(calls)
            } else {
                ControlFlow::Continue(())
            }
        });
        assert_eq!(calls, 2);
        assert_eq!(out, ControlFlow::Break(2));
        let committed = ring.consumer.metadata.as_ref().load(Ordering::SeqCst);
        assert_eq!(committed, item_advance(8) * 2);
    }

    #[test]
    fn drain_fast_counts_data_only() {
        let mut ring = TestRingBuf::new(&[
            Entry {
                len: 8,
                discard: false,
                fill: 0xAA,
            },
            Entry {
                len: 8,
                discard: true,
                fill: 0,
            },
            Entry {
                len: 8,
                discard: false,
                fill: 0xBB,
            },
        ]);
        let mut seen = 0usize;
        let read = ring.producer.drain_fast(&mut ring.consumer, |_| seen += 1);
        assert_eq!(read, 2);
        assert_eq!(seen, 2);
        let committed = ring.consumer.metadata.as_ref().load(Ordering::SeqCst);
        assert_eq!(committed, item_advance(8) * 3);
    }
}
