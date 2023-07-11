//! A [ring buffer map][ringbuf] that may be used to receive events from eBPF programs.
//! As of Linux 5.8, this is the preferred way to transfer per-event data from eBPF
//! programs to userspace.
//!
//! [ringbuf]: https://www.kernel.org/doc/html/latest/bpf/ringbuf.html

use crate::{
    generated::{BPF_RINGBUF_BUSY_BIT, BPF_RINGBUF_DISCARD_BIT, BPF_RINGBUF_HDR_SZ},
    maps::{MapData, MapError},
    sys::mmap,
};
use libc::{c_int, c_void, munmap, off_t, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE};
use std::{
    fmt::Debug,
    io,
    ops::Deref,
    os::fd::{AsRawFd, BorrowedFd, RawFd},
    ptr,
    ptr::NonNull,
    sync::atomic::{AtomicU32, AtomicUsize, Ordering},
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
#[doc(alias = "BPF_MAP_TYPE_RINGBUF")]
pub struct RingBuf<T> {
    _map: T,
    map_fd: i32,
    consumer: ConsumerPos,
    producer: ProducerData,
}

impl<T: core::borrow::Borrow<MapData>> RingBuf<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data: &MapData = map.borrow();
        let page_size = crate::util::page_size();
        let map_fd = data.fd_or_err().map_err(MapError::from)?;
        let byte_size = data.obj.max_entries();
        let consumer = ConsumerPos::new(map_fd, 0, page_size)?;
        let producer = ProducerData::new(map_fd, page_size, page_size, byte_size)?;
        Ok(RingBuf {
            _map: map,
            map_fd,
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
impl<T> AsRawFd for RingBuf<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.map_fd
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
        consumer.consume(data.len());
    }
}

impl Debug for RingBufItem<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { data, consumer } = self;
        // In general Relaxed here is sufficient, for debugging, it certainly is.
        let offset = consumer.as_ref().load(Ordering::Relaxed);
        f.debug_struct("RingBufItem")
            .field("offset", &offset)
            .field("len", &data.len())
            .finish()
    }
}

struct ConsumerPos(MMap);

impl ConsumerPos {
    fn new(fd: RawFd, offset: usize, page_size: usize) -> Result<Self, MapError> {
        Ok(Self(MMap::new(
            fd,
            page_size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            offset.try_into().unwrap(),
        )?))
    }

    // Write operation needs to be properly ordered with respect to the producer committing new
    // data to the ringbuf. The producer uses xchg (SeqCst) to commit new data [1]. The producer
    // reads the consumer offset after clearing the busy bit on a new entry [2]. By using SeqCst
    // here we ensure that either a subsequent read by the consumer to consume messages will see
    // an available message, or the producer in the kernel will see the updated consumer offset
    // that is caught up.
    //
    // [1]: https://github.com/torvalds/linux/blob/2772d7df/kernel/bpf/ringbuf.c#L487-L488
    // [2]: https://github.com/torvalds/linux/blob/2772d7df/kernel/bpf/ringbuf.c#L494
    const WRITE_ORDERING: Ordering = Ordering::SeqCst;

    fn consume(&mut self, len: usize) -> usize {
        self.as_ref()
            .fetch_add(Self::compute_increment(len), Self::WRITE_ORDERING)
    }

    fn set_offset(&mut self, prev_offset: usize, len: usize) -> usize {
        let offset = prev_offset + Self::compute_increment(len);
        self.as_ref().store(offset, Self::WRITE_ORDERING);
        offset
    }

    fn compute_increment(len: usize) -> usize {
        // TODO: Use primitive method when https://github.com/rust-lang/rust/issues/88581 is stabilized.
        fn next_multiple_of(n: usize, multiple: usize) -> usize {
            match n % multiple {
                0 => n,
                rem => n + (multiple - rem),
            }
        }
        next_multiple_of(len + usize::try_from(BPF_RINGBUF_HDR_SZ).unwrap(), 8)
    }
}

impl AsRef<AtomicUsize> for ConsumerPos {
    fn as_ref(&self) -> &AtomicUsize {
        let Self(MMap { ptr, .. }) = self;
        unsafe { ptr.cast::<AtomicUsize>().as_ref() }
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
    fn new(fd: RawFd, offset: usize, page_size: usize, byte_size: u32) -> Result<Self, MapError> {
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
        let data: &[u8] = &mmap.as_ref()[*data_offset..];

        // Load our consumer position. Only this program writes this position, and this object is not
        // Send, so relaxed is sufficient.
        let mut consumer_pos = consumer.as_ref().load(Ordering::Relaxed);
        while data_available(pos, pos_cache, consumer_pos) {
            match read_item(data, *mask, consumer_pos) {
                Item::Busy => return None,
                Item::Discard { len } => consumer_pos = consumer.set_offset(consumer_pos, len),
                Item::Data(data) => return Some(RingBufItem { data, consumer }),
            }
        }
        return None;

        enum Item<'a> {
            Busy,
            Discard { len: usize },
            Data(&'a [u8]),
        }

        fn data_available(producer: &AtomicUsize, cache: &mut usize, consumer: usize) -> bool {
            if consumer == *cache {
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
            consumer != *cache
        }

        fn read_item(data: &[u8], mask: u32, offset: usize) -> Item {
            let offset = offset & usize::try_from(mask).unwrap();
            let header_ptr = data
                .get(offset..offset + core::mem::size_of::<AtomicU32>())
                .expect("offset out of bounds")
                .as_ptr() as *const AtomicU32;
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
                    Item::Data(&data[data_offset..data_offset + len])
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

impl MMap {
    fn new(
        fd: RawFd,
        len: usize,
        prot: c_int,
        flags: c_int,
        offset: off_t,
    ) -> Result<Self, MapError> {
        match unsafe {
            mmap(
                ptr::null_mut(),
                len,
                prot,
                flags,
                BorrowedFd::borrow_raw(fd),
                offset,
            )
        } {
            MAP_FAILED => Err(MapError::SyscallError {
                call: "mmap",
                io_error: io::Error::last_os_error(),
            }),
            ptr => Ok(Self {
                ptr: std::ptr::NonNull::new(ptr).ok_or(
                    // This should never happen, but to be paranoid, and so we never need to talk
                    // about a null pointer, we check it anyway.
                    MapError::SyscallError {
                        call: "mmap",
                        io_error: io::Error::new(
                            io::ErrorKind::Other,
                            "mmap returned null pointer",
                        ),
                    },
                )?,
                len,
            }),
        }
    }
}

impl AsRef<[u8]> for MMap {
    fn as_ref(&self) -> &[u8] {
        let Self { ptr, len } = self;
        unsafe { std::slice::from_raw_parts(ptr.as_ptr().cast(), *len) }
    }
}

impl Drop for MMap {
    fn drop(&mut self) {
        let Self { ptr, len } = *self;
        unsafe { munmap(ptr.as_ptr(), len) };
    }
}
