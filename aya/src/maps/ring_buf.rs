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
    io,
    ops::Deref,
    os::fd::{AsRawFd, RawFd},
    ptr,
    ptr::NonNull,
    sync::atomic::{fence, AtomicU32, Ordering},
};

/// A map that can be used to receive events from eBPF programs.
///
/// This is similar to [`crate::maps::PerfEventArray`], but different in a few ways:
/// * It's shared across all CPUs, which allows a strong ordering between events.
/// * Data notifications are delivered precisely instead of being sampled for every N events;
///   the eBPF program can also control notification delivery if sampling is desired for performance
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
/// To receive async notifications of data availability, you clients may construct an
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
        let consumer = ConsumerPos::new(map_fd, page_size)?;
        let producer = ProducerData::new(map_fd, page_size, byte_size)?;
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
    // This is not an implementation of `Iterator` because we need to be able to refer
    // to the lifetime of the iterator in the returned `RingBufItem`. If the Iterator::Item
    // leveraged GATs, one could imagine an implementation of `Iterator` that would work.
    // GATs are stabilized in Rust 1.65, but there's not yet a trait that the community
    // seems to have standardized around.
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

// ConsumerPos corresponds to the consumer metadata page of the RingBuf.
struct ConsumerPos(MMap);

impl ConsumerPos {
    fn new(fd: RawFd, page_size: usize) -> Result<Self, MapError> {
        Ok(Self(MMap::new(
            fd,
            page_size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            0,
        )?))
    }

    fn load(&self) -> u32 {
        self.get_ref().load(Ordering::Relaxed)
    }

    fn consume(&mut self, len: usize) -> u32 {
        // TODO: Use primitive method when https://github.com/rust-lang/rust/issues/88581 is stabilized.
        fn next_multiple_of(n: u32, multiple: u32) -> u32 {
            match n % multiple {
                0 => n,
                rem => n + (multiple - rem),
            }
        }
        let to_add = next_multiple_of(len as u32 + BPF_RINGBUF_HDR_SZ, 8);
        to_add + self.get_ref().fetch_add(to_add, Ordering::Release)
    }

    fn get_ref(&self) -> &AtomicU32 {
        let Self(MMap { ptr, .. }) = self;
        unsafe { ptr.cast::<AtomicU32>().as_ref() }
    }
}

struct ProducerData {
    memmap: MMap,
    page_size: usize,
    mask: u32,
    pos_cache: u32,
}

impl ProducerData {
    fn new(fd: RawFd, page_size: usize, byte_size: u32) -> Result<Self, MapError> {
        // The producer pages have one page of metadata and then the data pages, all mapped
        // read-only. Note that the length of the mapping include the data pages twice
        // as the kernel will map them two time consecutively to avoid special handling
        // of entries cross over the end of the ring buffer.
        //
        // From kernel/bpf/ringbuf.c [0]:
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
        let len = page_size + 2 * byte_size as usize;
        let memmap = MMap::new(fd, len, PROT_READ, MAP_SHARED, page_size as off_t)?;
        Ok(Self {
            memmap,
            page_size,
            pos_cache: 0,
            mask: byte_size - 1,
        })
    }

    fn next<'a>(&'a mut self, consumer: &'a mut ConsumerPos) -> Option<RingBufItem<'a>> {
        let Self {
            ref memmap,
            page_size,
            pos_cache,
            mask,
        } = self;
        let pos = unsafe { memmap.ptr.cast().as_ref() };
        let data: &[u8] = &memmap.as_ref()[*page_size..];
        let mut consumer_pos = consumer.load();
        while data_available(pos, pos_cache, consumer_pos) {
            match read_item(data, *mask, consumer_pos) {
                Item::Busy => return None,
                Item::Data(data) => return Some(RingBufItem { data, consumer }),
                Item::Discard { len } => consumer_pos = consumer.consume(len),
            }
        }
        return None;

        bitflags! {
            #[derive(Clone, Copy)]
            struct Header: u32 {
                const BUSY = BPF_RINGBUF_BUSY_BIT;
                const DISCARD = BPF_RINGBUF_DISCARD_BIT;
            }
        }

        impl Header {
            fn len(self, mask: u32) -> usize {
                const LEN_MASK: u32 = !Header::all().bits();
                (self.bits() & LEN_MASK & mask) as usize
            }
        }

        enum Item<'a> {
            Data(&'a [u8]),
            Discard { len: usize },
            Busy,
        }

        fn retry_with_barrier<T: Copy>(f: impl Fn() -> T, should_retry: impl Fn(T) -> bool) -> T {
            let val = f();
            if !should_retry(val) {
                return val;
            }
            fence(Ordering::SeqCst);
            f()
        }

        fn data_available(producer: &AtomicU32, cache: &mut u32, consumer: u32) -> bool {
            debug_assert!(
                consumer <= *cache,
                "consumer={} > producer={}",
                consumer,
                *cache
            );
            if consumer < *cache {
                true
            } else {
                let prev = *cache;
                *cache = retry_with_barrier(|| producer.load(Ordering::Acquire), |v| v == prev);
                consumer < *cache
            }
        }

        fn read_item(data: &[u8], mask: u32, offset: u32) -> Item {
            let offset = offset & mask;
            let header_ptr = data[offset as usize..].as_ptr() as *const AtomicU32;
            let header_ref = unsafe { &*header_ptr };
            let header = retry_with_barrier(
                || Header::from_bits_retain(header_ref.load(Ordering::Acquire)),
                |header| header.contains(Header::BUSY),
            );
            if header.contains(Header::BUSY) {
                Item::Busy
            } else {
                let len = header.len(mask);
                if header.contains(Header::DISCARD) {
                    Item::Discard { len }
                } else {
                    let data_offset = offset as usize + BPF_RINGBUF_HDR_SZ as usize;
                    Item::Data(&data[data_offset..data_offset + len])
                }
            }
        }
    }
}

// MMap corresponds to a memory-mapped region.
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
        match unsafe { mmap(ptr::null_mut(), len, prot, flags, fd, offset) } {
            MAP_FAILED => Err(MapError::SyscallError {
                call: "mmap",
                io_error: io::Error::last_os_error(),
            }),
            // This should never happen, but to be paranoid, and so we never
            // need to talk about a null pointer, we check it anyway.
            res => Ok(Self {
                ptr: std::ptr::NonNull::new(res).ok_or(MapError::SyscallError {
                    call: "mmap",
                    io_error: io::Error::new(io::ErrorKind::Other, "mmap returned null pointer"),
                })?,
                len,
            }),
        }
    }
}

impl AsRef<[u8]> for MMap {
    fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().cast(), self.len) }
    }
}

impl Drop for MMap {
    fn drop(&mut self) {
        unsafe {
            munmap(self.ptr.as_ptr(), self.len);
        }
    }
}
