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
use libc::{c_void, munmap, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE};
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
/// * Data notifications are delivered more precisely instead of being sampled for every N events;
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
/// * Construct [`RingBuf`] using [`RingBuf::try_from`] on [`MapData`] something which implements
///   [`core::borrow::Borrow<MapData>`]`.
/// * Call [`RingBuf::next`] to poll events from the [`RingBuf`].
///
/// To receive async notifications of data availability, you clients may
/// construct an AsyncFd from the [`RingBuf`]'s file descriptor and poll it for
/// readiness.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.8.
///
#[doc(alias = "BPF_MAP_TYPE_RINGBUF")]
pub struct RingBuf<T> {
    _map: T,
    map_fd: i32,
    page_size: usize,
    consumer: ConsumerMeta,
    producer: ProducerMeta,
    data: DataPages,
}

impl<T: core::borrow::Borrow<MapData>> RingBuf<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data: &MapData = map.borrow();

        let page_size = crate::util::page_size();
        let map_fd = data.fd_or_err().map_err(MapError::from)?;
        let byte_size = data.obj.max_entries();

        let mmap = |len, prot, offset| {
            let res = unsafe { mmap(ptr::null_mut(), len, prot, MAP_SHARED, map_fd, offset) };
            match res {
                MAP_FAILED => Err(MapError::SyscallError {
                    call: "mmap",
                    io_error: io::Error::last_os_error(),
                }),
                // This should never happen, but to be paranoid, and so we never
                // need to talk about a null pointer, we check it anyway.
                _ => std::ptr::NonNull::new(res).ok_or(MapError::SyscallError {
                    call: "mmap",
                    io_error: io::Error::new(io::ErrorKind::Other, "mmap returned null pointer"),
                }),
            }
        };

        // The consumer metadata page is mapped once, read-write.
        // The producer pages have one page of metadata and then the data
        // pages are mapped twice, read-only. From kernel/bpf/ringbuf.c[0]:
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
        // [0]: https://github.com/torvalds/linux/blob/3f01e9fed8454dcd89727016c3e5b2fbb8f8e50c/kernel/bpf/ringbuf.c#L108-L124
        let consumer_page = mmap(page_size, PROT_READ | PROT_WRITE, 0)?;
        let producer_pages_len = page_size + 2 * (byte_size as usize);
        let producer_pages = mmap(producer_pages_len, PROT_READ, page_size as i64)?;
        let data_pages = unsafe {
            // Safe because we know page_size is properly aligned and producer_pages is NonNull.
            NonNull::new_unchecked((producer_pages.as_ptr() as usize + page_size) as *mut c_void)
        };
        Ok(RingBuf {
            _map: map,
            map_fd,
            consumer: ConsumerMeta::new(consumer_page),
            producer: ProducerMeta::new(producer_pages),
            data: DataPages::new(data_pages, byte_size - 1),
            page_size,
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
    pub fn next(&mut self) -> Option<RingBufItem<'_, T>> {
        let Self {
            _map: _,
            map_fd: _,
            page_size: _,
            consumer,
            producer,
            data,
        } = self;

        loop {
            let consumer_pos = consumer.load();
            if producer.caught_up_to(consumer_pos) {
                return None;
            }
            let header = data.load_header(consumer_pos);
            match header.state() {
                HeaderState::Ready => return Some(RingBufItem(self)),
                HeaderState::Busy => return None,
                HeaderState::Discard => consumer.consume(header),
            }
        }
    }

    fn consume(&mut self) {
        let Self { consumer, data, .. } = self;
        consumer.consume(data.load_header(consumer.load()))
    }
}

impl<T> Drop for RingBuf<T> {
    fn drop(&mut self) {
        let &mut Self {
            consumer: ConsumerMeta {
                ptr: consumer_pos_ptr,
            },
            producer:
                ProducerMeta {
                    ptr: producer_pos_ptr,
                    ..
                },
            page_size,
            data: DataPages { offset_mask, .. },
            ..
        } = self;

        let consumer_len = page_size;
        unsafe { munmap(consumer_pos_ptr.as_ptr() as *mut _, consumer_len) };
        let byte_size = (offset_mask + 1) as usize;
        let producer_len = page_size + 2 * byte_size;
        unsafe { munmap(producer_pos_ptr.as_ptr() as *mut _, producer_len) };
    }
}

/// Access to the RawFd can be used to construct an AsyncFd for use with epoll.
impl<T> AsRawFd for RingBuf<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.map_fd
    }
}

/// The current outstanding item read from the ringbuf.
pub struct RingBufItem<'a, T>(&'a mut RingBuf<T>);

impl<'a, T> Deref for RingBufItem<'a, T> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let Self(RingBuf { data, consumer, .. }) = self;
        data.load_slice(consumer.load())
    }
}

impl<'a, T> Drop for RingBufItem<'a, T> {
    fn drop(&mut self) {
        let Self(rb) = self;
        rb.consume();
    }
}

struct ConsumerMeta {
    ptr: NonNull<AtomicU32>,
}

impl ConsumerMeta {
    fn new(ptr: NonNull<c_void>) -> Self {
        Self { ptr: ptr.cast() }
    }

    fn load(&self) -> u32 {
        let Self { ptr } = self;

        // Consumer pos is written by *us*. This means that we'll load the same value regardless
        // of the `Ordering`.
        unsafe { ptr.as_ref() }.load(Ordering::Relaxed)
    }

    fn consume(&mut self, header: Header) {
        let Self { ptr } = self;
        unsafe { ptr.as_ref() }.fetch_add(roundup_len(header.len()), Ordering::Release);
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    struct HeaderFlags: u32 {
        const BUSY = BPF_RINGBUF_BUSY_BIT;
        const DISCARD = BPF_RINGBUF_DISCARD_BIT;
    }
}

#[derive(Clone, Copy)]
struct Header(HeaderFlags);

impl Header {
    fn len(self) -> u32 {
        let Self(flags) = self;
        flags.difference(HeaderFlags::all()).bits()
    }

    fn state(self) -> HeaderState {
        let Self(flags) = self;
        if flags.contains(HeaderFlags::BUSY) {
            HeaderState::Busy
        } else if flags.contains(HeaderFlags::DISCARD) {
            HeaderState::Discard
        } else {
            HeaderState::Ready
        }
    }
}

/// Abstracts the possible states of a ringbuf entry header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderState {
    /// Data is currently being written.
    Busy,
    /// The entry has been discarded.
    Discard,
    /// The entry is ready to be read.
    Ready,
}

/// Represents the pointer to the producer metadata page.
pub(super) struct ProducerMeta {
    ptr: std::ptr::NonNull<AtomicU32>,

    // In common scenarios, the producer position advances more than one message
    // by the time the consumer is notified. As a performance optimization, cache
    // the position when reading it to minimize the contention on the producer metadata
    // cache line.
    cache: u32,
}

impl ProducerMeta {
    fn new(ptr: std::ptr::NonNull<c_void>) -> Self {
        Self {
            cache: 0,
            ptr: ptr.cast(),
        }
    }

    fn caught_up_to(&mut self, pos: u32) -> bool {
        if self.cached_caught_up_to(pos) {
            self.refresh_cache();
            self.cached_caught_up_to(pos)
        } else {
            false
        }
    }

    fn cached_caught_up_to(&self, pos: u32) -> bool {
        let Self { cache, ptr: _ } = self;
        debug_assert!(pos <= *cache, "pos: {}, cache: {}", pos, cache);
        pos == *cache
    }

    fn refresh_cache(&mut self) {
        let Self { cache, ptr } = self;
        let prev = *cache;
        let load = || unsafe { ptr.as_ref() }.load(Ordering::Acquire);
        let should_retry = |v| v == prev;
        *cache = retry_with_barrier(load, should_retry)
    }
}

struct DataPages {
    ptr: NonNull<u8>,

    // Used to mask the value of the consumer offset to an offset in the
    // ringbuf data pages.
    offset_mask: u32,

    // Used to mask the ringbuf message header.
    //
    // Note: it's unclear whether this masking is necessary, but libbpf takes
    // care to always apply the offset mask to the length it reads out of
    // message headers, so we will too. The kernel contract is unclear about
    // what can possibly appear in the bit which are not in use as a flag today
    // and are not covered by the mask for the length of an entry. To avoid
    // needing to plumb mask around, we just mask out the bits we don't care
    // about when we read the header using this mask.
    header_mask: HeaderFlags,
}

impl DataPages {
    fn new(ptr: NonNull<c_void>, mask: u32) -> Self {
        Self {
            ptr: ptr.cast(),
            offset_mask: mask,
            header_mask: HeaderFlags::all() | HeaderFlags::from_bits_retain(mask),
        }
    }

    fn load_header(&self, offset: u32) -> Header {
        self.read_header_from_ptr(self.header_ptr(offset))
    }

    fn load_slice(&self, offset: u32) -> &[u8] {
        let header_ptr = self.header_ptr(offset);
        let data_ptr = (header_ptr as usize + BPF_RINGBUF_HDR_SZ as usize) as *const _;
        let len = self.read_header_from_ptr(header_ptr).len() as usize;
        unsafe { core::slice::from_raw_parts(data_ptr, len) }
    }

    fn header_ptr(&self, offset: u32) -> *const AtomicU32 {
        let Self {
            ptr,
            offset_mask,
            header_mask: _,
        } = self;
        let offset = (offset & *offset_mask) as usize;
        unsafe { ptr.as_ptr().add(offset) as *const AtomicU32 }
    }

    fn read_header_from_ptr(&self, header_ptr: *const AtomicU32) -> Header {
        let Self { header_mask, .. } = self;
        let load =
            || HeaderFlags::from_bits_retain(unsafe { (*header_ptr).load(Ordering::Acquire) });
        let should_retry = |v: HeaderFlags| v.contains(HeaderFlags::BUSY);
        Header(*header_mask & retry_with_barrier(load, should_retry))
    }
}

fn retry_with_barrier<T: Copy>(f: impl Fn() -> T, should_retry: impl Fn(T) -> bool) -> T {
    let val = f();
    if !should_retry(val) {
        return val;
    }
    fence(Ordering::SeqCst);
    f()
}

/// Round up a `len` to the nearest 8 byte alignment, adding BPF_RINGBUF_HDR_SZ and
/// clearing out the upper two bits of `len`.
fn roundup_len(mut len: u32) -> u32 {
    const LEN_MASK: u32 = !(BPF_RINGBUF_DISCARD_BIT | BPF_RINGBUF_BUSY_BIT);
    // clear out the upper two bits (busy and discard)
    len &= LEN_MASK;
    // add the size of the header prefix
    len += BPF_RINGBUF_HDR_SZ;
    // round to up to next multiple of 8
    (len + 7) & !7
}

#[cfg(test)]
mod tests {
    use super::{roundup_len, BPF_RINGBUF_BUSY_BIT, BPF_RINGBUF_DISCARD_BIT, BPF_RINGBUF_HDR_SZ};

    #[test]
    fn test_roundup_len() {
        // should always round up to nearest 8 byte alignment + BPF_RINGBUF_HDR_SZ
        assert_eq!(roundup_len(0), BPF_RINGBUF_HDR_SZ);
        assert_eq!(roundup_len(1), BPF_RINGBUF_HDR_SZ + 8);
        assert_eq!(roundup_len(8), BPF_RINGBUF_HDR_SZ + 8);
        assert_eq!(roundup_len(9), BPF_RINGBUF_HDR_SZ + 16);
        // should discard the upper two bits of len
        assert_eq!(
            roundup_len(0 | (BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT)),
            BPF_RINGBUF_HDR_SZ
        );
    }
}
