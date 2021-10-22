//! A [ring buffer map][ringbuf] that may be used to receive events from eBPF programs.
//! As of Linux 5.8, this is the preferred way to transfer per-event data from eBPF
//! programs to userspace.
//!
//! [ringbuf]: https://www.kernel.org/doc/html/latest/bpf/ringbuf.html

use std::{
    io,
    ops::Deref,
    os::unix::prelude::AsRawFd,
    ptr,
    sync::atomic::{fence, AtomicU32, AtomicUsize, Ordering},
};

use libc::{munmap, sysconf, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE, _SC_PAGESIZE};

use crate::{
    generated::{BPF_RINGBUF_BUSY_BIT, BPF_RINGBUF_DISCARD_BIT, BPF_RINGBUF_HDR_SZ},
    maps::{MapData, MapError},
    sys::mmap,
};

/// A map that can be used to receive events from eBPF programs.
///
/// This is similar to [`PerfEventArray`], but different in a few ways:
/// * It's shared across all CPUs, which allows a strong ordering between events. It also makes the
///   buffer creation easier.
/// * Data notifications are delivered for every event instead of being sampled for every N event;
///   the eBPF program can also control notification delivery if sampling is desired for performance reasons.
/// * On the eBPF side, it supports the reverse-commit pattern where the event can be directly
///   written into the ring without copying from a temporary location.
/// * Dropped sample notifications goes to the eBPF program as the return value of `reserve`/`output`,
///   and not the userspace reader. This might require extra code to handle, but allows for more
///   flexible schemes to handle dropped samples.
///
/// To receive events you need to:
/// * call [`RingBuf::try_from`]
/// * poll the returned [`RingBuf`] to be notified when events are inserted in the buffer
/// * call [`RingBuf::next`] to read the events
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.8.
///
/// # Examples
///
/// The following example shows how to read samples as well as using an async runtime
/// to wait for samples to be ready:
///
/// ```no_run
/// # use aya::maps::{Map, MapData, RingBuf};
/// # use std::ops::DerefMut;
/// # #[derive(thiserror::Error, Debug)]
/// # enum Error {
/// #    #[error(transparent)]
/// #    IO(#[from] std::io::Error),
/// #    #[error(transparent)]
/// #    Map(#[from] aya::maps::MapError),
/// #    #[error(transparent)]
/// #    Bpf(#[from] aya::BpfError),
/// # }
/// # struct Poll<T: AsRef<MapData>>(RingBuf<T>);
/// # impl<T: AsRef<MapData>> Poll<T> {
/// #    fn new(inner: RingBuf<T>) -> Self { Self (inner) }
/// #    async fn readable(&mut self) {}
/// #    fn get_inner_mut(&mut self) -> &mut RingBuf<T> { &mut self.0 }
/// # }
/// # async {
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use std::convert::{TryFrom, TryInto};
///
/// let mut ring = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;
///
/// // Poll would be a helper that takes an `AsRawFd` implementation and provides functionality
/// // to wait for the file descriptor to be readable.
/// let mut poll = Poll::new(ring);
/// loop {
///     // Wait for readiness.
///     poll.readable().await;
///
///     while let Some(e) = poll.get_inner_mut().next() {
///         // Do something with the data bytes
///     }
/// }
/// # Ok::<(), Error>(())
/// # };
/// ```
///
/// [`PerfEventArray`]: crate::maps::PerfEventArray
#[doc(alias = "BPF_MAP_TYPE_RINGBUF")]
pub struct RingBuf<T: AsRef<MapData>> {
    _map: T,
    map_fd: i32,
    data_ptr: *const u8,
    consumer_pos_ptr: *const AtomicUsize,
    producer_pos_ptr: *const AtomicUsize,
    // A copy of `*producer_pos_ptr` to reduce cache line contention.
    // Might be stale, and should be refreshed once the consumer position has caught up.
    producer_pos_cache: usize,
    page_size: usize,
    mask: usize,
}

impl<T: AsRef<MapData>> RingBuf<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.as_ref();

        // Determine page_size, map_fd, and set mask to map size - 1
        let page_size = unsafe { sysconf(_SC_PAGESIZE) } as usize;
        let map_fd = data.fd_or_err().map_err(MapError::from)?;
        let mask = (data.obj.max_entries() - 1) as usize;

        // Map writable consumer page
        let consumer_page = unsafe {
            mmap(
                ptr::null_mut(),
                page_size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                map_fd,
                0,
            )
        };
        if consumer_page == MAP_FAILED {
            return Err(MapError::SyscallError {
                call: "mmap".to_string(),
                io_error: io::Error::last_os_error(),
            });
        }

        // From kernel/bpf/ringbuf.c:
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
        let producer_pages = unsafe {
            mmap(
                ptr::null_mut(),
                page_size + 2 * (mask + 1),
                PROT_READ,
                MAP_SHARED,
                map_fd,
                page_size as _,
            )
        };
        if producer_pages == MAP_FAILED {
            return Err(MapError::SyscallError {
                call: "mmap".to_string(),
                io_error: io::Error::last_os_error(),
            });
        }

        Ok(RingBuf {
            _map: map,
            map_fd,
            data_ptr: unsafe { (producer_pages as *mut u8).add(page_size) },
            consumer_pos_ptr: consumer_page as *mut _,
            producer_pos_ptr: producer_pages as *mut _,
            producer_pos_cache: 0,
            page_size,
            mask,
        })
    }

    /// Try to take a new entry from the ringbuf.
    ///
    /// Returns `Some(item)` if the ringbuf is not empty.
    /// Returns `None` if the ringbuf is empty, in which case the caller may register for
    /// availability notifications through `epoll` or other APIs.
    // This is a streaming iterator which is not viable without GATs (stabilized in 1.65).
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<RingBufItem<T>> {
        // If `cb()` is true, do a memory barrier and test again if it's really true.
        // Returns true if both tests returns true.
        fn confirm_with_mb(mut cb: impl FnMut() -> bool) -> bool {
            cb() && {
                fence(Ordering::SeqCst);
                cb()
            }
        }

        loop {
            // Consumer pos is written by *us*. This means that we'll load the same value regardless
            // of the `Ordering`.
            let consumer_pos = unsafe { (*self.consumer_pos_ptr).load(Ordering::Relaxed) };
            #[allow(clippy::blocks_in_if_conditions)] // Meaning is clearer this way
            // Have we caught up?
            if consumer_pos == self.producer_pos_cache {
                // Cache might be stale, so test again. First, test without a costly memory barrier.
                // If that says we have caught up, do a memory barrier to ensure the previous write
                // is visible and test again.
                //
                // The memory barrier is necessary before committing to sleep due to possible race
                // condition: when the kernel writes n+2, see the consumer index n, while we write
                // n+1 and see the producer index n+1. If we then sleep, we'll never be waken up
                // because the kernel think we haven't caught up.
                if confirm_with_mb(|| {
                    self.producer_pos_cache =
                        unsafe { (*self.producer_pos_ptr).load(Ordering::Acquire) };
                    consumer_pos == self.producer_pos_cache
                }) {
                    return None;
                }
            }

            let sample_head = unsafe { self.data_ptr.add(consumer_pos & self.mask) };
            let mut len_and_flags = 0; // Dummy value

            // For reasons same as above, re-test with memory barrier before committing to sleep.
            #[allow(clippy::blocks_in_if_conditions)]
            if confirm_with_mb(|| {
                len_and_flags =
                    unsafe { (*(sample_head as *mut AtomicU32)).load(Ordering::Acquire) };
                (len_and_flags & BPF_RINGBUF_BUSY_BIT) != 0
            }) {
                return None;
            } else if (len_and_flags & BPF_RINGBUF_DISCARD_BIT) != 0 {
                self.consume();
            } else {
                break;
            }
        }

        Some(RingBufItem(self))
    }

    fn consume(&mut self) {
        let consumer_pos = unsafe { (*self.consumer_pos_ptr).load(Ordering::Relaxed) };
        let sample_head = unsafe { self.data_ptr.add(consumer_pos & self.mask) };
        let len_and_flags = unsafe { (*(sample_head as *mut AtomicU32)).load(Ordering::Relaxed) };
        assert_eq!(
            (len_and_flags & (BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT)),
            0
        );

        let new_consumer_pos = consumer_pos + roundup_len(len_and_flags) as usize;
        unsafe {
            (*self.consumer_pos_ptr).store(new_consumer_pos, Ordering::Release);
        }
    }
}

impl<T: AsRef<MapData>> Drop for RingBuf<T> {
    fn drop(&mut self) {
        if !self.consumer_pos_ptr.is_null() {
            // SAFETY: `consumer_pos` is not null and consumer page is not null and
            // consumer page was mapped with size `self.page_size`
            unsafe { munmap(self.consumer_pos_ptr as *mut _, self.page_size) };
        }

        if !self.producer_pos_ptr.is_null() {
            // SAFETY: `producer_pos` is not null and producer pages were mapped with size
            // `self.page_size + 2 * (self.mask + 1)`
            unsafe {
                munmap(
                    self.producer_pos_ptr as *mut _,
                    self.page_size + 2 * (self.mask + 1),
                )
            };
        }
    }
}

impl<T: AsRef<MapData>> AsRawFd for RingBuf<T> {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.map_fd
    }
}

/// An ringbuf item. When this item is dropped, the consumer index in the ringbuf will be updated.
pub struct RingBufItem<'a, T: AsRef<MapData>>(&'a mut RingBuf<T>);

impl<'a, T: AsRef<MapData>> Deref for RingBufItem<'a, T> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let consumer_pos = unsafe { (*self.0.consumer_pos_ptr).load(Ordering::Relaxed) };
        let sample_head = unsafe { self.0.data_ptr.add(consumer_pos & self.0.mask) };
        let len_and_flags = unsafe { (*(sample_head as *mut AtomicU32)).load(Ordering::Relaxed) };
        assert_eq!(
            (len_and_flags & (BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT)),
            0
        );

        // Coerce the sample into a &[u8]
        let sample_ptr = unsafe { sample_head.add(BPF_RINGBUF_HDR_SZ as usize) };
        unsafe { std::slice::from_raw_parts(sample_ptr as *const u8, len_and_flags as usize) }
    }
}

impl<'a, T: AsRef<MapData>> Drop for RingBufItem<'a, T> {
    fn drop(&mut self) {
        self.0.consume();
    }
}

/// Round up a `len` to the nearest 8 byte alignment, adding BPF_RINGBUF_HDR_SZ and
/// clearing out the upper two bits of `len`.
pub(crate) fn roundup_len(len: u32) -> u32 {
    let mut len = len;
    // clear out the upper two bits (busy and discard)
    len &= 0x3fffffff;
    // add the size of the header prefix
    len += BPF_RINGBUF_HDR_SZ;
    // round to up to next multiple of 8
    (len + 7) & !7
}

#[cfg(test)]
mod tests {
    use super::*;

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
