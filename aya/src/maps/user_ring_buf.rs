//! A user space ring buffer that eBPF programs drain.

use std::{
    borrow::Borrow,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
    os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd},
    slice,
    sync::atomic::{AtomicU32, AtomicUsize, Ordering},
};

use aya_obj::generated::{BPF_RINGBUF_BUSY_BIT, BPF_RINGBUF_DISCARD_BIT, BPF_RINGBUF_HDR_SZ};
use libc::{MAP_SHARED, PROT_READ, PROT_WRITE};

use crate::{
    maps::{MapData, MapError},
    util::{MMap, page_size},
};

/// A ring buffer that user space publishes into and an eBPF program drains.
///
/// `UserRingBuf` is the user-space-to-kernel counterpart of [`RingBuf`]: user space reserves a
/// sample with [`reserve`], writes into it, and submits it, then the eBPF program consumes the
/// samples by calling `bpf_user_ringbuf_drain` (exposed as `UserRingBuf::drain` in `aya-ebpf`).
///
/// To publish events you need to:
/// * Construct [`UserRingBuf`] using [`UserRingBuf::try_from`].
/// * Call [`reserve`] to obtain an entry, write the payload into it, then call [`submit`].
///
/// To receive async notifications that space has become available, you may construct an
/// [`tokio::io::unix::AsyncFd`] from the [`UserRingBuf`]'s file descriptor and poll it for
/// writability.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 6.1.
///
/// [`RingBuf`]: super::RingBuf
/// [`reserve`]: UserRingBuf::reserve
/// [`submit`]: UserRingBufEntry::submit
/// [`tokio::io::unix::AsyncFd`]: https://docs.rs/tokio/latest/tokio/io/unix/struct.AsyncFd.html
#[doc(alias = "BPF_MAP_TYPE_USER_RINGBUF")]
pub struct UserRingBuf<T> {
    map: T,
    consumer: ConsumerPos,
    producer: ProducerData,
}

impl<T: Borrow<MapData>> UserRingBuf<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data: &MapData = map.borrow();
        let page_size = page_size();
        let map_fd = data.fd().as_fd();
        let byte_size = data.obj.max_entries();
        let consumer = ConsumerPos::new(map_fd, page_size)?;
        let producer = ProducerData::new(map_fd, page_size, byte_size)?;
        Ok(Self {
            map,
            consumer,
            producer,
        })
    }

    pub(crate) fn map_data(&self) -> &MapData {
        self.map.borrow()
    }

    /// Reserves a sample of `size` bytes in the ring buffer.
    ///
    /// Returns `None` if the ring buffer has no room for the sample, either because it is full or
    /// because `size` exceeds its capacity. Write the payload into the returned entry, then call
    /// [`UserRingBufEntry::submit`] to publish it; dropping the entry without submitting discards
    /// it.
    ///
    /// Only one [`UserRingBufEntry`] may be outstanding at a time.
    pub fn reserve(&mut self, size: usize) -> Option<UserRingBufEntry<'_>> {
        let Self {
            map: _,
            consumer,
            producer,
        } = self;
        producer.reserve(size, consumer)
    }
}

impl<T: Borrow<MapData>> AsFd for UserRingBuf<T> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        let Self {
            map,
            consumer: _,
            producer: _,
        } = self;
        map.borrow().fd().as_fd()
    }
}

impl<T: Borrow<MapData>> AsRawFd for UserRingBuf<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.as_fd().as_raw_fd()
    }
}

/// A reserved sample in a [`UserRingBuf`], obtained from [`UserRingBuf::reserve`].
///
/// Write the payload through the `[u8]` view, then call [`submit`] to publish it. Dropping the entry
/// without submitting discards it.
///
/// [`submit`]: UserRingBufEntry::submit
pub struct UserRingBufEntry<'a> {
    payload: &'a mut [u8],
    header: *const AtomicU32,
}

impl Deref for UserRingBufEntry<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let Self { payload, header: _ } = self;
        payload
    }
}

impl DerefMut for UserRingBufEntry<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let Self { payload, header: _ } = self;
        payload
    }
}

impl UserRingBufEntry<'_> {
    /// Submits the sample, making it available to the eBPF program draining the ring buffer.
    pub fn submit(self) {
        ManuallyDrop::new(self).commit(false);
    }

    /// Discards the sample; the eBPF program draining the ring buffer skips it.
    pub fn discard(self) {
        ManuallyDrop::new(self).commit(true);
    }

    fn commit(&self, discard: bool) {
        let Self { payload, header } = self;
        let mut len = payload.len() as u32;
        if discard {
            len |= BPF_RINGBUF_DISCARD_BIT;
        }
        // Clear the busy bit (and optionally set the discard bit). The release store pairs with the
        // kernel's acquire load of the header in __bpf_user_ringbuf_peek, publishing the payload [0].
        //
        // [0]: https://github.com/torvalds/linux/blob/ffc253263a1375a65fa6c9f62a893e9767fbebfa/kernel/bpf/ringbuf.c#L675
        unsafe { &**header }.store(len, Ordering::Release);
    }
}

impl Drop for UserRingBufEntry<'_> {
    fn drop(&mut self) {
        // A reservation dropped without submitting is abandoned; discard it so the ring buffer is
        // not blocked by a perpetually busy sample.
        self.commit(true);
    }
}

// A read-only view of the consumer position, which the kernel advances as it drains samples.
struct ConsumerPos {
    mmap: MMap,
}

impl ConsumerPos {
    fn new(fd: BorrowedFd<'_>, page_size: usize) -> Result<Self, MapError> {
        // The consumer position page is owned by the kernel; user space only reads it.
        let mmap = MMap::new(fd, page_size, PROT_READ, MAP_SHARED, 0)?;
        Ok(Self { mmap })
    }

    fn get(&self) -> usize {
        // Pair the kernel's release store in __bpf_user_ringbuf_sample_release with an acquire load
        // so that freed space becomes visible [0].
        //
        // [0]: https://github.com/torvalds/linux/blob/ffc253263a1375a65fa6c9f62a893e9767fbebfa/kernel/bpf/ringbuf.c#L723
        unsafe { self.mmap.ptr().cast::<AtomicUsize>().as_ref() }.load(Ordering::Acquire)
    }
}

// A writable view of the producer position and the data region, both owned by user space.
struct ProducerData {
    mmap: MMap,

    // Offset in the mmap where the data region starts.
    data_offset: usize,

    // A bitmask which truncates positions to the domain of valid offsets in the ring buffer.
    mask: usize,
}

impl ProducerData {
    fn new(fd: BorrowedFd<'_>, page_size: usize, byte_size: u32) -> Result<Self, MapError> {
        // The producer pages hold one metadata page followed by the data pages, mapped read-write
        // because user space is the producer. The data pages are mapped twice consecutively so that
        // a sample which wraps the end of the ring buffer remains contiguous [0].
        //
        // [0]: https://github.com/torvalds/linux/blob/ffc253263a1375a65fa6c9f62a893e9767fbebfa/kernel/bpf/ringbuf.c#L99-L114
        let len = page_size + 2 * usize::try_from(byte_size).unwrap();
        let mmap = MMap::new(
            fd,
            len,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            page_size.try_into().unwrap(),
        )?;

        // byte_size is a power of two, so subtracting one yields a mask for offsets less than it.
        debug_assert!(byte_size.is_power_of_two());
        let mask = usize::try_from(byte_size - 1).unwrap();
        Ok(Self {
            mmap,
            data_offset: page_size,
            mask,
        })
    }

    fn reserve<'a>(
        &'a mut self,
        size: usize,
        consumer: &ConsumerPos,
    ) -> Option<UserRingBufEntry<'a>> {
        let Self {
            mmap,
            data_offset,
            mask,
        } = self;

        // The top two header bits encode the busy and discard flags, so a size that sets them would
        // be misread by the kernel; reject it like libbpf does.
        if size as u32 & (BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT) != 0 {
            return None;
        }

        let hdr_size = usize::try_from(BPF_RINGBUF_HDR_SZ).unwrap();
        let max_size = *mask + 1;
        let total = size
            .checked_add(hdr_size)
            .and_then(|total| total.checked_next_multiple_of(8))?;
        if total > max_size {
            return None;
        }

        // Read the producer position from the shared mapping on every reservation rather than
        // caching it, so that a second handle over the same map (or a reopened pin) advancing the
        // position cannot leave this one reserving a stale slot.
        let producer_pos = unsafe { mmap.ptr().cast::<AtomicUsize>().as_ref() };
        let pos = producer_pos.load(Ordering::Acquire);
        let available = max_size - pos.wrapping_sub(consumer.get());
        if available < total {
            return None;
        }

        let data = unsafe { mmap.ptr().cast::<u8>().add(*data_offset) };

        // Write the header with the busy bit set so the kernel skips the sample until it is
        // submitted. The kernel only reads the first word of the header for user ring buffers, so
        // the second word is left untouched. The data region is mapped twice, so the header and the
        // payload are each contiguous across the wrap.
        let header_offset = pos & *mask;
        let header = unsafe { data.add(header_offset) }.cast::<AtomicU32>();
        unsafe { header.as_ref() }.store(size as u32 | BPF_RINGBUF_BUSY_BIT, Ordering::Relaxed);

        // Publish the advanced producer position. The release store pairs with the kernel's acquire
        // load in __bpf_user_ringbuf_peek and makes the busy header visible [0].
        //
        // [0]: https://github.com/torvalds/linux/blob/ffc253263a1375a65fa6c9f62a893e9767fbebfa/kernel/bpf/ringbuf.c#L664
        producer_pos.store(pos + total, Ordering::Release);

        let payload = unsafe {
            slice::from_raw_parts_mut(data.add((header_offset + hdr_size) & *mask).as_ptr(), size)
        };
        Some(UserRingBufEntry {
            payload,
            header: header.as_ptr().cast_const(),
        })
    }
}
