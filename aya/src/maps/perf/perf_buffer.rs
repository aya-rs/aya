use std::{
    fmt::{self, Debug, Formatter},
    io,
    marker::PhantomData,
    ops::Deref,
    os::fd::{AsFd, BorrowedFd},
    ptr::{self, NonNull},
    slice,
    sync::atomic::{self, Ordering},
};

use aya_obj::generated::{
    PERF_FLAG_FD_CLOEXEC, perf_event_header, perf_event_mmap_page,
    perf_event_type::{PERF_RECORD_LOST, PERF_RECORD_SAMPLE},
};
use bytes::BytesMut;
use libc::{MAP_SHARED, PROT_READ, PROT_WRITE};
use thiserror::Error;

use crate::{
    programs::perf_event::{
        PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent, WakeupPolicy,
    },
    sys::{PerfEventIoctlRequest, SyscallError, perf_event_ioctl, perf_event_open},
    util::MMap,
};

/// Perf buffer error.
#[derive(Error, Debug)]
pub enum PerfBufferError {
    /// the page count value passed to [`PerfEventArray::open`](crate::maps::PerfEventArray::open) is invalid.
    #[error("invalid page count {page_count}, the value must be a power of two")]
    InvalidPageCount {
        /// the page count
        page_count: usize,
    },

    /// `perf_event_open` failed.
    #[error("perf_event_open failed: {io_error}")]
    OpenError {
        /// the source of this error
        #[source]
        io_error: io::Error,
    },

    /// `mmap`-ping the buffer failed.
    #[error("mmap failed: {io_error}")]
    MMapError {
        /// the source of this error
        #[source]
        io_error: io::Error,
    },

    /// The `PERF_EVENT_IOC_ENABLE` ioctl failed
    #[error("PERF_EVENT_IOC_ENABLE failed: {io_error}")]
    PerfEventEnableError {
        #[source]
        /// the source of this error
        io_error: io::Error,
    },

    /// `read_events()` was called with no output buffers.
    #[error("read_events() was called with no output buffers")]
    NoBuffers,

    /// `read_events()` was called with a buffer that is not large enough to
    /// contain the next event in the perf buffer.
    #[deprecated(
        since = "0.10.8",
        note = "read_events() now calls BytesMut::reserve() internally, so this error is never returned"
    )]
    #[error("the buffer needs to be of at least {size} bytes")]
    MoreSpaceNeeded {
        /// expected size
        size: usize,
    },

    /// An IO error occurred.
    #[error(transparent)]
    IOError(#[from] io::Error),
}

/// Return type of `read_events()`.
#[derive(Debug, PartialEq, Eq)]
pub struct Events {
    /// The number of events read.
    pub read: usize,
    /// The number of events lost.
    pub lost: usize,
}

/// An event read from a perf event array buffer.
///
/// See [`PerfEventArrayBuffer::next_event`].
///
/// [`PerfEventArrayBuffer::next_event`]: crate::maps::perf::PerfEventArrayBuffer::next_event
#[derive(Debug)]
pub enum PerfEvent<'a> {
    /// A `PERF_RECORD_SAMPLE` event. The wrapped [`PerfSample`] derefs to the
    /// raw sample bytes emitted by `bpf_perf_event_output()`, including any
    /// kernel-side alignment padding that follows the payload.
    Sample(PerfSample<'a>),
    /// A `PERF_RECORD_LOST` event from the kernel, signalling that samples
    /// were dropped because the ring buffer was full.
    Lost {
        /// Number of dropped samples.
        count: u64,
    },
}

/// A reference to a sample read from a perf event array buffer.
///
/// Yielded by [`PerfEventArrayBuffer::next_event`] inside [`PerfEvent::Sample`].
/// Derefs to `&[u8]`. When dropped, advances the perf ring buffer's `data_tail`
/// so the kernel may reuse the underlying memory.
///
/// # Leaks
///
/// `mem::forget`-ing a [`PerfSample`] suppresses the `data_tail` advance, so
/// the kernel observes the buffer as full and stops writing new events.
///
/// [`PerfEventArrayBuffer::next_event`]: crate::maps::perf::PerfEventArrayBuffer::next_event
pub struct PerfSample<'a> {
    data: &'a [u8],
    data_tail: NonNull<u64>,
    advance: u64,
    _marker: PhantomData<&'a mut ()>,
}

// SAFETY: `data_tail` points into the mmap'd `perf_event_mmap_page`,
// which outlives `'a`. The borrow that produced this `PerfSample`
// retains `&mut PerfBuffer` for the lifetime, so no other Rust code
// can read or write `data_tail` while the sample is live; the kernel
// reads `data_tail` via its own ordered atomic access.
unsafe impl Send for PerfSample<'_> {}
unsafe impl Sync for PerfSample<'_> {}

impl Deref for PerfSample<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let Self { data, .. } = self;
        data
    }
}

impl Drop for PerfSample<'_> {
    fn drop(&mut self) {
        let Self {
            data_tail, advance, ..
        } = self;
        advance_data_tail(*data_tail, *advance);
    }
}

impl Debug for PerfSample<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self { data, advance, .. } = self;
        f.debug_struct("PerfSample")
            .field("len", &data.len())
            .field("advance", advance)
            .finish()
    }
}

#[cfg_attr(test, derive(Debug))]
pub(crate) struct PerfBuffer {
    mmap: MMap,
    size: usize,
    page_size: usize,
    fd: crate::MockableFd,
    scratch: Vec<u8>,
}

impl PerfBuffer {
    pub(crate) fn open(
        cpu: u32,
        page_size: usize,
        page_count: usize,
    ) -> Result<Self, PerfBufferError> {
        if !page_count.is_power_of_two() {
            return Err(PerfBufferError::InvalidPageCount { page_count });
        }

        let fd = perf_event_open(
            PerfEventConfig::Software(SoftwareEvent::BpfOutput),
            PerfEventScope::AllProcessesOneCpu { cpu },
            SamplePolicy::Period(1),
            WakeupPolicy::Events(1),
            false,
            PERF_FLAG_FD_CLOEXEC,
        )
        .map_err(|io_error| PerfBufferError::OpenError { io_error })?;
        let size = page_size * page_count;
        let mmap = MMap::new(
            fd.as_fd(),
            size + page_size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            0,
        )
        .map_err(|SyscallError { call: _, io_error }| PerfBufferError::MMapError { io_error })?;

        let perf_buf = Self {
            mmap,
            size,
            page_size,
            fd,
            scratch: Vec::new(),
        };

        perf_event_ioctl(perf_buf.fd.as_fd(), PerfEventIoctlRequest::Enable)
            .map_err(|io_error| PerfBufferError::PerfEventEnableError { io_error })?;

        Ok(perf_buf)
    }

    const fn buf(&self) -> NonNull<perf_event_mmap_page> {
        self.mmap.ptr().cast()
    }

    pub(crate) fn readable(&self) -> bool {
        let header = self.buf().as_ptr();
        let head = unsafe { (*header).data_head } as usize;
        let tail = unsafe { (*header).data_tail } as usize;
        head != tail
    }

    pub(crate) fn next_event(&mut self) -> Option<PerfEvent<'_>> {
        let header = self.buf().as_ptr();
        // SAFETY: the mmap region spans `page_size + size` bytes; the data area
        // starts at offset `page_size`.
        let base = unsafe { header.byte_add(self.page_size) }.cast::<u8>();
        let mmap_size = self.size;

        // SAFETY: `header` is non-null and points to the mmap'd
        // `perf_event_mmap_page` for the lifetime of `self`.
        let data_tail_ptr: NonNull<u64> =
            unsafe { NonNull::new_unchecked(&raw mut (*header).data_tail) };

        loop {
            // SAFETY: `header` is valid for the lifetime of `self`. `u64`
            // is the kernel ABI even on 32-bit targets where the read may
            // not be a single instruction; the Acquire fence below pairs
            // with the kernel's smp_store_release on `data_head`.
            let head = unsafe { (*header).data_head } as usize;
            let tail = unsafe { (*header).data_tail } as usize;
            if head == tail {
                return None;
            }
            // Pair with the kernel's smp_store_release on `data_head`: subsequent
            // record reads must not be reordered before observing the head.
            atomic::fence(Ordering::Acquire);

            let event_start = tail % mmap_size;
            // SAFETY: the kernel guarantees event headers are 8-byte aligned
            // and never span the ring buffer wrap boundary, so reading a
            // `perf_event_header` at `base + event_start` is in-bounds.
            let event: perf_event_header =
                unsafe { ptr::read_unaligned(base.add(event_start).cast()) };
            let event_size = event.size as usize;
            let event_type = event.type_;

            match event_type {
                x if x == PERF_RECORD_SAMPLE as u32 => {
                    let mut size_buf = [0u8; size_of::<u32>()];
                    fill_from_mmap(
                        event_start + size_of::<perf_event_header>(),
                        base,
                        mmap_size,
                        &mut size_buf,
                    );
                    let sample_size = u32::from_ne_bytes(size_buf) as usize;
                    let sample_start =
                        (event_start + size_of::<perf_event_header>() + size_of::<u32>())
                            % mmap_size;

                    let data: &[u8] = if sample_start + sample_size <= mmap_size {
                        // SAFETY: the if-condition guarantees the slice is
                        // entirely within the mmap data area. The kernel will
                        // not overwrite these bytes until `PerfSample` is
                        // dropped and advances `data_tail`.
                        unsafe { slice::from_raw_parts(base.add(sample_start), sample_size) }
                    } else {
                        // Sample wraps the ring buffer end; copy into scratch.
                        self.scratch.clear();
                        self.scratch.reserve(sample_size);
                        let first = mmap_size - sample_start;
                        // SAFETY: `[sample_start, mmap_size)` and
                        // `[0, sample_size - first)` are disjoint ranges within
                        // the mmap data area; together they cover the wrapping
                        // sample exactly.
                        unsafe {
                            self.scratch.extend_from_slice(slice::from_raw_parts(
                                base.add(sample_start),
                                first,
                            ));
                            self.scratch.extend_from_slice(slice::from_raw_parts(
                                base,
                                sample_size - first,
                            ));
                        }
                        &self.scratch
                    };

                    return Some(PerfEvent::Sample(PerfSample {
                        data,
                        data_tail: data_tail_ptr,
                        advance: event_size as u64,
                        _marker: PhantomData,
                    }));
                }
                x if x == PERF_RECORD_LOST as u32 => {
                    let mut count_buf = [0u8; size_of::<u64>()];
                    fill_from_mmap(
                        event_start + size_of::<perf_event_header>() + size_of::<u64>(),
                        base,
                        mmap_size,
                        &mut count_buf,
                    );
                    // No borrowed data; advance `data_tail` immediately.
                    advance_data_tail(data_tail_ptr, event_size as u64);
                    return Some(PerfEvent::Lost {
                        count: u64::from_ne_bytes(count_buf),
                    });
                }
                _ => {
                    // Unknown event type; advance past it and try the next one.
                    advance_data_tail(data_tail_ptr, event_size as u64);
                }
            }
        }
    }

    pub(crate) fn read_events(
        &mut self,
        buffers: &mut [BytesMut],
    ) -> Result<Events, PerfBufferError> {
        if buffers.is_empty() {
            return Err(PerfBufferError::NoBuffers);
        }
        let header = self.buf().as_ptr();
        let base = unsafe { header.byte_add(self.page_size) };

        let mut events = Events { read: 0, lost: 0 };
        let mut buf_n = 0;

        let read_event = |event_start, event_type, base, buf: &mut BytesMut| {
            let sample_size = match event_type {
                x if x == PERF_RECORD_SAMPLE as u32 || x == PERF_RECORD_LOST as u32 => {
                    let mut size = [0u8; size_of::<u32>()];
                    fill_from_mmap(
                        event_start + size_of::<perf_event_header>(),
                        base,
                        self.size,
                        &mut size,
                    );
                    u32::from_ne_bytes(size)
                }
                _ => return Ok(None),
            } as usize;

            let sample_start =
                (event_start + size_of::<perf_event_header>() + size_of::<u32>()) % self.size;

            match event_type {
                x if x == PERF_RECORD_SAMPLE as u32 => {
                    buf.clear();
                    buf.reserve(sample_size);
                    unsafe { buf.set_len(sample_size) }

                    fill_from_mmap(sample_start, base, self.size, buf);

                    Ok(Some((1, 0)))
                }
                x if x == PERF_RECORD_LOST as u32 => {
                    let mut count = [0u8; size_of::<u64>()];
                    fill_from_mmap(
                        event_start + size_of::<perf_event_header>() + size_of::<u64>(),
                        base,
                        self.size,
                        &mut count,
                    );
                    Ok(Some((0, u64::from_ne_bytes(count) as usize)))
                }
                _ => Ok(None),
            }
        };

        let head = unsafe { (*header).data_head } as usize;
        let mut tail = unsafe { (*header).data_tail } as usize;
        // Pair with the kernel's smp_store_release on `data_head`: subsequent
        // record reads must not be reordered before observing the head.
        atomic::fence(Ordering::Acquire);
        let result = loop {
            if head == tail {
                break Ok(());
            }
            if buf_n == buffers.len() {
                break Ok(());
            }

            let buf = &mut buffers[buf_n];

            let event_start = tail % self.size;
            let event: perf_event_header =
                unsafe { ptr::read_unaligned(base.byte_add(event_start).cast()) };
            let event_size = event.size as usize;

            match read_event(event_start, event.type_, base.cast(), buf) {
                Ok(Some((read, lost))) => {
                    if read > 0 {
                        buf_n += 1;
                        events.read += read;
                    }
                    events.lost += lost;
                }
                Ok(None) => { /* skip unknown event type */ }
                Err(e) => {
                    // we got an error and we didn't process any events, propagate the error
                    // and give the caller a chance to increase buffers
                    break Err(e);
                }
            }
            tail += event_size;
        };

        atomic::fence(Ordering::SeqCst);
        unsafe { (*header).data_tail = tail as u64 }

        result.map(|()| events)
    }
}

impl AsFd for PerfBuffer {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl Drop for PerfBuffer {
    fn drop(&mut self) {
        let _unused: io::Result<()> =
            perf_event_ioctl(self.fd.as_fd(), PerfEventIoctlRequest::Disable);
    }
}

/// Add `advance` to the `u64` at `data_tail` with kernel-paired `SeqCst`
/// ordering.
fn advance_data_tail(data_tail: NonNull<u64>, advance: u64) {
    // Pair with the kernel's smp_load_acquire on `data_tail`.
    atomic::fence(Ordering::SeqCst);
    // SAFETY: `data_tail` points into the mmap'd `perf_event_mmap_page`,
    // and userspace is the only writer of this field.
    unsafe {
        let p = data_tail.as_ptr();
        *p = (*p).wrapping_add(advance);
    }
}

/// Copy `out_buf.len()` bytes starting at `start_off` from the perf ring buffer
/// at `base`, handling wrap-around at `mmap_size`.
///
/// # Safety
///
/// `base` must point to a valid mmap region of at least `mmap_size` bytes.
fn fill_from_mmap(start_off: usize, base: *const u8, mmap_size: usize, out_buf: &mut [u8]) {
    let len = out_buf.len();
    let end = (start_off + len) % mmap_size;
    let start = start_off % mmap_size;

    if start < end {
        // SAFETY: `start < end <= mmap_size` and `len = end - start`, so the
        // read is entirely within the mmap region.
        unsafe {
            out_buf.copy_from_slice(slice::from_raw_parts(base.add(start), len));
        }
    } else {
        let size = mmap_size - start;
        // SAFETY: `[start, mmap_size)` and `[0, len - size)` are disjoint
        // ranges within the mmap region; together they cover the wrapped read.
        unsafe {
            out_buf[..size].copy_from_slice(slice::from_raw_parts(base.add(start), size));
            out_buf[size..].copy_from_slice(slice::from_raw_parts(base, len - size));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use assert_matches::assert_matches;

    use super::*;
    use crate::sys::{Syscall, TEST_MMAP_RET, override_syscall};

    #[repr(C)]
    #[derive(Debug)]
    struct Sample {
        header: perf_event_header,
        size: u32,
    }

    const PAGE_SIZE: usize = 4096;
    #[repr(C)]
    union MMappedBuf {
        mmap_page: perf_event_mmap_page,
        data: [u8; PAGE_SIZE * 2],
    }

    fn fake_mmap(buf: &mut MMappedBuf) {
        let buf: *mut _ = buf;
        override_syscall(|call| match call {
            Syscall::PerfEventOpen { .. } => Ok(crate::MockableFd::mock_signed_fd().into()),
            Syscall::PerfEventIoctl { .. } => Ok(0),
            call @ Syscall::Ebpf { .. } => panic!("unexpected syscall: {call:?}"),
        });
        TEST_MMAP_RET.with(|ret| *ret.borrow_mut() = buf.cast());
    }

    #[test]
    fn test_invalid_page_count() {
        assert_matches!(
            PerfBuffer::open(1, PAGE_SIZE, 0),
            Err(PerfBufferError::InvalidPageCount { .. })
        );
        assert_matches!(
            PerfBuffer::open(1, PAGE_SIZE, 3),
            Err(PerfBufferError::InvalidPageCount { .. })
        );
        assert_matches!(
            PerfBuffer::open(1, PAGE_SIZE, 5),
            Err(PerfBufferError::InvalidPageCount { .. })
        );
    }

    #[test]
    fn test_no_out_bufs() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        assert_matches!(buf.read_events(&mut []), Err(PerfBufferError::NoBuffers))
    }

    #[test]
    fn test_no_events() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let out_buf = BytesMut::with_capacity(4);
        assert_eq!(
            buf.read_events(&mut [out_buf]).unwrap(),
            Events { read: 0, lost: 0 }
        );
    }

    fn write<T: Debug>(mmapped_buf: &mut MMappedBuf, offset: usize, value: T) -> usize {
        let dst: *mut _ = mmapped_buf;
        let head = offset + size_of::<T>();
        unsafe {
            ptr::write_unaligned(dst.byte_add(PAGE_SIZE + offset).cast(), value);
            mmapped_buf.mmap_page.data_head = head as u64;
        }
        head
    }

    #[test]
    fn test_read_first_lost() {
        #[repr(C)]
        #[derive(Debug)]
        struct LostSamples {
            header: perf_event_header,
            id: u64,
            count: u64,
        }

        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        write(
            &mut mmapped_buf,
            0,
            LostSamples {
                header: perf_event_header {
                    type_: PERF_RECORD_LOST as u32,
                    misc: 0,
                    size: size_of::<LostSamples>() as u16,
                },
                id: 1,
                count: 0xCAFEBABE,
            },
        );

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let out_buf = BytesMut::with_capacity(0);
        let events = buf.read_events(&mut [out_buf]).unwrap();
        assert_eq!(events.lost, 0xCAFEBABE);
    }

    #[repr(C)]
    #[derive(Debug)]
    struct TestPerfRecord<T: Debug> {
        s_hdr: Sample,
        value: T,
    }

    fn write_sample<T: Debug>(mmapped_buf: &mut MMappedBuf, offset: usize, value: T) -> usize {
        write(
            mmapped_buf,
            offset,
            TestPerfRecord {
                s_hdr: Sample {
                    header: perf_event_header {
                        type_: PERF_RECORD_SAMPLE as u32,
                        misc: 0,
                        size: size_of::<TestPerfRecord<T>>() as u16,
                    },
                    size: size_of::<T>() as u32,
                },
                value,
            },
        )
    }

    fn u32_from_buf(buf: &[u8]) -> u32 {
        u32::from_ne_bytes(buf[..4].try_into().unwrap())
    }

    fn u64_from_buf(buf: &[u8]) -> u64 {
        u64::from_ne_bytes(buf[..8].try_into().unwrap())
    }

    #[test]
    fn test_read_first_sample() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        write_sample(&mut mmapped_buf, 0, 0xCAFEBABEu32);

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let mut out_bufs = [BytesMut::with_capacity(4)];

        let events = buf.read_events(&mut out_bufs).unwrap();
        assert_eq!(events, Events { lost: 0, read: 1 });
        assert_eq!(u32_from_buf(&out_bufs[0]), 0xCAFEBABE);
    }

    #[test]
    fn test_read_many_with_many_reads() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        let next = write_sample(&mut mmapped_buf, 0, 0xCAFEBABEu32);
        write_sample(&mut mmapped_buf, next, 0xBADCAFEu32);

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let mut out_bufs = [BytesMut::with_capacity(4)];

        let events = buf.read_events(&mut out_bufs).unwrap();
        assert_eq!(events, Events { lost: 0, read: 1 });
        assert_eq!(u32_from_buf(&out_bufs[0]), 0xCAFEBABE);

        let events = buf.read_events(&mut out_bufs).unwrap();
        assert_eq!(events, Events { lost: 0, read: 1 });
        assert_eq!(u32_from_buf(&out_bufs[0]), 0xBADCAFE);
    }

    #[test]
    fn test_read_many_with_one_read() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        let next = write_sample(&mut mmapped_buf, 0, 0xCAFEBABEu32);
        write_sample(&mut mmapped_buf, next, 0xBADCAFEu32);

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let mut out_bufs = std::iter::repeat_n(BytesMut::with_capacity(4), 3).collect::<Vec<_>>();

        let events = buf.read_events(&mut out_bufs).unwrap();
        assert_eq!(events, Events { lost: 0, read: 2 });
        assert_eq!(u32_from_buf(&out_bufs[0]), 0xCAFEBABE);
        assert_eq!(u32_from_buf(&out_bufs[1]), 0xBADCAFE);
    }

    #[test]
    fn test_read_last_sample() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        let offset = PAGE_SIZE - size_of::<TestPerfRecord<u32>>();
        write_sample(&mut mmapped_buf, offset, 0xCAFEBABEu32);
        mmapped_buf.mmap_page.data_tail = offset as u64;

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let mut out_bufs = [BytesMut::with_capacity(4)];

        let events = buf.read_events(&mut out_bufs).unwrap();
        assert_eq!(events, Events { lost: 0, read: 1 });
        assert_eq!(u32_from_buf(&out_bufs[0]), 0xCAFEBABE);
    }

    #[test]
    fn test_read_wrapping_sample_size() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        let offset = PAGE_SIZE - size_of::<perf_event_header>() - 2;
        write(
            &mut mmapped_buf,
            offset,
            perf_event_header {
                type_: PERF_RECORD_SAMPLE as u32,
                misc: 0,
                size: size_of::<TestPerfRecord<u64>>() as u16,
            },
        );
        mmapped_buf.mmap_page.data_tail = offset as u64;

        let (left, right) = if cfg!(target_endian = "little") {
            (0x0004u16, 0x0000u16)
        } else {
            (0x0000u16, 0x0004u16)
        };
        write(&mut mmapped_buf, PAGE_SIZE - 2, left);
        write(&mut mmapped_buf, 0, right);
        write(&mut mmapped_buf, 2, 0xBAADCAFEu32);

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let mut out_bufs = [BytesMut::with_capacity(8)];

        let events = buf.read_events(&mut out_bufs).unwrap();
        assert_eq!(events, Events { lost: 0, read: 1 });
        assert_eq!(u32_from_buf(&out_bufs[0]), 0xBAADCAFE);
    }

    #[test]
    fn test_next_event_empty() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        assert_matches!(buf.next_event(), None);
    }

    #[test]
    fn test_next_event_lost() {
        #[repr(C)]
        #[derive(Debug)]
        struct LostSamples {
            header: perf_event_header,
            id: u64,
            count: u64,
        }

        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        write(
            &mut mmapped_buf,
            0,
            LostSamples {
                header: perf_event_header {
                    type_: PERF_RECORD_LOST as u32,
                    misc: 0,
                    size: size_of::<LostSamples>() as u16,
                },
                id: 1,
                count: 0xCAFEBABE,
            },
        );

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        assert_matches!(
            buf.next_event(),
            Some(PerfEvent::Lost { count: 0xCAFEBABE })
        );
        assert_matches!(buf.next_event(), None);
    }

    #[test]
    fn test_next_event_sample() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        write_sample(&mut mmapped_buf, 0, 0xCAFEBABEu32);

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        assert_matches!(
            buf.next_event(),
            Some(PerfEvent::Sample(bytes)) if u32_from_buf(&bytes) == 0xCAFEBABE
        );
        assert_matches!(buf.next_event(), None);
    }

    #[test]
    fn test_next_event_consecutive_samples() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        let next = write_sample(&mut mmapped_buf, 0, 0xCAFEBABEu32);
        write_sample(&mut mmapped_buf, next, 0xBADCAFEu32);

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let mut payloads = Vec::new();
        while let Some(event) = buf.next_event() {
            match event {
                PerfEvent::Sample(bytes) => payloads.push(u32_from_buf(&bytes)),
                PerfEvent::Lost { count } => panic!("unexpected lost: {count}"),
            }
        }
        assert_eq!(payloads, [0xCAFEBABE, 0xBADCAFE]);
    }

    #[test]
    fn test_next_event_wrapping_value() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        let (left, right) = if cfg!(target_endian = "little") {
            (0xCAFEBABEu32, 0xBAADCAFEu32)
        } else {
            (0xBAADCAFEu32, 0xCAFEBABEu32)
        };

        let offset = PAGE_SIZE - size_of::<TestPerfRecord<u32>>();
        write(
            &mut mmapped_buf,
            offset,
            TestPerfRecord {
                s_hdr: Sample {
                    header: perf_event_header {
                        type_: PERF_RECORD_SAMPLE as u32,
                        misc: 0,
                        size: size_of::<TestPerfRecord<u64>>() as u16,
                    },
                    size: size_of::<u64>() as u32,
                },
                value: left,
            },
        );
        write(&mut mmapped_buf, 0, right);
        mmapped_buf.mmap_page.data_tail = offset as u64;

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        assert_matches!(
            buf.next_event(),
            Some(PerfEvent::Sample(bytes))
                if u64_from_buf(&bytes) == 0xBAADCAFECAFEBABE
        );
    }

    #[test]
    fn test_read_wrapping_value() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        let (left, right) = if cfg!(target_endian = "little") {
            (0xCAFEBABEu32, 0xBAADCAFEu32)
        } else {
            (0xBAADCAFEu32, 0xCAFEBABEu32)
        };

        let offset = PAGE_SIZE - size_of::<TestPerfRecord<u32>>();
        write(
            &mut mmapped_buf,
            offset,
            TestPerfRecord {
                s_hdr: Sample {
                    header: perf_event_header {
                        type_: PERF_RECORD_SAMPLE as u32,
                        misc: 0,
                        size: size_of::<TestPerfRecord<u64>>() as u16,
                    },
                    size: size_of::<u64>() as u32,
                },
                value: left,
            },
        );
        write(&mut mmapped_buf, 0, right);
        mmapped_buf.mmap_page.data_tail = offset as u64;

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let mut out_bufs = [BytesMut::with_capacity(8)];

        let events = buf.read_events(&mut out_bufs).unwrap();
        assert_eq!(events, Events { lost: 0, read: 1 });
        assert_eq!(u64_from_buf(&out_bufs[0]), 0xBAADCAFECAFEBABE);
    }
}
