use std::{
    fmt::{self, Debug, Formatter},
    io,
    marker::PhantomData,
    os::fd::{AsFd, BorrowedFd},
    ptr::{self, NonNull},
    slice,
    sync::atomic::{self, Ordering},
};

use aya_obj::generated::{
    PERF_FLAG_FD_CLOEXEC, perf_event_header, perf_event_mmap_page,
    perf_event_type::{PERF_RECORD_LOST, PERF_RECORD_SAMPLE},
};
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

    /// An IO error occurred.
    #[error(transparent)]
    IOError(#[from] io::Error),
}

/// An event read from a perf event array buffer.
///
/// See [`PerfEventArrayBuffer::next_event`].
///
/// [`PerfEventArrayBuffer::next_event`]: crate::maps::perf::PerfEventArrayBuffer::next_event
#[derive(Debug)]
pub enum PerfEvent<'a> {
    /// A `PERF_RECORD_SAMPLE` event. The sample bytes emitted by
    /// `bpf_perf_event_output()` are accessible via [`PerfSample::as_slices`],
    /// including any kernel-side alignment padding that follows the payload.
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
/// The bytes are borrowed directly from the kernel-mapped ring buffer; when
/// the sample straddles the ring boundary they are exposed as two slices via
/// [`as_slices`](Self::as_slices). When dropped, advances the perf ring
/// buffer's `data_tail` so the kernel may reuse the underlying memory.
///
/// # Leaks
///
/// `mem::forget`-ing a [`PerfSample`] suppresses the `data_tail` advance, so
/// the kernel observes the buffer as full and stops writing new events.
///
/// [`PerfEventArrayBuffer::next_event`]: crate::maps::perf::PerfEventArrayBuffer::next_event
pub struct PerfSample<'a> {
    head: &'a [u8],
    tail: &'a [u8],
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

impl PerfSample<'_> {
    /// Returns the sample bytes as up to two slices, borrowed directly from
    /// the mmap'd ring buffer. The second slice is empty for samples that fit
    /// contiguously; both are populated when a sample straddles the ring
    /// boundary.
    pub const fn as_slices(&self) -> (&[u8], &[u8]) {
        let Self { head, tail, .. } = self;
        (head, tail)
    }

    /// Total length of the sample in bytes.
    pub const fn len(&self) -> usize {
        let Self { head, tail, .. } = self;
        head.len() + tail.len()
    }

    /// Returns `true` if the sample is empty.
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
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
        let Self {
            head,
            tail,
            advance,
            ..
        } = self;
        f.debug_struct("PerfSample")
            .field("len", &(head.len() + tail.len()))
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
        // SAFETY: `header` is non-null and points to the mmap'd
        // `perf_event_mmap_page` for the lifetime of `self`.
        let (head, tail) = unsafe {
            (
                load_acquire_u64(&raw const (*header).data_head),
                load_volatile_u64(&raw const (*header).data_tail),
            )
        };
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
            // SAFETY: `header` is valid for the lifetime of `self`.
            let (head, tail) = unsafe {
                (
                    load_acquire_u64(&raw const (*header).data_head) as usize,
                    load_volatile_u64(&raw const (*header).data_tail) as usize,
                )
            };
            if head == tail {
                return None;
            }

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

                    let (head, tail) = if sample_start + sample_size <= mmap_size {
                        // SAFETY: the if-condition guarantees the slice is
                        // entirely within the mmap data area. The kernel will
                        // not overwrite these bytes until `PerfSample` is
                        // dropped and advances `data_tail`.
                        let s =
                            unsafe { slice::from_raw_parts(base.add(sample_start), sample_size) };
                        (s, &[][..])
                    } else {
                        let first = mmap_size - sample_start;
                        // SAFETY: `[sample_start, mmap_size)` and
                        // `[0, sample_size - first)` are disjoint ranges within
                        // the mmap data area; together they cover the wrapping
                        // sample exactly. The kernel will not overwrite either
                        // range until `PerfSample` is dropped and advances
                        // `data_tail`.
                        let head = unsafe { slice::from_raw_parts(base.add(sample_start), first) };
                        let tail = unsafe { slice::from_raw_parts(base, sample_size - first) };
                        (head, tail)
                    };

                    return Some(PerfEvent::Sample(PerfSample {
                        head,
                        tail,
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

/// Advance `data_tail` by `advance`. The kernel-pairing contract is documented
/// on [`store_release_u64`].
fn advance_data_tail(data_tail: NonNull<u64>, advance: u64) {
    let p = data_tail.as_ptr();
    let new = load_volatile_u64(p).wrapping_add(advance);
    store_release_u64(p, new);
}

// Helpers for kernel-shared `__u64` fields in `perf_event_mmap_page`. Each
// takes a raw pointer to the field; the caller must ensure it remains valid
// for the duration of the call. `store_release_u64` additionally requires
// userspace to be the sole writer. The userspace barrier contract mirrors
// `tools/include/linux/ring_buffer.h`.

/// Acquire-load a kernel-shared `__u64` (e.g. `data_head`). Pairs with the
/// kernel's `smp_wmb() + WRITE_ONCE()` publish [1].
///
/// [1]: https://github.com/torvalds/linux/blob/05f7e89a/kernel/events/ring_buffer.c#L113-L114
fn load_acquire_u64(ptr: *const u64) -> u64 {
    // SAFETY: caller-validated pointer.
    let value = unsafe { ptr::read_volatile(ptr) };
    atomic::fence(Ordering::Acquire);
    value
}

/// `READ_ONCE` semantics; no fence. Use where userspace is the sole writer.
fn load_volatile_u64(ptr: *const u64) -> u64 {
    // SAFETY: caller-validated pointer.
    unsafe { ptr::read_volatile(ptr) }
}

/// Release-store a kernel-shared `__u64` (e.g. `data_tail`). Pairs with the
/// kernel's `READ_ONCE()` load [1].
///
/// [1]: https://github.com/torvalds/linux/blob/05f7e89a/kernel/events/ring_buffer.c#L202
fn store_release_u64(ptr: *mut u64, value: u64) {
    atomic::fence(Ordering::SeqCst);
    // SAFETY: caller-validated pointer; userspace is the sole writer.
    unsafe {
        ptr::write_volatile(ptr, value);
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
    use test_case::test_case;

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

    fn write<T: Debug>(mmapped_buf: &mut MMappedBuf, offset: usize, value: T) -> usize {
        let dst: *mut _ = mmapped_buf;
        let head = offset + size_of::<T>();
        unsafe {
            ptr::write_unaligned(dst.byte_add(PAGE_SIZE + offset).cast(), value);
            mmapped_buf.mmap_page.data_head = head as u64;
        }
        head
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

    fn sample_bytes(sample: &PerfSample<'_>) -> Vec<u8> {
        let (head, tail) = sample.as_slices();
        let mut v = Vec::with_capacity(head.len() + tail.len());
        v.extend_from_slice(head);
        v.extend_from_slice(tail);
        v
    }

    #[test_case(&[] ; "empty")]
    #[test_case(&[0xCAFEBABEu32] ; "single")]
    #[test_case(&[0xCAFEBABEu32, 0xBADCAFEu32] ; "consecutive")]
    fn test_next_event_samples(expected: &[u32]) {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        let mut offset = 0;
        for &v in expected {
            offset = write_sample(&mut mmapped_buf, offset, v);
        }

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let mut payloads = Vec::new();
        while let Some(event) = buf.next_event() {
            match event {
                PerfEvent::Sample(sample) => payloads.push(u32_from_buf(&sample_bytes(&sample))),
                PerfEvent::Lost { count } => panic!("unexpected lost: {count}"),
            }
        }
        assert_eq!(payloads, expected);
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

    fn fixture_wrap_data(mmapped_buf: &mut MMappedBuf) -> &'static [u8] {
        let (left, right) = if cfg!(target_endian = "little") {
            (0xCAFEBABEu32, 0xBAADCAFEu32)
        } else {
            (0xBAADCAFEu32, 0xCAFEBABEu32)
        };
        let offset = PAGE_SIZE - size_of::<TestPerfRecord<u32>>();
        write(
            mmapped_buf,
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
        write(mmapped_buf, 0, right);
        mmapped_buf.mmap_page.data_tail = offset as u64;
        static EXPECTED: [u8; 8] = 0xBAADCAFECAFEBABEu64.to_ne_bytes();
        &EXPECTED
    }

    fn fixture_wrap_size_prefix(mmapped_buf: &mut MMappedBuf) -> &'static [u8] {
        let offset = PAGE_SIZE - size_of::<perf_event_header>() - 2;
        write(
            mmapped_buf,
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
        write(mmapped_buf, PAGE_SIZE - 2, left);
        write(mmapped_buf, 0, right);
        write(mmapped_buf, 2, 0xBAADCAFEu32);
        static EXPECTED: [u8; 4] = 0xBAADCAFEu32.to_ne_bytes();
        &EXPECTED
    }

    #[test_case(fixture_wrap_data ; "data")]
    #[test_case(fixture_wrap_size_prefix ; "size_prefix")]
    fn test_next_event_wrap(setup: fn(&mut MMappedBuf) -> &'static [u8]) {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        let expected = setup(&mut mmapped_buf);

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        assert_matches!(
            buf.next_event(),
            Some(PerfEvent::Sample(sample))
                if &sample_bytes(&sample)[..expected.len()] == expected
        );
    }
}
