use std::{
    convert::Infallible,
    io,
    ops::ControlFlow,
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
/// Yielded by [`PerfEventArrayBuffer::try_fold`], [`PerfEventArrayBuffer::fold`],
/// and [`PerfEventArrayBuffer::for_each`].
///
/// [`PerfEventArrayBuffer::try_fold`]: super::PerfEventArrayBuffer::try_fold
/// [`PerfEventArrayBuffer::fold`]: super::PerfEventArrayBuffer::fold
/// [`PerfEventArrayBuffer::for_each`]: super::PerfEventArrayBuffer::for_each
#[derive(Debug)]
pub enum PerfEvent<'a> {
    /// A sample emitted by `bpf_perf_event_output()`. The bytes are exposed
    /// as up to two slices borrowed directly from the kernel-mapped ring
    /// buffer; the second slice is empty for samples that fit contiguously,
    /// and both are populated when a sample straddles the ring boundary. The
    /// bytes include any kernel-side alignment padding that follows the
    /// payload.
    #[doc(alias = "PERF_RECORD_SAMPLE")]
    Sample {
        /// First chunk of the sample, or the entire sample when it does not wrap.
        head: &'a [u8],
        /// Second chunk; empty unless the sample straddles the ring boundary.
        tail: &'a [u8],
    },
    /// A signal from the kernel that samples were dropped because the ring
    /// buffer was full.
    #[doc(alias = "PERF_RECORD_LOST")]
    Lost {
        /// Number of dropped samples.
        count: u64,
    },
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

    /// Read `data_head`, the kernel's producer position. Pairs with the
    /// kernel's `smp_wmb() + WRITE_ONCE()` publish [1].
    ///
    /// [1]: https://github.com/torvalds/linux/blob/05f7e89a/kernel/events/ring_buffer.c#L113-L114
    fn data_head(&self) -> u64 {
        // SAFETY: `self.buf()` points to the mmap'd `perf_event_mmap_page`
        // for the lifetime of `self`. The kernel writes this field
        // concurrently, so we must use `read_volatile`; an `&u64` would be UB.
        let value = unsafe { ptr::read_volatile(&raw const (*self.buf().as_ptr()).data_head) };
        atomic::fence(Ordering::Acquire);
        value
    }

    /// Read `data_tail`, the userspace consumer position. Userspace is the
    /// sole writer, so a plain read suffices.
    fn data_tail(&self) -> u64 {
        // SAFETY: `self.buf()` points to the mmap'd `perf_event_mmap_page`
        // for the lifetime of `self`. Only userspace writes this field, so
        // there is no concurrent kernel write to race with.
        unsafe { (*self.buf().as_ptr()).data_tail }
    }

    /// Mutable pointer to `data_tail`, for use by [`TailTracker`] which
    /// commits the local position with a release-store on drop.
    fn data_tail_ptr(&mut self) -> NonNull<u64> {
        // SAFETY: same as `data_head`.
        unsafe { NonNull::new_unchecked(&raw mut (*self.buf().as_ptr()).data_tail) }
    }

    /// Pointer to the start of the data pages following the header page.
    const fn data_pages(&self) -> *const u8 {
        // SAFETY: the mmap spans `page_size + size` bytes; the data area
        // starts at offset `page_size`.
        unsafe { self.buf().as_ptr().byte_add(self.page_size) }.cast::<u8>()
    }

    pub(crate) fn readable(&self) -> bool {
        self.data_head() != self.data_tail()
    }

    pub(crate) fn try_fold<B, C, F>(&mut self, init: C, mut f: F) -> ControlFlow<B, C>
    where
        F: FnMut(C, PerfEvent<'_>) -> ControlFlow<B, C>,
    {
        let base = self.data_pages();
        let mmap_size = self.size;
        let data_head = self.data_head();
        let initial_tail = self.data_tail();
        let mut tracker = TailTracker::new(self.data_tail_ptr(), initial_tail);

        let mut acc = init;
        while tracker.tail != data_head {
            let event_start = (tracker.tail % mmap_size as u64) as usize;
            // SAFETY: the kernel guarantees event headers are 8-byte aligned
            // and never span the ring buffer wrap boundary, so reading a
            // `perf_event_header` at `base + event_start` is in-bounds.
            let event: perf_event_header =
                unsafe { ptr::read_unaligned(base.add(event_start).cast()) };
            let event_size = event.size as usize;
            let event_type = event.type_;
            tracker.advance(event_size as u64);

            let perf_event = match event_type {
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
                        // not overwrite these bytes until `data_tail` is
                        // committed (via `TailTracker::drop`).
                        let s =
                            unsafe { slice::from_raw_parts(base.add(sample_start), sample_size) };
                        (s, &[][..])
                    } else {
                        let first = mmap_size - sample_start;
                        // SAFETY: `[sample_start, mmap_size)` and
                        // `[0, sample_size - first)` are disjoint ranges within
                        // the mmap data area; together they cover the wrapping
                        // sample exactly. The kernel will not overwrite either
                        // range until `data_tail` is committed (via
                        // `TailTracker::drop`).
                        let head = unsafe { slice::from_raw_parts(base.add(sample_start), first) };
                        let tail = unsafe { slice::from_raw_parts(base, sample_size - first) };
                        (head, tail)
                    };
                    PerfEvent::Sample { head, tail }
                }
                x if x == PERF_RECORD_LOST as u32 => {
                    let mut count_buf = [0u8; size_of::<u64>()];
                    fill_from_mmap(
                        event_start + size_of::<perf_event_header>() + size_of::<u64>(),
                        base,
                        mmap_size,
                        &mut count_buf,
                    );
                    PerfEvent::Lost {
                        count: u64::from_ne_bytes(count_buf),
                    }
                }
                _ => continue,
            };

            match f(acc, perf_event) {
                ControlFlow::Continue(next) => acc = next,
                ControlFlow::Break(v) => return ControlFlow::Break(v),
            }
        }

        ControlFlow::Continue(acc)
    }

    pub(crate) fn fold<C, F>(&mut self, init: C, mut f: F) -> C
    where
        F: FnMut(C, PerfEvent<'_>) -> C,
    {
        let ControlFlow::Continue(acc) = self
            .try_fold::<Infallible, _, _>(init, |acc, event| ControlFlow::Continue(f(acc, event)));
        acc
    }

    pub(crate) fn for_each<F>(&mut self, mut f: F)
    where
        F: FnMut(PerfEvent<'_>),
    {
        self.fold((), |(), event| f(event))
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

/// Tracks the local `data_tail` position during a drain. On drop, commits the
/// position to the shared `perf_event_mmap_page` so the kernel may reuse the
/// consumed bytes. Combining the per-event advance into a single
/// release-store amortizes the kernel-visible barrier across the drain and
/// preserves panic safety.
struct TailTracker {
    data_tail_ptr: NonNull<u64>,
    tail: u64,
    dirty: bool,
}

impl TailTracker {
    const fn new(data_tail_ptr: NonNull<u64>, tail: u64) -> Self {
        Self {
            data_tail_ptr,
            tail,
            dirty: false,
        }
    }

    const fn advance(&mut self, by: u64) {
        self.tail = self.tail.wrapping_add(by);
        self.dirty = true;
    }
}

impl Drop for TailTracker {
    fn drop(&mut self) {
        let Self {
            data_tail_ptr,
            tail,
            dirty,
        } = self;
        if *dirty {
            // Release-store of `data_tail`. Pairs with the kernel's
            // `READ_ONCE()` load [1]. The userspace barrier contract mirrors
            // `tools/include/linux/ring_buffer.h`.
            //
            // [1]: https://github.com/torvalds/linux/blob/05f7e89a/kernel/events/ring_buffer.c#L202
            atomic::fence(Ordering::SeqCst);
            // SAFETY: `data_tail_ptr` was derived from a `&mut PerfBuffer`
            // and remains valid for the lifetime of this tracker; userspace
            // is the sole writer of `data_tail`.
            unsafe {
                ptr::write_volatile(data_tail_ptr.as_ptr(), *tail);
            }
        }
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

    fn sample_bytes(head: &[u8], tail: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(head.len() + tail.len());
        v.extend_from_slice(head);
        v.extend_from_slice(tail);
        v
    }

    #[test_case(&[] ; "empty")]
    #[test_case(&[0xCAFEBABEu32] ; "single")]
    #[test_case(&[0xCAFEBABEu32, 0xBADCAFEu32] ; "consecutive")]
    fn test_for_each_samples(expected: &[u32]) {
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
        buf.for_each(|event| match event {
            PerfEvent::Sample { head, tail } => {
                payloads.push(u32_from_buf(&sample_bytes(head, tail)));
            }
            PerfEvent::Lost { count } => panic!("unexpected lost: {count}"),
        });
        assert_eq!(payloads, expected);
    }

    #[test]
    fn test_for_each_lost() {
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

        let mut events = Vec::new();
        buf.for_each(|event| match event {
            PerfEvent::Sample { .. } => panic!("unexpected sample"),
            PerfEvent::Lost { count } => events.push(count),
        });
        assert_eq!(events, [0xCAFEBABE]);
    }

    // The `write` helper sets `data_head` to the post-write absolute byte
    // offset, which is convenient for non-wrapping records but does not match
    // the kernel-side semantics of monotonic `data_head`/`data_tail` counters.
    // Wrap fixtures fix `data_head` up afterwards to match the real kernel
    // contract (tail + total_event_size).
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
        mmapped_buf.mmap_page.data_head = (offset + size_of::<TestPerfRecord<u64>>()) as u64;
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
        // The sample size prefix is `size_of::<u32>()` (matches the u32
        // payload below). It straddles the wrap boundary as two u16 halves.
        let (left, right) = if cfg!(target_endian = "little") {
            (size_of::<u32>() as u16, 0u16)
        } else {
            (0u16, size_of::<u32>() as u16)
        };
        write(mmapped_buf, PAGE_SIZE - 2, left);
        write(mmapped_buf, 0, right);
        write(mmapped_buf, 2, 0xBAADCAFEu32);
        mmapped_buf.mmap_page.data_tail = offset as u64;
        mmapped_buf.mmap_page.data_head = (offset + size_of::<TestPerfRecord<u64>>()) as u64;
        static EXPECTED: [u8; 4] = 0xBAADCAFEu32.to_ne_bytes();
        &EXPECTED
    }

    #[test_case(fixture_wrap_data ; "data")]
    #[test_case(fixture_wrap_size_prefix ; "size_prefix")]
    fn test_for_each_wrap(setup: fn(&mut MMappedBuf) -> &'static [u8]) {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        let expected = setup(&mut mmapped_buf);

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let mut got: Vec<u8> = Vec::new();
        buf.for_each(|event| match event {
            PerfEvent::Sample { head, tail } => got.extend(sample_bytes(head, tail)),
            PerfEvent::Lost { count } => panic!("unexpected lost: {count}"),
        });
        assert_eq!(&got[..expected.len()], expected);
    }
}
