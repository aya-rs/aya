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
        // SAFETY: `self.buf()` points to the mmap'd `perf_event_mmap_page` for
        // the lifetime of `self`, so the field projection is in-bounds and
        // aligned.
        let ptr = unsafe { &raw const (*self.buf().as_ptr()).data_head };
        // SAFETY: the kernel writes `data_head` concurrently; a plain read
        // would be UB.
        let value = unsafe { ptr::read_volatile(ptr) };
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

    /// Mutable pointer to `data_tail`, used by [`try_fold`] to commit the
    /// local position with a release-store on scope exit.
    ///
    /// [`try_fold`]: Self::try_fold
    fn data_tail_ptr(&mut self) -> NonNull<u64> {
        // SAFETY: `self.buf()` points to the mmap'd `perf_event_mmap_page` for
        // the lifetime of `self`, so the field projection is in-bounds and
        // aligned.
        let ptr = unsafe { &raw mut (*self.buf().as_ptr()).data_tail };
        // SAFETY: `self.buf()` is `NonNull`, so a field projection within it
        // is non-null.
        unsafe { NonNull::new_unchecked(ptr) }
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
        let data_tail_ptr = self.data_tail_ptr();

        // Defer the userspace release-store of `data_tail` to scope exit so
        // it pairs with the kernel's `READ_ONCE()` [1] in one SeqCst barrier
        // instead of per event, and remains panic-safe.
        //
        // [1]: https://github.com/torvalds/linux/blob/05f7e89a/kernel/events/ring_buffer.c#L202
        let mut guard = scopeguard::guard(initial_tail, |tail| {
            if tail != initial_tail {
                atomic::fence(Ordering::SeqCst);
                // SAFETY: `data_tail_ptr` was derived from a `&mut PerfBuffer`
                // outliving this scope; userspace is the sole writer of
                // `data_tail`.
                unsafe {
                    ptr::write_volatile(data_tail_ptr.as_ptr(), tail);
                }
            }
        });

        let tail = &mut *guard;

        let mut acc = init;
        while *tail != data_head {
            let event_start = (*tail % mmap_size as u64) as usize;
            debug_assert_eq!(
                event_start % 8,
                0,
                "perf records are 8-byte aligned (event_start={event_start})"
            );
            // SAFETY: the kernel pads each record to 8 bytes [1] and the
            // buffer is page-aligned, so `base + event_start` is aligned for
            // `perf_event_header` and the 8-byte header fits before the wrap
            // boundary.
            //
            // [1]: https://github.com/torvalds/linux/blob/05f7e89a/kernel/events/core.c#L8451
            let event: perf_event_header = unsafe { ptr::read(base.add(event_start).cast()) };
            *tail = tail.wrapping_add(u64::from(event.size));

            let perf_event = match event.type_ {
                x if x == PERF_RECORD_SAMPLE as u32 => {
                    // The `u32` size prefix follows the header at an 8-aligned
                    // offset, so it never spans the wrap.
                    let size_offset = (event_start + size_of::<perf_event_header>()) % mmap_size;
                    // SAFETY: same kernel-alignment guarantee as the header read.
                    let sample_size: u32 = unsafe { ptr::read(base.add(size_offset).cast()) };
                    let sample_size = sample_size as usize;

                    // The sample payload follows the size prefix and may span
                    // the wrap.
                    let sample_start =
                        (event_start + size_of::<perf_event_header>() + size_of::<u32>())
                            % mmap_size;
                    debug_assert!(sample_size <= mmap_size);
                    let (head, tail) = if let Some(second) =
                        (sample_start + sample_size).checked_sub(mmap_size)
                    {
                        let first = mmap_size - sample_start;
                        // SAFETY: `[sample_start, mmap_size)` and `[0, second)`
                        // are disjoint ranges within the mmap region; the
                        // kernel will not overwrite them until `data_tail`
                        // is committed on scope exit.
                        let head = unsafe { slice::from_raw_parts(base.add(sample_start), first) };
                        let tail = unsafe { slice::from_raw_parts(base, second) };
                        (head, tail)
                    } else {
                        // SAFETY: same as above; `sample_start + sample_size
                        // <= mmap_size`, contiguous within mmap.
                        let head =
                            unsafe { slice::from_raw_parts(base.add(sample_start), sample_size) };
                        (head, &[][..])
                    };
                    PerfEvent::Sample { head, tail }
                }
                x if x == PERF_RECORD_LOST as u32 => {
                    // `PERF_RECORD_LOST` layout is
                    // `{ header, u64 id, u64 lost, sample_id }` [1]; skip past
                    // `id` to read the `lost` count.
                    //
                    // [1]: https://github.com/torvalds/linux/blob/05f7e89a/include/uapi/linux/perf_event.h#L906-L914
                    let lost_offset =
                        (event_start + size_of::<perf_event_header>() + size_of::<u64>())
                            % mmap_size;
                    // SAFETY: same kernel-alignment guarantee as the header read; the
                    // fixed 8-byte field at an 8-aligned offset cannot span the wrap.
                    let count: u64 = unsafe { ptr::read(base.add(lost_offset).cast()) };
                    PerfEvent::Lost { count }
                }
                event_type => {
                    // `PerfBuffer::open` configures `SoftwareEvent::BpfOutput`
                    // with no side-band attr flags [1]; the kernel only emits
                    // SAMPLE and LOST.
                    //
                    // [1]: https://github.com/torvalds/linux/blob/05f7e89a/kernel/events/core.c#L5182-L5200
                    debug_assert!(false, "unexpected perf record type: {event_type}");
                    continue;
                }
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

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use assert_matches::assert_matches;
    use rstest::rstest;

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

    #[rstest]
    #[case::empty(&[])]
    #[case::single(&[0xCAFEBABEu32])]
    #[case::consecutive(&[0xCAFEBABEu32, 0xBADCAFEu32])]
    fn test_for_each_samples(#[case] expected: &[u32]) {
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

    #[test]
    fn test_for_each_wrap() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        let expected = fixture_wrap_data(&mut mmapped_buf);

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
