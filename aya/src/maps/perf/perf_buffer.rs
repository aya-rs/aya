use std::{
    io,
    marker::PhantomData,
    mem,
    os::fd::{AsFd, BorrowedFd},
    ptr,
    rc::Rc,
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
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Events {
    /// The number of events read.
    pub read: usize,
    /// The number of events lost.
    pub lost: usize,
}

/// Zero-copy view into a sample payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawSampleData<'a> {
    first: &'a [u8],
    second: &'a [u8],
}

impl<'a> RawSampleData<'a> {
    /// Returns the two slices that make up the sample data.
    pub fn as_slices(&self) -> (&'a [u8], &'a [u8]) {
        (self.first, self.second)
    }

    /// Returns the total length of the sample data.
    pub fn len(&self) -> usize {
        self.first.len() + self.second.len()
    }

    /// Returns true if the sample data is contiguous.
    pub fn is_contiguous(&self) -> bool {
        self.second.is_empty()
    }
}

/// Zero-copy sample payload returned by [`RawEvents`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawSample<'a> {
    data: RawSampleData<'a>,
}

impl<'a> RawSample<'a> {
    /// Returns the zero-copy data slices for this sample.
    pub fn data(&self) -> RawSampleData<'a> {
        self.data
    }
}

/// Iterator over zero-copy samples in a perf buffer.
///
/// The consumer position is updated when this value is dropped. Do not hold
/// instances of this type or its yielded samples across `.await` points. Avoid
/// using `mem::forget`, as that will prevent advancing the tail and eventually
/// stall or drop events.
pub struct RawEvents<'a> {
    perf: &'a mut PerfBuffer,
    head: usize,
    tail: usize,
    base: *const u8,
    events: Events,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl<'a> RawEvents<'a> {
    /// Returns the number of events read and lost so far.
    pub fn events(&self) -> Events {
        self.events
    }

    fn read_bytes_into(&self, start_off: usize, out: &mut [u8]) {
        let len = out.len();
        let start = start_off % self.perf.size;
        let end = (start + len) % self.perf.size;

        if start < end {
            out.copy_from_slice(unsafe { slice::from_raw_parts(self.base.add(start), len) });
        } else {
            let size = self.perf.size - start;
            unsafe {
                out[..size].copy_from_slice(slice::from_raw_parts(self.base.add(start), size));
                out[size..].copy_from_slice(slice::from_raw_parts(self.base, len - size));
            }
        }
    }

    fn read_event_header(&self, start_off: usize) -> perf_event_header {
        let mut buf = [0u8; mem::size_of::<perf_event_header>()];
        self.read_bytes_into(start_off, &mut buf);
        unsafe { ptr::read_unaligned(buf.as_ptr().cast()) }
    }

    fn read_u32(&self, start_off: usize) -> u32 {
        let mut buf = [0u8; mem::size_of::<u32>()];
        self.read_bytes_into(start_off, &mut buf);
        u32::from_ne_bytes(buf)
    }

    fn read_u64(&self, start_off: usize) -> u64 {
        let mut buf = [0u8; mem::size_of::<u64>()];
        self.read_bytes_into(start_off, &mut buf);
        u64::from_ne_bytes(buf)
    }

    fn sample_data(&self, start_off: usize, len: usize) -> RawSampleData<'a> {
        let start = start_off % self.perf.size;
        if start + len <= self.perf.size {
            let first = unsafe { slice::from_raw_parts(self.base.add(start), len) };
            RawSampleData {
                first,
                second: &[],
            }
        } else {
            let first_len = self.perf.size - start;
            let first = unsafe { slice::from_raw_parts(self.base.add(start), first_len) };
            let second = unsafe { slice::from_raw_parts(self.base, len - first_len) };
            RawSampleData { first, second }
        }
    }
}

impl<'a> Iterator for RawEvents<'a> {
    type Item = RawSample<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let header_size = mem::size_of::<perf_event_header>();
        while self.head != self.tail {
            let event_start = self.tail % self.perf.size;
            let event = self.read_event_header(event_start);
            let event_size = event.size as usize;
            if event_size < header_size {
                // Malformed record; avoid infinite loops and out-of-bounds reads.
                self.tail = self.head;
                return None;
            }

            match event.type_ {
                x if x == PERF_RECORD_SAMPLE as u32 => {
                    if event_size < header_size + mem::size_of::<u32>() {
                        self.tail = self.head;
                        return None;
                    }
                    let sample_size = self.read_u32(event_start + header_size) as usize;
                    let payload_max = event_size - header_size - mem::size_of::<u32>();
                    if sample_size > payload_max || sample_size > self.perf.size {
                        self.tail = self.head;
                        return None;
                    }
                    let sample_start =
                        (event_start + header_size + mem::size_of::<u32>()) % self.perf.size;
                    let data = self.sample_data(sample_start, sample_size);
                    self.tail += event_size;
                    self.events.read += 1;
                    return Some(RawSample { data });
                }
                x if x == PERF_RECORD_LOST as u32 => {
                    if event_size < header_size + mem::size_of::<u64>() * 2 {
                        self.tail = self.head;
                        return None;
                    }
                    let count = self.read_u64(event_start + header_size + mem::size_of::<u64>());
                    self.events.lost += count as usize;
                    self.tail += event_size;
                }
                _ => {
                    self.tail += event_size;
                }
            }
        }
        None
    }
}

impl Drop for RawEvents<'_> {
    fn drop(&mut self) {
        let header = self.perf.buf().as_ptr();
        atomic::fence(Ordering::SeqCst);
        unsafe { (*header).data_tail = self.tail as u64 };
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

    fn buf(&self) -> ptr::NonNull<perf_event_mmap_page> {
        self.mmap.ptr().cast()
    }

    pub(crate) fn readable(&self) -> bool {
        let header = self.buf().as_ptr();
        let head = unsafe { (*header).data_head } as usize;
        atomic::fence(Ordering::Acquire);
        let tail = unsafe { (*header).data_tail } as usize;
        head != tail
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

        let fill_buf = |start_off, base: *const u8, mmap_size, out_buf: &mut [u8]| {
            let len = out_buf.len();

            let end = (start_off + len) % mmap_size;
            let start = start_off % mmap_size;

            if start < end {
                out_buf.copy_from_slice(unsafe { slice::from_raw_parts(base.add(start), len) });
            } else {
                let size = mmap_size - start;
                unsafe {
                    out_buf[..size].copy_from_slice(slice::from_raw_parts(base.add(start), size));
                    out_buf[size..].copy_from_slice(slice::from_raw_parts(base, len - size));
                }
            }
        };

        let read_event = |event_start, event_type, base, buf: &mut BytesMut| {
            let sample_size = match event_type {
                x if x == PERF_RECORD_SAMPLE as u32 || x == PERF_RECORD_LOST as u32 => {
                    let mut size = [0u8; mem::size_of::<u32>()];
                    fill_buf(
                        event_start + mem::size_of::<perf_event_header>(),
                        base,
                        self.size,
                        &mut size,
                    );
                    u32::from_ne_bytes(size)
                }
                _ => return Ok(None),
            } as usize;

            let sample_start =
                (event_start + mem::size_of::<perf_event_header>() + mem::size_of::<u32>())
                    % self.size;

            match event_type {
                x if x == PERF_RECORD_SAMPLE as u32 => {
                    buf.clear();
                    buf.reserve(sample_size);
                    unsafe { buf.set_len(sample_size) };

                    fill_buf(sample_start, base, self.size, buf);

                    Ok(Some((1, 0)))
                }
                x if x == PERF_RECORD_LOST as u32 => {
                    let mut count = [0u8; mem::size_of::<u64>()];
                    fill_buf(
                        event_start + mem::size_of::<perf_event_header>() + mem::size_of::<u64>(),
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
        unsafe { (*header).data_tail = tail as u64 };

        result.map(|()| events)
    }

    pub(crate) fn read_events_raw(&mut self) -> Result<RawEvents<'_>, PerfBufferError> {
        let header = self.buf().as_ptr();
        let base = unsafe { header.byte_add(self.page_size) };
        let head = unsafe { (*header).data_head } as usize;
        let tail = unsafe { (*header).data_tail } as usize;

        Ok(RawEvents {
            perf: self,
            head,
            tail,
            base: base.cast(),
            events: Events { read: 0, lost: 0 },
            _not_send_sync: PhantomData,
        })
    }
}

/// Benchmark helpers for perf buffer microbenchmarks.
#[cfg(feature = "bench")]
pub mod bench {
    use std::{
        alloc::{Layout, alloc, dealloc},
        ffi::c_void,
        mem,
        ptr,
        slice,
    };

    use aya_obj::generated::perf_event_mmap_page;
    use bytes::BytesMut;

    use super::{Events, PerfBuffer, PerfBufferError, RawEvents};
    use crate::sys::{Syscall, TEST_MMAP_RET, override_syscall};

    /// Test-only perf buffer backed by a fake mmap region.
    pub struct BenchBuffer {
        buf: PerfBuffer,
        mmap: BenchMmap,
        page_size: usize,
    }

    impl BenchBuffer {
        /// Creates a new bench buffer with a fake mmap region.
        pub fn new(page_size: usize, page_count: usize) -> Result<Self, PerfBufferError> {
            let len = page_size
                .checked_mul(page_count + 1)
                .expect("mmap size overflow");
            let mut mmap = BenchMmap::new(len, page_size);
            unsafe { ptr::write_bytes(mmap.as_mut_ptr(), 0, len) };

            override_syscall(|call| match call {
                Syscall::PerfEventOpen { .. } => Ok(crate::MockableFd::mock_signed_fd().into()),
                Syscall::PerfEventIoctl { .. } => Ok(0),
                call => panic!("unexpected syscall: {call:?}"),
            });
            TEST_MMAP_RET.with(|ret| *ret.borrow_mut() = mmap.as_mut_ptr().cast::<c_void>());

            let buf = PerfBuffer::open(1, page_size, page_count)?;

            Ok(Self {
                buf,
                mmap,
                page_size,
            })
        }

        /// Reads events into the provided buffers, copying the sample data.
        pub fn read_events(&mut self, buffers: &mut [BytesMut]) -> Result<Events, PerfBufferError> {
            self.buf.read_events(buffers)
        }

        /// Reads events without copying sample data.
        pub fn read_events_raw(&mut self) -> Result<RawEvents<'_>, PerfBufferError> {
            self.buf.read_events_raw()
        }

        /// Returns a mutable reference to the mmap header page.
        pub fn mmap_page_mut(&mut self) -> &mut perf_event_mmap_page {
            unsafe { &mut *self.mmap.as_mut_ptr().cast::<perf_event_mmap_page>() }
        }

        /// Returns a mutable slice for the data pages.
        pub fn data_mut(&mut self) -> &mut [u8] {
            let start = self.page_size;
            let len = self.buf.size;
            unsafe { slice::from_raw_parts_mut(self.mmap.as_mut_ptr().add(start), len) }
        }
    }

    /// Returns the system page size used by perf buffers.
    pub fn default_page_size() -> usize {
        crate::util::page_size()
    }

    struct BenchMmap {
        ptr: ptr::NonNull<u8>,
        _len: usize,
        layout: Layout,
    }

    impl BenchMmap {
        fn new(len: usize, align: usize) -> Self {
            let layout = Layout::from_size_align(len, align.max(mem::align_of::<usize>()))
                .expect("invalid mmap layout");
            let ptr = unsafe { alloc(layout) };
            let ptr = ptr::NonNull::new(ptr).expect("allocation failed");
            Self {
                ptr,
                _len: len,
                layout,
            }
        }

        fn as_mut_ptr(&mut self) -> *mut u8 {
            self.ptr.as_ptr()
        }
    }

    impl Drop for BenchMmap {
        fn drop(&mut self) {
            unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
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
        let _: io::Result<()> = perf_event_ioctl(self.fd.as_fd(), PerfEventIoctlRequest::Disable);
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
    union MMappedBuf {
        mmap_page: perf_event_mmap_page,
        data: [u8; PAGE_SIZE * 2],
    }

    fn fake_mmap(buf: &mut MMappedBuf) {
        let buf: *mut _ = buf;
        override_syscall(|call| match call {
            Syscall::PerfEventOpen { .. } => Ok(crate::MockableFd::mock_signed_fd().into()),
            Syscall::PerfEventIoctl { .. } => Ok(0),
            call => panic!("unexpected syscall: {call:?}"),
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

    #[test]
    fn test_raw_no_events() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let mut raw = buf.read_events_raw().unwrap();
        assert_eq!(raw.next(), None);
        assert_eq!(raw.events(), Events { read: 0, lost: 0 });
    }

    fn write<T: Debug>(mmapped_buf: &mut MMappedBuf, offset: usize, value: T) -> usize {
        let dst: *mut _ = mmapped_buf;
        let head = offset + mem::size_of::<T>();
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
                    size: mem::size_of::<LostSamples>() as u16,
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
    struct PerfSample<T: Debug> {
        s_hdr: Sample,
        value: T,
    }

    fn write_sample<T: Debug>(mmapped_buf: &mut MMappedBuf, offset: usize, value: T) -> usize {
        write(
            mmapped_buf,
            offset,
            PerfSample {
                s_hdr: Sample {
                    header: perf_event_header {
                        type_: PERF_RECORD_SAMPLE as u32,
                        misc: 0,
                        size: mem::size_of::<PerfSample<T>>() as u16,
                    },
                    size: mem::size_of::<T>() as u32,
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

    fn u64_from_raw_sample(sample: RawSample<'_>) -> u64 {
        let (first, second) = sample.data().as_slices();
        let mut out = [0u8; 8];
        let first_len = first.len().min(8);
        out[..first_len].copy_from_slice(&first[..first_len]);
        if first_len < 8 {
            out[first_len..].copy_from_slice(&second[..8 - first_len]);
        }
        u64::from_ne_bytes(out)
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
    fn test_raw_read_first_sample() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        write_sample(&mut mmapped_buf, 0, 0xCAFEBABEu32);

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let mut raw = buf.read_events_raw().unwrap();
        let sample = raw.next().expect("missing sample");
        let (first, second) = sample.data().as_slices();
        assert!(second.is_empty());
        assert_eq!(u32_from_buf(first), 0xCAFEBABE);
        assert_eq!(raw.events(), Events { lost: 0, read: 1 });
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

        let offset = PAGE_SIZE - mem::size_of::<PerfSample<u32>>();
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

        let offset = PAGE_SIZE - mem::size_of::<perf_event_header>() - 2;
        write(
            &mut mmapped_buf,
            offset,
            perf_event_header {
                type_: PERF_RECORD_SAMPLE as u32,
                misc: 0,
                size: mem::size_of::<PerfSample<u64>>() as u16,
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
    fn test_read_wrapping_value() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        let (left, right) = if cfg!(target_endian = "little") {
            (0xCAFEBABEu32, 0xBAADCAFEu32)
        } else {
            (0xBAADCAFEu32, 0xCAFEBABEu32)
        };

        let offset = PAGE_SIZE - mem::size_of::<PerfSample<u32>>();
        write(
            &mut mmapped_buf,
            offset,
            PerfSample {
                s_hdr: Sample {
                    header: perf_event_header {
                        type_: PERF_RECORD_SAMPLE as u32,
                        misc: 0,
                        size: mem::size_of::<PerfSample<u64>>() as u16,
                    },
                    size: mem::size_of::<u64>() as u32,
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

    #[test]
    fn test_raw_read_wrapping_value() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };

        let (left, right) = if cfg!(target_endian = "little") {
            (0xCAFEBABEu32, 0xBAADCAFEu32)
        } else {
            (0xBAADCAFEu32, 0xCAFEBABEu32)
        };

        let offset = PAGE_SIZE - mem::size_of::<PerfSample<u32>>();
        write(
            &mut mmapped_buf,
            offset,
            PerfSample {
                s_hdr: Sample {
                    header: perf_event_header {
                        type_: PERF_RECORD_SAMPLE as u32,
                        misc: 0,
                        size: mem::size_of::<PerfSample<u64>>() as u16,
                    },
                    size: mem::size_of::<u64>() as u32,
                },
                value: left,
            },
        );
        write(&mut mmapped_buf, 0, right);
        mmapped_buf.mmap_page.data_tail = offset as u64;

        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let mut raw = buf.read_events_raw().unwrap();
        let sample = raw.next().expect("missing sample");
        assert_eq!(u64_from_raw_sample(sample), 0xBAADCAFECAFEBABE);
        assert_eq!(raw.events(), Events { lost: 0, read: 1 });
    }
}
