use std::{
    ffi::c_void,
    io, mem,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd},
    ptr, slice,
    sync::atomic::{self, AtomicPtr, Ordering},
};

use bytes::BytesMut;
use libc::{munmap, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE};
use thiserror::Error;

use crate::{
    generated::{
        perf_event_header, perf_event_mmap_page,
        perf_event_type::{PERF_RECORD_LOST, PERF_RECORD_SAMPLE},
    },
    sys::{mmap, perf_event_ioctl, perf_event_open_bpf, SysResult},
    PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE,
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

#[derive(Debug)]
pub(crate) struct PerfBuffer {
    buf: AtomicPtr<perf_event_mmap_page>,
    size: usize,
    page_size: usize,
    fd: OwnedFd,
}

impl PerfBuffer {
    pub(crate) fn open(
        cpu_id: u32,
        page_size: usize,
        page_count: usize,
    ) -> Result<PerfBuffer, PerfBufferError> {
        if !page_count.is_power_of_two() {
            return Err(PerfBufferError::InvalidPageCount { page_count });
        }

        let fd = perf_event_open_bpf(cpu_id as i32)
            .map_err(|(_, io_error)| PerfBufferError::OpenError { io_error })?;
        let size = page_size * page_count;
        let buf = unsafe {
            mmap(
                ptr::null_mut(),
                size + page_size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                fd.as_fd(),
                0,
            )
        };
        if buf == MAP_FAILED {
            return Err(PerfBufferError::MMapError {
                io_error: io::Error::last_os_error(),
            });
        }

        let perf_buf = PerfBuffer {
            buf: AtomicPtr::new(buf as *mut perf_event_mmap_page),
            fd,
            size,
            page_size,
        };

        perf_event_ioctl(perf_buf.fd.as_fd(), PERF_EVENT_IOC_ENABLE, 0)
            .map_err(|(_, io_error)| PerfBufferError::PerfEventEnableError { io_error })?;

        Ok(perf_buf)
    }

    pub(crate) fn readable(&self) -> bool {
        let header = self.buf.load(Ordering::SeqCst);
        let head = unsafe { (*header).data_head } as usize;
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
        let header = self.buf.load(Ordering::SeqCst);
        let base = header as usize + self.page_size;

        let mut events = Events { read: 0, lost: 0 };
        let mut buf_n = 0;

        let fill_buf = |start_off, base, mmap_size, out_buf: &mut [u8]| {
            let len = out_buf.len();

            let end = (start_off + len) % mmap_size;
            let start = start_off % mmap_size;

            if start < end {
                out_buf.copy_from_slice(unsafe {
                    slice::from_raw_parts((base + start) as *const u8, len)
                });
            } else {
                let size = mmap_size - start;
                unsafe {
                    out_buf[..size]
                        .copy_from_slice(slice::from_raw_parts((base + start) as *const u8, size));
                    out_buf[size..]
                        .copy_from_slice(slice::from_raw_parts(base as *const u8, len - size));
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
        while head != tail {
            if buf_n == buffers.len() {
                break;
            }

            let buf = &mut buffers[buf_n];

            let event_start = tail % self.size;
            let event =
                unsafe { ptr::read_unaligned((base + event_start) as *const perf_event_header) };
            let event_size = event.size as usize;

            match read_event(event_start, event.type_, base, buf) {
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
                    atomic::fence(Ordering::SeqCst);
                    unsafe { (*header).data_tail = tail as u64 };
                    return Err(e);
                }
            }
            tail += event_size;
        }

        atomic::fence(Ordering::SeqCst);
        unsafe { (*header).data_tail = tail as u64 };

        Ok(events)
    }
}

impl AsRawFd for PerfBuffer {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for PerfBuffer {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl Drop for PerfBuffer {
    fn drop(&mut self) {
        unsafe {
            let _: SysResult<_> = perf_event_ioctl(self.fd.as_fd(), PERF_EVENT_IOC_DISABLE, 0);
            munmap(
                self.buf.load(Ordering::SeqCst) as *mut c_void,
                self.size + self.page_size,
            );
        }
    }
}

#[derive(Debug)]
#[repr(C)]
struct Sample {
    header: perf_event_header,
    pub size: u32,
}

#[repr(C)]
#[derive(Debug)]
struct LostSamples {
    header: perf_event_header,
    pub id: u64,
    pub count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        generated::perf_event_mmap_page,
        sys::{override_syscall, Syscall, TEST_MMAP_RET},
    };
    use assert_matches::assert_matches;
    use std::{fmt::Debug, mem};

    const PAGE_SIZE: usize = 4096;
    union MMappedBuf {
        mmap_page: perf_event_mmap_page,
        data: [u8; PAGE_SIZE * 2],
    }

    fn fake_mmap(buf: &MMappedBuf) {
        override_syscall(|call| match call {
            Syscall::PerfEventOpen { .. } | Syscall::PerfEventIoctl { .. } => Ok(42),
            call => panic!("unexpected syscall: {:?}", call),
        });
        TEST_MMAP_RET.with(|ret| *ret.borrow_mut() = buf as *const _ as *mut _);
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
    #[cfg_attr(miri, ignore)]
    fn test_no_out_bufs() {
        let mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        fake_mmap(&mmapped_buf);

        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();
        assert_matches!(buf.read_events(&mut []), Err(PerfBufferError::NoBuffers))
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_no_events() {
        let mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        fake_mmap(&mmapped_buf);

        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();
        let out_buf = BytesMut::with_capacity(4);
        assert_eq!(
            buf.read_events(&mut [out_buf]).unwrap(),
            Events { read: 0, lost: 0 }
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_read_first_lost() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        fake_mmap(&mmapped_buf);

        let evt = LostSamples {
            header: perf_event_header {
                type_: PERF_RECORD_LOST as u32,
                misc: 0,
                size: mem::size_of::<LostSamples>() as u16,
            },
            id: 1,
            count: 0xCAFEBABE,
        };
        write(&mut mmapped_buf, 0, evt);

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

    fn write<T: Debug>(mmapped_buf: &mut MMappedBuf, offset: usize, value: T) -> usize {
        let dst = (mmapped_buf as *const _ as usize + PAGE_SIZE + offset) as *const PerfSample<T>
            as *mut T;
        unsafe {
            ptr::write_unaligned(dst, value);
            mmapped_buf.mmap_page.data_head = (offset + mem::size_of::<T>()) as u64;
            mmapped_buf.mmap_page.data_head as usize
        }
    }

    fn write_sample<T: Debug>(mmapped_buf: &mut MMappedBuf, offset: usize, value: T) -> usize {
        let sample = PerfSample {
            s_hdr: Sample {
                header: perf_event_header {
                    type_: PERF_RECORD_SAMPLE as u32,
                    misc: 0,
                    size: mem::size_of::<PerfSample<T>>() as u16,
                },
                size: mem::size_of::<T>() as u32,
            },
            value,
        };
        write(mmapped_buf, offset, sample)
    }

    fn u32_from_buf(buf: &[u8]) -> u32 {
        u32::from_ne_bytes(buf[..4].try_into().unwrap())
    }

    fn u64_from_buf(buf: &[u8]) -> u64 {
        u64::from_ne_bytes(buf[..8].try_into().unwrap())
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_read_first_sample() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        fake_mmap(&mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        write_sample(&mut mmapped_buf, 0, 0xCAFEBABEu32);

        let mut out_bufs = [BytesMut::with_capacity(4)];

        let events = buf.read_events(&mut out_bufs).unwrap();
        assert_eq!(events, Events { lost: 0, read: 1 });
        assert_eq!(u32_from_buf(&out_bufs[0]), 0xCAFEBABE);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_read_many_with_many_reads() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        fake_mmap(&mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let next = write_sample(&mut mmapped_buf, 0, 0xCAFEBABEu32);
        write_sample(&mut mmapped_buf, next, 0xBADCAFEu32);

        let mut out_bufs = [BytesMut::with_capacity(4)];

        let events = buf.read_events(&mut out_bufs).unwrap();
        assert_eq!(events, Events { lost: 0, read: 1 });
        assert_eq!(u32_from_buf(&out_bufs[0]), 0xCAFEBABE);

        let events = buf.read_events(&mut out_bufs).unwrap();
        assert_eq!(events, Events { lost: 0, read: 1 });
        assert_eq!(u32_from_buf(&out_bufs[0]), 0xBADCAFE);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_read_many_with_one_read() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        fake_mmap(&mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let next = write_sample(&mut mmapped_buf, 0, 0xCAFEBABEu32);
        write_sample(&mut mmapped_buf, next, 0xBADCAFEu32);

        let mut out_bufs = (0..3)
            .map(|_| BytesMut::with_capacity(4))
            .collect::<Vec<_>>();

        let events = buf.read_events(&mut out_bufs).unwrap();
        assert_eq!(events, Events { lost: 0, read: 2 });
        assert_eq!(u32_from_buf(&out_bufs[0]), 0xCAFEBABE);
        assert_eq!(u32_from_buf(&out_bufs[1]), 0xBADCAFE);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_read_last_sample() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        fake_mmap(&mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let offset = PAGE_SIZE - mem::size_of::<PerfSample<u32>>();
        mmapped_buf.mmap_page.data_tail = offset as u64;
        write_sample(&mut mmapped_buf, offset, 0xCAFEBABEu32);

        let mut out_bufs = [BytesMut::with_capacity(4)];

        let events = buf.read_events(&mut out_bufs).unwrap();
        assert_eq!(events, Events { lost: 0, read: 1 });
        assert_eq!(u32_from_buf(&out_bufs[0]), 0xCAFEBABE);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_read_wrapping_sample_size() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        fake_mmap(&mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let header = perf_event_header {
            type_: PERF_RECORD_SAMPLE as u32,
            misc: 0,
            size: mem::size_of::<PerfSample<u64>>() as u16,
        };

        let offset = PAGE_SIZE - mem::size_of::<perf_event_header>() - 2;
        mmapped_buf.mmap_page.data_tail = offset as u64;
        write(&mut mmapped_buf, offset, header);
        write(&mut mmapped_buf, PAGE_SIZE - 2, 0x0004u16);
        write(&mut mmapped_buf, 0, 0x0000u16);
        write(&mut mmapped_buf, 2, 0xBAADCAFEu32);

        let mut out_bufs = [BytesMut::with_capacity(8)];

        let events = buf.read_events(&mut out_bufs).unwrap();
        assert_eq!(events, Events { lost: 0, read: 1 });
        assert_eq!(u32_from_buf(&out_bufs[0]), 0xBAADCAFE);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_read_wrapping_value() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        fake_mmap(&mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let sample = PerfSample {
            s_hdr: Sample {
                header: perf_event_header {
                    type_: PERF_RECORD_SAMPLE as u32,
                    misc: 0,
                    size: mem::size_of::<PerfSample<u64>>() as u16,
                },
                size: mem::size_of::<u64>() as u32,
            },
            value: 0xCAFEBABEu32,
        };

        let offset = PAGE_SIZE - mem::size_of::<PerfSample<u32>>();
        mmapped_buf.mmap_page.data_tail = offset as u64;
        write(&mut mmapped_buf, offset, sample);
        write(&mut mmapped_buf, 0, 0xBAADCAFEu32);

        let mut out_bufs = [BytesMut::with_capacity(8)];

        let events = buf.read_events(&mut out_bufs).unwrap();
        assert_eq!(events, Events { lost: 0, read: 1 });
        assert_eq!(u64_from_buf(&out_bufs[0]), 0xBAADCAFECAFEBABE);
    }
}
