use std::{
    cell::RefMut,
    convert::TryFrom,
    ffi::c_void,
    fs, io, mem,
    ops::DerefMut,
    ptr, slice,
    str::FromStr,
    sync::atomic::{self, AtomicPtr, Ordering},
};

use bytes::BytesMut;
use libc::{
    c_int, close, munmap, sysconf, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE, _SC_PAGESIZE,
};
use thiserror::Error;

use crate::{
    generated::{
        bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY, perf_event_header, perf_event_mmap_page,
        perf_event_type::*,
    },
    maps::{Map, MapError},
    syscalls::{bpf_map_update_elem, perf_event_ioctl, perf_event_open},
    RawFd, PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE,
};

const ONLINE_CPUS: &str = "/sys/devices/system/cpu/online";

#[derive(Error, Debug)]
pub enum PerfBufferError {
    #[error("invalid page count {page_count}, the value must be a power of two")]
    InvalidPageCount { page_count: usize },

    #[error("perf_event_open failed: {io_error}")]
    OpenFailed {
        #[source]
        io_error: io::Error,
    },

    #[error("mmap failed: {io_error}")]
    MMapFailed {
        #[source]
        io_error: io::Error,
    },

    #[error("PERF_EVENT_IOC_ENABLE failed: {io_error}")]
    PerfEventEnableFailed {
        #[source]
        io_error: io::Error,
    },

    #[error("read_events() was called with no output buffers")]
    NoBuffers,

    #[error("the buffer needs to be of at least {size} bytes")]
    MoreSpaceNeeded { size: usize },
}

#[derive(Debug, PartialEq)]
pub struct Events {
    pub read: usize,
    pub lost: usize,
}

struct PerfBuffer {
    buf: AtomicPtr<perf_event_mmap_page>,
    size: usize,
    page_size: usize,
    fd: RawFd,
}

impl PerfBuffer {
    fn open(
        cpu_id: u32,
        page_size: usize,
        page_count: usize,
    ) -> Result<PerfBuffer, PerfBufferError> {
        if !page_count.is_power_of_two() {
            return Err(PerfBufferError::InvalidPageCount { page_count });
        }

        let fd = perf_event_open(cpu_id as i32)
            .map_err(|(_, io_error)| PerfBufferError::OpenFailed { io_error })?
            as RawFd;
        let size = page_size * page_count;
        let buf = unsafe {
            mmap(
                ptr::null_mut(),
                size + page_size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                fd,
                0,
            )
        };
        if buf == MAP_FAILED {
            return Err(PerfBufferError::MMapFailed {
                io_error: io::Error::last_os_error(),
            });
        }

        let perf_buf = PerfBuffer {
            buf: AtomicPtr::new(buf as *mut perf_event_mmap_page),
            fd,
            size,
            page_size,
        };

        perf_event_ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)
            .map_err(|(_, io_error)| PerfBufferError::PerfEventEnableFailed { io_error })?;

        Ok(perf_buf)
    }

    pub fn read_events(&mut self, buffers: &mut [BytesMut]) -> Result<Events, PerfBufferError> {
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
                PERF_RECORD_SAMPLE | PERF_RECORD_LOST => {
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
                PERF_RECORD_SAMPLE => {
                    buf.clear();
                    if sample_size > buf.capacity() {
                        return Err(PerfBufferError::MoreSpaceNeeded { size: sample_size });
                    }

                    unsafe { buf.set_len(sample_size) };

                    fill_buf(sample_start, base, self.size, buf);

                    Ok(Some((1, 0)))
                }
                PERF_RECORD_LOST => {
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
                Err(PerfBufferError::MoreSpaceNeeded { .. }) if events.read > 0 => {
                    // we have processed some events so we're going to return those. In the
                    // next read_events() we'll return an error unless the caller increases the
                    // buffer size
                    break;
                }
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

        return Ok(events);
    }
}

impl Drop for PerfBuffer {
    fn drop(&mut self) {
        unsafe {
            let _ = perf_event_ioctl(self.fd, PERF_EVENT_IOC_DISABLE, 0);
            munmap(
                self.buf.load(Ordering::SeqCst) as *mut c_void,
                self.size + self.page_size,
            );
            close(self.fd);
        }
    }
}

#[derive(Error, Debug)]
pub enum PerfMapError {
    #[error("error parsing /sys/devices/system/cpu/online")]
    InvalidOnlineCpuFile,

    #[error("no CPUs specified")]
    NoCpus,

    #[error("invalid cpu {cpu_id}")]
    InvalidCpu { cpu_id: u32 },

    #[error("map error: {0}")]
    MapError(#[from] MapError),

    #[error("perf buffer error: {0}")]
    PerfBufferError(#[from] PerfBufferError),

    #[error("bpf_map_update_elem failed: {io_error}")]
    UpdateElementFailed {
        #[source]
        io_error: io::Error,
    },
}

pub struct PerfMap<T: DerefMut<Target = Map>> {
    map: T,
    cpu_fds: Vec<(u32, RawFd)>,
    buffers: Vec<Option<PerfBuffer>>,
}

impl<T: DerefMut<Target = Map>> PerfMap<T> {
    pub fn new(
        map: T,
        cpu_ids: Option<Vec<u32>>,
        page_count: Option<usize>,
    ) -> Result<PerfMap<T>, PerfMapError> {
        let map_type = map.obj.def.map_type;
        if map_type != BPF_MAP_TYPE_PERF_EVENT_ARRAY {
            return Err(MapError::InvalidMapType {
                map_type: map_type as u32,
            })?;
        }

        let mut cpu_ids = match cpu_ids {
            Some(ids) => ids,
            None => online_cpus().map_err(|_| PerfMapError::InvalidOnlineCpuFile)?,
        };
        if cpu_ids.is_empty() {
            return Err(PerfMapError::NoCpus);
        }
        cpu_ids.sort();
        let min_cpu = cpu_ids.first().unwrap();
        let max_cpu = cpu_ids.last().unwrap();
        let mut buffers = (*min_cpu..=*max_cpu).map(|_| None).collect::<Vec<_>>();

        let map_fd = map.fd_or_err()?;
        let page_size = unsafe { sysconf(_SC_PAGESIZE) } as usize;

        let mut cpu_fds = Vec::new();
        for cpu_id in &cpu_ids {
            let buf = PerfBuffer::open(*cpu_id, page_size, page_count.unwrap_or(2))?;
            bpf_map_update_elem(map_fd, cpu_id, &buf.fd, 0)
                .map_err(|(_, io_error)| PerfMapError::UpdateElementFailed { io_error })?;
            cpu_fds.push((*cpu_id, buf.fd));
            buffers[*cpu_id as usize] = Some(buf);
        }

        Ok(PerfMap {
            map,
            cpu_fds,
            buffers,
        })
    }

    pub fn cpu_file_descriptors(&self) -> &[(u32, RawFd)] {
        self.cpu_fds.as_slice()
    }

    pub fn read_cpu_events(
        &mut self,
        cpu_id: u32,
        buffers: &mut [BytesMut],
    ) -> Result<Events, PerfMapError> {
        let buf = match self.buffers.get_mut(cpu_id as usize) {
            None | Some(None) => return Err(PerfMapError::InvalidCpu { cpu_id }),
            Some(Some(buf)) => buf,
        };

        Ok(buf.read_events(buffers)?)
    }
}

impl<'a> TryFrom<RefMut<'a, Map>> for PerfMap<RefMut<'a, Map>> {
    type Error = PerfMapError;

    fn try_from(a: RefMut<'a, Map>) -> Result<PerfMap<RefMut<'a, Map>>, PerfMapError> {
        PerfMap::new(a, None, None)
    }
}

impl<'a> TryFrom<&'a mut Map> for PerfMap<&'a mut Map> {
    type Error = PerfMapError;

    fn try_from(a: &'a mut Map) -> Result<PerfMap<&'a mut Map>, PerfMapError> {
        PerfMap::new(a, None, None)
    }
}

fn online_cpus() -> Result<Vec<u32>, ()> {
    let data = fs::read_to_string(ONLINE_CPUS).map_err(|_| ())?;
    parse_online_cpus(data.trim())
}

fn parse_online_cpus(data: &str) -> Result<Vec<u32>, ()> {
    let mut cpus = Vec::new();
    for range in data.split(',') {
        cpus.extend({
            match range
                .splitn(2, '-')
                .map(u32::from_str)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ())?
                .as_slice()
            {
                &[] | &[_, _, _, ..] => return Err(()),
                &[start] => start..=start,
                &[start, end] => start..=end,
            }
        })
    }

    Ok(cpus)
}

#[cfg_attr(test, allow(unused_variables))]
unsafe fn mmap(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: i32,
    offset: i64,
) -> *mut c_void {
    #[cfg(not(test))]
    return libc::mmap(addr, len, prot, flags, fd, offset);

    #[cfg(test)]
    use crate::syscalls::TEST_MMAP_RET;

    #[cfg(test)]
    TEST_MMAP_RET.with(|ret| *ret.borrow())
}

#[derive(Debug)]
#[repr(C)]
pub struct Sample {
    header: perf_event_header,
    pub size: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct LostSamples {
    header: perf_event_header,
    pub id: u64,
    pub count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        generated::perf_event_mmap_page,
        syscalls::{override_syscall, Syscall, TEST_MMAP_RET},
    };

    use std::{convert::TryInto, fmt::Debug, iter::FromIterator, mem};

    #[test]
    fn test_parse_online_cpus() {
        assert_eq!(parse_online_cpus("0").unwrap(), vec![0]);
        assert_eq!(parse_online_cpus("0,1").unwrap(), vec![0, 1]);
        assert_eq!(parse_online_cpus("0,1,2").unwrap(), vec![0, 1, 2]);
        assert_eq!(parse_online_cpus("0-7").unwrap(), Vec::from_iter(0..=7));
        assert_eq!(parse_online_cpus("0-3,4-7").unwrap(), Vec::from_iter(0..=7));
        assert_eq!(parse_online_cpus("0-5,6,7").unwrap(), Vec::from_iter(0..=7));
        assert!(parse_online_cpus("").is_err());
        assert!(parse_online_cpus("0-1,2-").is_err());
        assert!(parse_online_cpus("foo").is_err());
    }

    const PAGE_SIZE: usize = 4096;
    union MMappedBuf {
        mmap_page: perf_event_mmap_page,
        data: [u8; PAGE_SIZE * 2],
    }

    fn fake_mmap(buf: &mut MMappedBuf) {
        override_syscall(|call| match call {
            Syscall::PerfEventOpen { .. } | Syscall::PerfEventIoctl { .. } => Ok(42),
            _ => panic!(),
        });
        TEST_MMAP_RET.with(|ret| *ret.borrow_mut() = buf as *const _ as *mut _);
    }

    #[test]
    fn test_invalid_page_count() {
        assert!(matches!(
            PerfBuffer::open(1, PAGE_SIZE, 0),
            Err(PerfBufferError::InvalidPageCount { .. })
        ));
        assert!(matches!(
            PerfBuffer::open(1, PAGE_SIZE, 3),
            Err(PerfBufferError::InvalidPageCount { .. })
        ));
        assert!(matches!(
            PerfBuffer::open(1, PAGE_SIZE, 5),
            Err(PerfBufferError::InvalidPageCount { .. })
        ));
    }

    #[test]
    fn test_no_out_bufs() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        fake_mmap(&mut mmapped_buf);

        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();
        assert!(matches!(
            buf.read_events(&mut []),
            Err(PerfBufferError::NoBuffers)
        ))
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
    fn test_read_first_lost() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        fake_mmap(&mut mmapped_buf);

        let evt = LostSamples {
            header: perf_event_header {
                type_: PERF_RECORD_LOST,
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
                    type_: PERF_RECORD_SAMPLE,
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
    fn test_read_first_sample() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        write_sample(&mut mmapped_buf, 0, 0xCAFEBABEu32);

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
        fake_mmap(&mut mmapped_buf);
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
    fn test_read_many_with_one_read() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        fake_mmap(&mut mmapped_buf);
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
    fn test_read_last_sample() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        fake_mmap(&mut mmapped_buf);
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
    fn test_read_wrapping_sample_size() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let header = perf_event_header {
            type_: PERF_RECORD_SAMPLE,
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
    fn test_read_wrapping_value() {
        let mut mmapped_buf = MMappedBuf {
            data: [0; PAGE_SIZE * 2],
        };
        fake_mmap(&mut mmapped_buf);
        let mut buf = PerfBuffer::open(1, PAGE_SIZE, 1).unwrap();

        let sample = PerfSample {
            s_hdr: Sample {
                header: perf_event_header {
                    type_: PERF_RECORD_SAMPLE,
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
