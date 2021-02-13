use std::{convert::TryFrom, io, ops::DerefMut, os::unix::prelude::AsRawFd, sync::Arc};

use bytes::BytesMut;
use libc::{sysconf, _SC_PAGESIZE};
use thiserror::Error;

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    maps::perf_map::{Events, PerfBuffer, PerfBufferError},
    maps::{Map, MapError, MapRefMut},
    sys::bpf_map_update_elem,
    RawFd,
};

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

    #[error(transparent)]
    IOError(#[from] io::Error),

    #[error("bpf_map_update_elem failed: {io_error}")]
    UpdateElementError {
        #[source]
        io_error: io::Error,
    },
}

pub struct PerfMapBuffer<T: DerefMut<Target = Map>> {
    _map: Arc<T>,
    buf: PerfBuffer,
}

impl<T: DerefMut<Target = Map>> PerfMapBuffer<T> {
    pub fn readable(&self) -> bool {
        self.buf.readable()
    }

    pub fn read_events(&mut self, buffers: &mut [BytesMut]) -> Result<Events, PerfBufferError> {
        self.buf.read_events(buffers)
    }
}

impl<T: DerefMut<Target = Map>> AsRawFd for PerfMapBuffer<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.buf.as_raw_fd()
    }
}

pub struct PerfMap<T: DerefMut<Target = Map>> {
    map: Arc<T>,
    page_size: usize,
}

impl<T: DerefMut<Target = Map>> PerfMap<T> {
    pub fn new(map: T) -> Result<PerfMap<T>, PerfMapError> {
        let map_type = map.obj.def.map_type;
        if map_type != BPF_MAP_TYPE_PERF_EVENT_ARRAY {
            return Err(MapError::InvalidMapType {
                map_type: map_type as u32,
            })?;
        }

        Ok(PerfMap {
            map: Arc::new(map),
            // Safety: libc
            page_size: unsafe { sysconf(_SC_PAGESIZE) } as usize,
        })
    }

    pub fn open(
        &mut self,
        index: u32,
        page_count: Option<usize>,
    ) -> Result<PerfMapBuffer<T>, PerfMapError> {
        // FIXME: keep track of open buffers

        let map_fd = self.map.fd_or_err()?;
        let buf = PerfBuffer::open(index, self.page_size, page_count.unwrap_or(2))?;
        bpf_map_update_elem(map_fd, &index, &buf.as_raw_fd(), 0)
            .map_err(|(_, io_error)| PerfMapError::UpdateElementError { io_error })?;

        Ok(PerfMapBuffer {
            buf,
            _map: self.map.clone(),
        })
    }
}

impl TryFrom<MapRefMut> for PerfMap<MapRefMut> {
    type Error = PerfMapError;

    fn try_from(a: MapRefMut) -> Result<PerfMap<MapRefMut>, PerfMapError> {
        PerfMap::new(a)
    }
}
