use bytes::BytesMut;
use std::{
    convert::TryFrom,
    ops::DerefMut,
    os::unix::prelude::{AsRawFd, RawFd},
};

#[cfg(feature = "async_std")]
use async_io::Async;

#[cfg(feature = "async_tokio")]
use tokio::io::unix::AsyncFd;

use crate::maps::{
    perf::{Events, PerfBufferError, PerfEventArray, PerfEventArrayBuffer},
    Map, MapError, MapRefMut,
};

pub struct AsyncPerfEventArray<T: DerefMut<Target = Map>> {
    perf_map: PerfEventArray<T>,
}

impl<T: DerefMut<Target = Map>> AsyncPerfEventArray<T> {
    pub fn open(
        &mut self,
        index: u32,
        page_count: Option<usize>,
    ) -> Result<AsyncPerfEventArrayBuffer<T>, PerfBufferError> {
        let buf = self.perf_map.open(index, page_count)?;
        let fd = buf.as_raw_fd();
        Ok(AsyncPerfEventArrayBuffer {
            buf,

            #[cfg(feature = "async_tokio")]
            async_fd: AsyncFd::new(fd)?,

            #[cfg(feature = "async_std")]
            async_fd: Async::new(fd)?,
        })
    }
}

impl<T: DerefMut<Target = Map>> AsyncPerfEventArray<T> {
    fn new(map: T) -> Result<AsyncPerfEventArray<T>, MapError> {
        Ok(AsyncPerfEventArray {
            perf_map: PerfEventArray::new(map)?,
        })
    }
}

pub struct AsyncPerfEventArrayBuffer<T: DerefMut<Target = Map>> {
    buf: PerfEventArrayBuffer<T>,

    #[cfg(feature = "async_tokio")]
    async_fd: AsyncFd<RawFd>,

    #[cfg(feature = "async_std")]
    async_fd: Async<RawFd>,
}

#[cfg(feature = "async_tokio")]
impl<T: DerefMut<Target = Map>> AsyncPerfEventArrayBuffer<T> {
    pub async fn read_events(
        &mut self,
        buffers: &mut [BytesMut],
    ) -> Result<Events, PerfBufferError> {
        loop {
            let mut guard = self.async_fd.readable_mut().await?;

            match self.buf.read_events(buffers) {
                Ok(events) if events.read > 0 || events.lost > 0 => return Ok(events),
                Ok(_) => {
                    guard.clear_ready();
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(feature = "async_std")]
impl<T: DerefMut<Target = Map>> AsyncPerfEventArrayBuffer<T> {
    pub async fn read_events(
        &mut self,
        buffers: &mut [BytesMut],
    ) -> Result<Events, PerfBufferError> {
        loop {
            if !self.buf.readable() {
                let _ = self.async_fd.readable().await?;
            }

            match self.buf.read_events(buffers) {
                Ok(events) if events.read > 0 || events.lost > 0 => return Ok(events),
                Ok(_) => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

impl TryFrom<MapRefMut> for AsyncPerfEventArray<MapRefMut> {
    type Error = MapError;

    fn try_from(a: MapRefMut) -> Result<AsyncPerfEventArray<MapRefMut>, MapError> {
        AsyncPerfEventArray::new(a)
    }
}
