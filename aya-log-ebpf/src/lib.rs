#![no_std]

pub extern crate ufmt;

mod macros;

use core::{cmp, mem, ptr};

use aya_bpf::{
    macros::map,
    maps::{PerCpuArray, PerfEventByteArray},
};
pub use aya_log_common::Level;
use aya_log_common::RecordField;
pub use aya_log_common::LOG_BUF_CAPACITY;

#[doc(hidden)]
#[repr(C)]
pub struct LogBuf {
    pub buf: [u8; LOG_BUF_CAPACITY],
}

#[doc(hidden)]
#[map]
pub static mut AYA_LOG_BUF: PerCpuArray<LogBuf> = PerCpuArray::with_max_entries(1, 0);

#[doc(hidden)]
#[map]
pub static mut AYA_LOGS: PerfEventByteArray = PerfEventByteArray::new(0);

#[doc(hidden)]
pub struct LogBufWriter<'a> {
    pos: usize,
    data: &'a mut [u8],
}

impl<'a> LogBufWriter<'a> {
    pub fn new(data: &mut [u8]) -> LogBufWriter<'_> {
        LogBufWriter {
            pos: mem::size_of::<RecordField>() + mem::size_of::<usize>(),
            data,
        }
    }

    pub fn finish(self) -> usize {
        let mut buf = self.data;
        unsafe { ptr::write_unaligned(buf.as_mut_ptr() as *mut _, RecordField::Log) };
        buf = &mut buf[mem::size_of::<RecordField>()..];

        let len = self.pos - mem::size_of::<RecordField>() - mem::size_of::<usize>();
        unsafe { ptr::write_unaligned(buf.as_mut_ptr() as *mut _, len) };

        self.pos
    }
}

impl<'a> ufmt::uWrite for LogBufWriter<'a> {
    type Error = ();

    fn write_str(&mut self, s: &str) -> Result<(), Self::Error> {
        let bytes = s.as_bytes();
        let len = bytes.len();

        // this is to make sure the verifier knows about the upper bound
        if len > LOG_BUF_CAPACITY {
            return Err(());
        }

        let available = self.data.len() - self.pos;
        if available < len {
            return Err(());
        }

        self.data[self.pos..self.pos + len].copy_from_slice(&bytes[..len]);
        self.pos += len;
        Ok(())
    }
}

struct TagLenValue<'a> {
    tag: RecordField,
    value: &'a [u8],
}

impl<'a> TagLenValue<'a> {
    #[inline(always)]
    pub(crate) fn new(tag: RecordField, value: &'a [u8]) -> TagLenValue<'a> {
        TagLenValue { tag, value }
    }

    pub(crate) fn try_write(&self, mut buf: &mut [u8]) -> Result<usize, ()> {
        let size = mem::size_of::<RecordField>() + mem::size_of::<usize>() + self.value.len();
        if buf.len() < size {
            return Err(());
        }

        unsafe { ptr::write_unaligned(buf.as_mut_ptr() as *mut _, self.tag) };
        buf = &mut buf[mem::size_of::<RecordField>()..];

        unsafe { ptr::write_unaligned(buf.as_mut_ptr() as *mut _, self.value.len()) };
        buf = &mut buf[mem::size_of::<usize>()..];

        let len = cmp::min(buf.len(), self.value.len());
        buf[..len].copy_from_slice(&self.value[..len]);
        Ok(size)
    }
}

#[doc(hidden)]
pub fn write_record_header(
    buf: &mut [u8],
    target: &str,
    level: Level,
    module: &str,
    file: &str,
    line: u32,
) -> Result<usize, ()> {
    let mut size = 0;
    for attr in [
        TagLenValue::new(RecordField::Target, target.as_bytes()),
        TagLenValue::new(RecordField::Level, &(level as usize).to_ne_bytes()),
        TagLenValue::new(RecordField::Module, module.as_bytes()),
        TagLenValue::new(RecordField::File, file.as_bytes()),
        TagLenValue::new(RecordField::Line, &line.to_ne_bytes()),
    ] {
        size += attr.try_write(&mut buf[size..])?;
    }

    Ok(size)
}
