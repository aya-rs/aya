#![no_std]

use core::{cmp, mem, ptr};

use aya_bpf::{
    macros::map,
    maps::{PerCpuArray, PerfEventByteArray},
};
use aya_log_common::{ArgType, RecordField};
pub use aya_log_common::{Level, LOG_BUF_CAPACITY};
pub use aya_log_ebpf_macros::{debug, error, info, log, trace, warn};

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

struct TagLenValue<'a, T> {
    tag: T,
    value: &'a [u8],
}

impl<'a, T> TagLenValue<'a, T>
where
    T: Copy,
{
    #[inline(always)]
    pub(crate) fn new(tag: T, value: &'a [u8]) -> TagLenValue<'a, T> {
        TagLenValue { tag, value }
    }

    pub(crate) fn write(&self, mut buf: &mut [u8]) -> Result<usize, ()> {
        let size = mem::size_of::<T>() + mem::size_of::<usize>() + self.value.len();
        if buf.len() < size {
            return Err(());
        }

        unsafe { ptr::write_unaligned(buf.as_mut_ptr() as *mut _, self.tag) };
        buf = &mut buf[mem::size_of::<T>()..];

        unsafe { ptr::write_unaligned(buf.as_mut_ptr() as *mut _, self.value.len()) };
        buf = &mut buf[mem::size_of::<usize>()..];

        let len = cmp::min(buf.len(), self.value.len());
        buf[..len].copy_from_slice(&self.value[..len]);
        Ok(size)
    }
}

pub trait WriteToBuf {
    #[allow(clippy::result_unit_err)]
    fn write(&self, buf: &mut [u8]) -> Result<usize, ()>;
}

macro_rules! impl_write_to_buf {
    ($type:ident, $arg_type:expr) => {
        impl WriteToBuf for $type {
            fn write(&self, buf: &mut [u8]) -> Result<usize, ()> {
                TagLenValue::<ArgType>::new($arg_type, &self.to_ne_bytes()).write(buf)
            }
        }
    };
}

impl_write_to_buf!(i8, ArgType::I8);
impl_write_to_buf!(i16, ArgType::I16);
impl_write_to_buf!(i32, ArgType::I32);
impl_write_to_buf!(i64, ArgType::I64);
impl_write_to_buf!(i128, ArgType::I128);
impl_write_to_buf!(isize, ArgType::Isize);

impl_write_to_buf!(u8, ArgType::U8);
impl_write_to_buf!(u16, ArgType::U16);
impl_write_to_buf!(u32, ArgType::U32);
impl_write_to_buf!(u64, ArgType::U64);
impl_write_to_buf!(u128, ArgType::U128);
impl_write_to_buf!(usize, ArgType::Usize);

impl_write_to_buf!(f32, ArgType::F32);
impl_write_to_buf!(f64, ArgType::F64);

impl WriteToBuf for str {
    fn write(&self, buf: &mut [u8]) -> Result<usize, ()> {
        TagLenValue::<ArgType>::new(ArgType::Str, self.as_bytes()).write(buf)
    }
}

#[allow(clippy::result_unit_err)]
#[doc(hidden)]
pub fn write_record_header(
    buf: &mut [u8],
    target: &str,
    level: Level,
    module: &str,
    file: &str,
    line: u32,
    num_args: usize,
) -> Result<usize, ()> {
    let mut size = 0;
    for attr in [
        TagLenValue::<RecordField>::new(RecordField::Target, target.as_bytes()),
        TagLenValue::<RecordField>::new(RecordField::Level, &(level as usize).to_ne_bytes()),
        TagLenValue::<RecordField>::new(RecordField::Module, module.as_bytes()),
        TagLenValue::<RecordField>::new(RecordField::File, file.as_bytes()),
        TagLenValue::<RecordField>::new(RecordField::Line, &line.to_ne_bytes()),
        TagLenValue::<RecordField>::new(RecordField::NumArgs, &num_args.to_ne_bytes()),
    ] {
        size += attr.write(&mut buf[size..])?;
    }

    Ok(size)
}

#[allow(clippy::result_unit_err)]
#[doc(hidden)]
pub fn write_record_message(buf: &mut [u8], msg: &str) -> Result<usize, ()> {
    TagLenValue::<RecordField>::new(RecordField::Log, msg.as_bytes()).write(buf)
}

#[doc(hidden)]
pub mod macro_support {
    pub use aya_log_common::{Level, LOG_BUF_CAPACITY};
    pub use aya_log_ebpf_macros::log;
}
