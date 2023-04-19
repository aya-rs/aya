#![no_std]

use core::{mem, num, ptr, slice};

use num_enum::IntoPrimitive;

pub const LOG_BUF_CAPACITY: usize = 8192;

pub const LOG_FIELDS: usize = 6;

pub type LogValueLength = u16;

#[repr(u8)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, IntoPrimitive)]
pub enum Level {
    /// The "error" level.
    ///
    /// Designates very serious errors.
    Error = 1,
    /// The "warn" level.
    ///
    /// Designates hazardous situations.
    Warn,
    /// The "info" level.
    ///
    /// Designates useful information.
    Info,
    /// The "debug" level.
    ///
    /// Designates lower priority information.
    Debug,
    /// The "trace" level.
    ///
    /// Designates very low priority, often extremely verbose, information.
    Trace,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum RecordField {
    Target = 1,
    Level,
    Module,
    File,
    Line,
    NumArgs,
}

/// Types which are supported by aya-log and can be safely sent from eBPF
/// programs to userspace.
#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum Argument {
    DisplayHint,

    I8,
    I16,
    I32,
    I64,
    Isize,

    U8,
    U16,
    U32,
    U64,
    Usize,

    F32,
    F64,

    /// `[u8; 6]` array which represents a MAC address.
    ArrU8Len6,
    /// `[u8; 16]` array which represents an IPv6 address.
    ArrU8Len16,
    /// `[u16; 8]` array which represents an IPv6 address.
    ArrU16Len8,

    Str,
}

/// All display hints
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, IntoPrimitive)]
pub enum DisplayHint {
    /// Default string representation.
    Default = 1,
    /// `:x`
    LowerHex,
    /// `:X`
    UpperHex,
    /// `:ipv4`
    Ipv4,
    /// `:ipv6`
    Ipv6,
    /// `:mac`
    LowerMac,
    /// `:MAC`
    UpperMac,
}

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
        // Break the abstraction to please the verifier.
        if buf.len() > LOG_BUF_CAPACITY {
            buf = &mut buf[..LOG_BUF_CAPACITY];
        }
        let Self { tag, value } = self;
        let len = value.len();
        let wire_len: LogValueLength = value
            .len()
            .try_into()
            .map_err(|num::TryFromIntError { .. }| ())?;
        let size = mem::size_of_val(tag) + mem::size_of_val(&wire_len) + len;
        if size > buf.len() {
            return Err(());
        }

        unsafe { ptr::write_unaligned(buf.as_mut_ptr() as *mut _, *tag) };
        buf = &mut buf[mem::size_of_val(tag)..];

        unsafe { ptr::write_unaligned(buf.as_mut_ptr() as *mut _, wire_len) };
        buf = &mut buf[mem::size_of_val(&wire_len)..];

        unsafe { ptr::copy_nonoverlapping(value.as_ptr(), buf.as_mut_ptr(), len) };

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
                TagLenValue::<Argument>::new($arg_type, &self.to_ne_bytes()).write(buf)
            }
        }
    };
}

impl_write_to_buf!(i8, Argument::I8);
impl_write_to_buf!(i16, Argument::I16);
impl_write_to_buf!(i32, Argument::I32);
impl_write_to_buf!(i64, Argument::I64);
impl_write_to_buf!(isize, Argument::Isize);

impl_write_to_buf!(u8, Argument::U8);
impl_write_to_buf!(u16, Argument::U16);
impl_write_to_buf!(u32, Argument::U32);
impl_write_to_buf!(u64, Argument::U64);
impl_write_to_buf!(usize, Argument::Usize);

impl_write_to_buf!(f32, Argument::F32);
impl_write_to_buf!(f64, Argument::F64);

impl WriteToBuf for [u8; 16] {
    fn write(&self, buf: &mut [u8]) -> Result<usize, ()> {
        TagLenValue::<Argument>::new(Argument::ArrU8Len16, self).write(buf)
    }
}

impl WriteToBuf for [u16; 8] {
    fn write(&self, buf: &mut [u8]) -> Result<usize, ()> {
        let ptr = self.as_ptr().cast::<u8>();
        let bytes = unsafe { slice::from_raw_parts(ptr, 16) };
        TagLenValue::<Argument>::new(Argument::ArrU16Len8, bytes).write(buf)
    }
}

impl WriteToBuf for [u8; 6] {
    fn write(&self, buf: &mut [u8]) -> Result<usize, ()> {
        TagLenValue::<Argument>::new(Argument::ArrU8Len6, self).write(buf)
    }
}

impl WriteToBuf for str {
    fn write(&self, buf: &mut [u8]) -> Result<usize, ()> {
        TagLenValue::<Argument>::new(Argument::Str, self.as_bytes()).write(buf)
    }
}

impl WriteToBuf for DisplayHint {
    fn write(&self, buf: &mut [u8]) -> Result<usize, ()> {
        let v: u8 = (*self).into();
        TagLenValue::<Argument>::new(Argument::DisplayHint, &v.to_ne_bytes()).write(buf)
    }
}

#[allow(clippy::result_unit_err)]
#[doc(hidden)]
#[inline(always)]
pub fn write_record_header(
    buf: &mut [u8],
    target: &str,
    level: Level,
    module: &str,
    file: &str,
    line: u32,
    num_args: usize,
) -> Result<usize, ()> {
    let level: u8 = level.into();
    let mut size = 0;
    for attr in [
        TagLenValue::<RecordField>::new(RecordField::Target, target.as_bytes()),
        TagLenValue::<RecordField>::new(RecordField::Level, &level.to_ne_bytes()),
        TagLenValue::<RecordField>::new(RecordField::Module, module.as_bytes()),
        TagLenValue::<RecordField>::new(RecordField::File, file.as_bytes()),
        TagLenValue::<RecordField>::new(RecordField::Line, &line.to_ne_bytes()),
        TagLenValue::<RecordField>::new(RecordField::NumArgs, &num_args.to_ne_bytes()),
    ] {
        size += attr.write(&mut buf[size..])?;
    }

    Ok(size)
}

#[cfg(test)]
mod test {
    use super::*;

    fn log_value_length_sufficient() {
        assert!(
            LOG_BUF_CAPACITY >= LogValueLength::MAX.into(),
            "{} < {}",
            LOG_BUF_CAPACITY,
            LogValueLength::MAX
        );
    }
}
