#![no_std]

use core::{mem, num, ptr};

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

macro_rules! impl_formatter_for_types {
    ($trait:path : { $($type:ty),*}) => {
        $(
            impl $trait for $type {}
        )*
    };
}

pub trait DefaultFormatter {}
impl_formatter_for_types!(
    DefaultFormatter: {
        bool,
        i8, i16, i32, i64, isize,
        u8, u16, u32, u64, usize,
        f32, f64,
        char,
        str,
        &str
    }
);

pub trait LowerHexFormatter {}
impl_formatter_for_types!(
    LowerHexFormatter: {
        i8, i16, i32, i64, isize,
        u8, u16, u32, u64, usize,
        &[u8]
    }
);

pub trait UpperHexFormatter {}
impl_formatter_for_types!(
    UpperHexFormatter: {
        i8, i16, i32, i64, isize,
        u8, u16, u32, u64, usize,
        &[u8]
    }
);

pub trait IpFormatter {}
impl IpFormatter for u32 {}
impl IpFormatter for [u8; 16] {}
impl IpFormatter for [u16; 8] {}

pub trait LowerMacFormatter {}
impl LowerMacFormatter for [u8; 6] {}

pub trait UpperMacFormatter {}
impl UpperMacFormatter for [u8; 6] {}

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

    Bytes,
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
    /// `:i`
    Ip,
    /// `:mac`
    LowerMac,
    /// `:MAC`
    UpperMac,
}

struct TagLenValue<T, V> {
    pub tag: T,
    pub value: V,
}

impl<T, V> TagLenValue<T, V>
where
    V: IntoIterator<Item = u8>,
    <V as IntoIterator>::IntoIter: ExactSizeIterator,
{
    pub(crate) fn write(self, mut buf: &mut [u8]) -> Result<usize, ()> {
        // Break the abstraction to please the verifier.
        if buf.len() > LOG_BUF_CAPACITY {
            buf = &mut buf[..LOG_BUF_CAPACITY];
        }
        let Self { tag, value } = self;
        let value = value.into_iter();
        let len = value.len();
        let wire_len: LogValueLength = value
            .len()
            .try_into()
            .map_err(|num::TryFromIntError { .. }| ())?;
        let size = mem::size_of_val(&tag) + mem::size_of_val(&wire_len) + len;
        if size > buf.len() {
            return Err(());
        }

        let tag_size = mem::size_of_val(&tag);
        unsafe { ptr::write_unaligned(buf.as_mut_ptr() as *mut _, tag) };
        buf = &mut buf[tag_size..];

        unsafe { ptr::write_unaligned(buf.as_mut_ptr() as *mut _, wire_len) };
        buf = &mut buf[mem::size_of_val(&wire_len)..];

        buf.iter_mut().zip(value).for_each(|(dst, src)| {
            *dst = src;
        });

        Ok(size)
    }
}

impl<T, V> TagLenValue<T, V> {
    #[inline(always)]
    pub(crate) fn new(tag: T, value: V) -> TagLenValue<T, V> {
        TagLenValue { tag, value }
    }
}

pub trait WriteToBuf {
    #[allow(clippy::result_unit_err)]
    fn write(self, buf: &mut [u8]) -> Result<usize, ()>;
}

macro_rules! impl_write_to_buf {
    ($type:ident, $arg_type:expr) => {
        impl WriteToBuf for $type {
            fn write(self, buf: &mut [u8]) -> Result<usize, ()> {
                TagLenValue::new($arg_type, self.to_ne_bytes()).write(buf)
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
    fn write(self, buf: &mut [u8]) -> Result<usize, ()> {
        TagLenValue::new(Argument::ArrU8Len16, self).write(buf)
    }
}

impl WriteToBuf for [u16; 8] {
    fn write(self, buf: &mut [u8]) -> Result<usize, ()> {
        let bytes = unsafe { core::mem::transmute::<_, [u8; 16]>(self) };
        TagLenValue::new(Argument::ArrU16Len8, bytes).write(buf)
    }
}

impl WriteToBuf for [u8; 6] {
    fn write(self, buf: &mut [u8]) -> Result<usize, ()> {
        TagLenValue::new(Argument::ArrU8Len6, self).write(buf)
    }
}

impl WriteToBuf for &[u8] {
    fn write(self, buf: &mut [u8]) -> Result<usize, ()> {
        TagLenValue::new(Argument::Bytes, self.iter().copied()).write(buf)
    }
}

impl WriteToBuf for &str {
    fn write(self, buf: &mut [u8]) -> Result<usize, ()> {
        TagLenValue::new(Argument::Str, self.as_bytes().iter().copied()).write(buf)
    }
}

impl WriteToBuf for DisplayHint {
    fn write(self, buf: &mut [u8]) -> Result<usize, ()> {
        let v: u8 = self.into();
        TagLenValue::new(Argument::DisplayHint, v.to_ne_bytes()).write(buf)
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
    size += TagLenValue::new(RecordField::Target, target.as_bytes().iter().copied())
        .write(&mut buf[size..])?;
    size += TagLenValue::new(RecordField::Level, level.to_ne_bytes()).write(&mut buf[size..])?;
    size += TagLenValue::new(RecordField::Module, module.as_bytes().iter().copied())
        .write(&mut buf[size..])?;
    size += TagLenValue::new(RecordField::File, file.as_bytes().iter().copied())
        .write(&mut buf[size..])?;
    size += TagLenValue::new(RecordField::Line, line.to_ne_bytes()).write(&mut buf[size..])?;
    size +=
        TagLenValue::new(RecordField::NumArgs, num_args.to_ne_bytes()).write(&mut buf[size..])?;
    Ok(size)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn log_value_length_sufficient() {
        assert!(
            LOG_BUF_CAPACITY <= LogValueLength::MAX.into(),
            "{} > {}",
            LOG_BUF_CAPACITY,
            LogValueLength::MAX
        );
    }
}
