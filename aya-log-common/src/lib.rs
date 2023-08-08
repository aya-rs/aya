#![no_std]

use core::num;

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
#[derive(Copy, Clone, Debug, IntoPrimitive)]
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
#[derive(Copy, Clone, Debug, IntoPrimitive)]
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

#[inline(always)]
pub(crate) fn write(tag: u8, value: &[u8], buf: &mut [u8]) -> Result<usize, ()> {
    let wire_len: LogValueLength = value
        .len()
        .try_into()
        .map_err(|num::TryFromIntError { .. }| ())?;
    let values: &[&[u8]] = &[&[tag], &wire_len.to_ne_bytes(), value];
    let mut size = 0;
    for src in values {
        let buf = buf.get_mut(size..).ok_or(())?;
        let buf = buf.get_mut(..src.len()).ok_or(())?;
        buf.copy_from_slice(src);
        size += src.len();
    }
    Ok(size)
}

pub trait WriteToBuf {
    #[allow(clippy::result_unit_err)]
    fn write(self, buf: &mut [u8]) -> Result<usize, ()>;
}

macro_rules! impl_write_to_buf {
    ($type:ident, $arg_type:expr) => {
        impl WriteToBuf for $type {
            fn write(self, buf: &mut [u8]) -> Result<usize, ()> {
                write($arg_type.into(), &self.to_ne_bytes(), buf)
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
    #[inline(always)]
    fn write(self, buf: &mut [u8]) -> Result<usize, ()> {
        write(Argument::ArrU8Len16.into(), &self, buf)
    }
}

impl WriteToBuf for [u16; 8] {
    #[inline(always)]
    fn write(self, buf: &mut [u8]) -> Result<usize, ()> {
        let bytes = unsafe { core::mem::transmute::<_, [u8; 16]>(self) };
        write(Argument::ArrU16Len8.into(), &bytes, buf)
    }
}

impl WriteToBuf for [u8; 6] {
    #[inline(always)]
    fn write(self, buf: &mut [u8]) -> Result<usize, ()> {
        write(Argument::ArrU8Len6.into(), &self, buf)
    }
}

impl WriteToBuf for &[u8] {
    #[inline(always)]
    fn write(self, buf: &mut [u8]) -> Result<usize, ()> {
        write(Argument::Bytes.into(), self, buf)
    }
}

impl WriteToBuf for &str {
    #[inline(always)]
    fn write(self, buf: &mut [u8]) -> Result<usize, ()> {
        write(Argument::Str.into(), self.as_bytes(), buf)
    }
}

impl WriteToBuf for DisplayHint {
    #[inline(always)]
    fn write(self, buf: &mut [u8]) -> Result<usize, ()> {
        let v: u8 = self.into();
        write(Argument::DisplayHint.into(), &v.to_ne_bytes(), buf)
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
    for (tag, value) in [
        (RecordField::Target.into(), target.as_bytes()),
        (RecordField::Level.into(), &level.to_ne_bytes()),
        (RecordField::Module.into(), module.as_bytes()),
        (RecordField::File.into(), file.as_bytes()),
        (RecordField::Line.into(), &line.to_ne_bytes()),
        (RecordField::NumArgs.into(), &num_args.to_ne_bytes()),
    ] {
        let buf = buf.get_mut(size..).ok_or(())?;
        size += write(tag, value, buf)?;
    }
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
