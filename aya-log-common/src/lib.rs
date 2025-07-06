#![no_std]

use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::{NonZeroUsize, TryFromIntError},
};

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
        &str,
        IpAddr, Ipv4Addr, Ipv6Addr
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
impl IpFormatter for IpAddr {}
impl IpFormatter for Ipv4Addr {}
impl IpFormatter for Ipv6Addr {}
impl IpFormatter for u32 {}
impl IpFormatter for [u8; 4] {}
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

    Ipv4Addr,
    Ipv6Addr,

    /// `[u8; 4]` array which represents an IPv4 address.
    ArrU8Len4,
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

// Must be inlined, else the BPF backend emits:
//
// llvm: <unknown>:0:0: in function _ZN14aya_log_common5write17hc9ed05433e23a663E { i64, i64 } (i8, ptr, i64, ptr, i64): only integer returns supported
#[inline(always)]
pub(crate) fn write(tag: u8, value: &[u8], buf: &mut [u8]) -> Option<NonZeroUsize> {
    // TODO(https://github.com/rust-lang/rust-clippy/issues/14112): Remove this allowance when the
    // lint behaves more sensibly.
    #[expect(clippy::manual_ok_err)]
    let wire_len: LogValueLength = match value.len().try_into() {
        Ok(wire_len) => Some(wire_len),
        Err(TryFromIntError { .. }) => None,
    }?;
    let mut size = 0;
    for slice in [&[tag][..], &wire_len.to_ne_bytes()[..], value] {
        let buf = buf.get_mut(size..)?;
        let buf = buf.get_mut(..slice.len())?;
        buf.copy_from_slice(slice);
        size += slice.len();
    }
    NonZeroUsize::new(size)
}

pub trait WriteToBuf {
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize>;
}

macro_rules! impl_write_to_buf {
    ($type:ident, $arg_type:expr) => {
        impl WriteToBuf for $type {
            // This need not be inlined because the return value is Option<N> where N is
            // mem::size_of<$type>, which is a compile-time constant.
            #[inline(never)]
            fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
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

impl WriteToBuf for IpAddr {
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        match self {
            IpAddr::V4(ipv4_addr) => write(Argument::Ipv4Addr.into(), &ipv4_addr.octets(), buf),
            IpAddr::V6(ipv6_addr) => write(Argument::Ipv6Addr.into(), &ipv6_addr.octets(), buf),
        }
    }
}

impl WriteToBuf for Ipv4Addr {
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        write(Argument::Ipv4Addr.into(), &self.octets(), buf)
    }
}

impl WriteToBuf for [u8; 4] {
    // This need not be inlined because the return value is Option<N> where N is 16, which is a
    // compile-time constant.
    #[inline(never)]
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        write(Argument::ArrU8Len4.into(), &self, buf)
    }
}

impl WriteToBuf for Ipv6Addr {
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        write(Argument::Ipv6Addr.into(), &self.octets(), buf)
    }
}

impl WriteToBuf for [u8; 16] {
    // This need not be inlined because the return value is Option<N> where N is 16, which is a
    // compile-time constant.
    #[inline(never)]
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        write(Argument::ArrU8Len16.into(), &self, buf)
    }
}

impl WriteToBuf for [u16; 8] {
    // This need not be inlined because the return value is Option<N> where N is 16, which is a
    // compile-time constant.
    #[inline(never)]
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        let bytes = unsafe { core::mem::transmute::<[u16; 8], [u8; 16]>(self) };
        write(Argument::ArrU16Len8.into(), &bytes, buf)
    }
}

impl WriteToBuf for [u8; 6] {
    // This need not be inlined because the return value is Option<N> where N is 6, which is a
    // compile-time constant.
    #[inline(never)]
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        write(Argument::ArrU8Len6.into(), &self, buf)
    }
}

impl WriteToBuf for &[u8] {
    // Must be inlined, else the BPF backend emits:
    //
    // llvm: <unknown>:0:0: in function _ZN63_$LT$$RF$$u5b$u8$u5d$$u20$as$u20$aya_log_common..WriteToBuf$GT$5write17h08f30a45f7b9f09dE { i64, i64 } (ptr, i64, ptr, i64): only integer returns supported
    #[inline(always)]
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        write(Argument::Bytes.into(), self, buf)
    }
}

impl WriteToBuf for &str {
    // Must be inlined, else the BPF backend emits:
    //
    // llvm: <unknown>:0:0: in function _ZN54_$LT$$RF$str$u20$as$u20$aya_log_common..WriteToBuf$GT$5write17h7e2d1ccaa758e2b5E { i64, i64 } (ptr, i64, ptr, i64): only integer returns supported
    #[inline(always)]
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        write(Argument::Str.into(), self.as_bytes(), buf)
    }
}

impl WriteToBuf for DisplayHint {
    // This need not be inlined because the return value is Option<N> where N is 1, which is a
    // compile-time constant.
    #[inline(never)]
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        let v: u8 = self.into();
        write(Argument::DisplayHint.into(), &v.to_ne_bytes(), buf)
    }
}

#[doc(hidden)]
#[inline(always)] // This function takes too many arguments to not be inlined.
pub fn write_record_header(
    buf: &mut [u8],
    target: &str,
    level: Level,
    module: &str,
    file: &str,
    line: u32,
    num_args: usize,
) -> Option<NonZeroUsize> {
    let level: u8 = level.into();
    let mut size = 0;
    for (tag, value) in [
        (RecordField::Target, target.as_bytes()),
        (RecordField::Level, &level.to_ne_bytes()),
        (RecordField::Module, module.as_bytes()),
        (RecordField::File, file.as_bytes()),
        (RecordField::Line, &line.to_ne_bytes()),
        (RecordField::NumArgs, &num_args.to_ne_bytes()),
    ] {
        let buf = buf.get_mut(size..)?;
        let len = write(tag.into(), value, buf)?;
        size += len.get();
    }
    NonZeroUsize::new(size)
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
