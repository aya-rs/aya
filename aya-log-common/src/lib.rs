#![no_std]

use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::TryFromIntError,
};

use num_enum::IntoPrimitive;

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
pub enum RecordFieldKind {
    Target,
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
pub enum ArgumentKind {
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

pub trait Argument {
    fn as_argument(&self) -> (ArgumentKind, impl AsRef<[u8]>);
}

macro_rules! impl_argument {
    ($self:ident, $arg_type:expr) => {
        impl Argument for $self {
            fn as_argument(&self) -> (ArgumentKind, impl AsRef<[u8]>) {
                ($arg_type, self.to_ne_bytes())
            }
        }
    };
}

impl_argument!(i8, ArgumentKind::I8);
impl_argument!(i16, ArgumentKind::I16);
impl_argument!(i32, ArgumentKind::I32);
impl_argument!(i64, ArgumentKind::I64);
impl_argument!(isize, ArgumentKind::Isize);

impl_argument!(u8, ArgumentKind::U8);
impl_argument!(u16, ArgumentKind::U16);
impl_argument!(u32, ArgumentKind::U32);
impl_argument!(u64, ArgumentKind::U64);
impl_argument!(usize, ArgumentKind::Usize);

impl_argument!(f32, ArgumentKind::F32);
impl_argument!(f64, ArgumentKind::F64);

enum Either<L, R> {
    Left(L),
    Right(R),
}

impl<L, R> AsRef<[u8]> for Either<L, R>
where
    L: AsRef<[u8]>,
    R: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        match self {
            Either::Left(l) => l.as_ref(),
            Either::Right(r) => r.as_ref(),
        }
    }
}

impl Argument for IpAddr {
    fn as_argument(&self) -> (ArgumentKind, impl AsRef<[u8]>) {
        match self {
            IpAddr::V4(ipv4_addr) => {
                let (kind, value) = ipv4_addr.as_argument();
                (kind, Either::Left(value))
            }
            IpAddr::V6(ipv6_addr) => {
                let (kind, value) = ipv6_addr.as_argument();
                (kind, Either::Right(value))
            }
        }
    }
}

impl Argument for Ipv4Addr {
    fn as_argument(&self) -> (ArgumentKind, impl AsRef<[u8]>) {
        (ArgumentKind::Ipv4Addr, self.octets())
    }
}

impl Argument for [u8; 4] {
    fn as_argument(&self) -> (ArgumentKind, impl AsRef<[u8]>) {
        (ArgumentKind::ArrU8Len4, self)
    }
}

impl Argument for Ipv6Addr {
    fn as_argument(&self) -> (ArgumentKind, impl AsRef<[u8]>) {
        (ArgumentKind::Ipv6Addr, self.octets())
    }
}

impl Argument for [u8; 16] {
    fn as_argument(&self) -> (ArgumentKind, impl AsRef<[u8]>) {
        (ArgumentKind::ArrU8Len16, self)
    }
}

impl Argument for [u16; 8] {
    fn as_argument(&self) -> (ArgumentKind, impl AsRef<[u8]>) {
        let bytes = unsafe { core::mem::transmute::<&[u16; 8], &[u8; 16]>(self) };
        (ArgumentKind::ArrU16Len8, bytes)
    }
}

impl Argument for [u8; 6] {
    fn as_argument(&self) -> (ArgumentKind, impl AsRef<[u8]>) {
        (ArgumentKind::ArrU8Len6, self)
    }
}

impl Argument for &[u8] {
    fn as_argument(&self) -> (ArgumentKind, impl AsRef<[u8]>) {
        (ArgumentKind::Bytes, self)
    }
}

impl Argument for &str {
    fn as_argument(&self) -> (ArgumentKind, impl AsRef<[u8]>) {
        (ArgumentKind::Str, self.as_bytes())
    }
}

impl Argument for DisplayHint {
    fn as_argument(&self) -> (ArgumentKind, impl AsRef<[u8]>) {
        let v: u8 = (*self).into();
        (ArgumentKind::DisplayHint, v.to_ne_bytes())
    }
}

fn wire_len(value: &[u8]) -> Option<[u8; 2]> {
    match LogValueLength::try_from(value.len()) {
        Ok(wire_len) => Some(wire_len.to_ne_bytes()),
        Err(TryFromIntError { .. }) => None,
    }
}

#[doc(hidden)]
pub struct Field<T>([u8; 1], [u8; 2], T);

impl<T: AsRef<[u8]>> Field<T> {
    pub fn new(kind: impl Into<u8>, value: T) -> Option<Self> {
        let wire_len = wire_len(value.as_ref())?;
        Some(Self([kind.into()], wire_len, value))
    }

    pub fn with_bytes(&self, op: &mut impl FnMut(&[u8]) -> Option<()>) -> Option<()> {
        let Self(kind, wire_len, value) = self;
        op(&kind[..])?;
        op(&wire_len[..])?;
        op(value.as_ref())?;
        Some(())
    }
}

#[doc(hidden)]
pub struct Header<'a> {
    target: Field<&'a [u8]>,
    level: Field<[u8; 1]>,
    module: Field<&'a [u8]>,
    file: Field<&'a [u8]>,
    line: Field<[u8; 4]>,
    num_args: Field<[u8; 4]>,
}

impl<'a> Header<'a> {
    pub fn new(
        target: &'a str,
        level: Level,
        module: &'a str,
        file: &'a str,
        line: u32,
        num_args: u32,
    ) -> Option<Self> {
        let target = target.as_bytes();
        let level: u8 = level.into();
        let level = level.to_ne_bytes();
        let module = module.as_bytes();
        let file = file.as_bytes();
        let line = line.to_ne_bytes();
        let num_args = num_args.to_ne_bytes();
        let target = Field::new(RecordFieldKind::Target, target)?;
        let level = Field::new(RecordFieldKind::Level, level)?;
        let module = Field::new(RecordFieldKind::Module, module)?;
        let file = Field::new(RecordFieldKind::File, file)?;
        let line = Field::new(RecordFieldKind::Line, line)?;
        let num_args = Field::new(RecordFieldKind::NumArgs, num_args)?;

        Some(Self {
            target,
            level,
            module,
            file,
            line,
            num_args,
        })
    }

    pub fn with_bytes(&self, op: &mut impl FnMut(&[u8]) -> Option<()>) -> Option<()> {
        let Self {
            target,
            level,
            module,
            file,
            line,
            num_args,
        } = self;
        target.with_bytes(op)?;
        level.with_bytes(op)?;
        module.with_bytes(op)?;
        file.with_bytes(op)?;
        line.with_bytes(op)?;
        num_args.with_bytes(op)?;
        Some(())
    }
}
