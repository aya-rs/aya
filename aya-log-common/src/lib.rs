#![no_std]

pub const LOG_BUF_CAPACITY: usize = 1024;

pub const LOG_FIELDS: usize = 7;

#[repr(usize)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
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

#[repr(usize)]
#[derive(Copy, Clone, Debug)]
pub enum RecordField {
    Target = 1,
    Level,
    Module,
    File,
    Line,
    NumArgs,
    Log,
}

#[repr(usize)]
#[derive(Copy, Clone, Debug)]
pub enum ArgType {
    I8,
    I16,
    I32,
    I64,
    I128,
    Isize,

    U8,
    U16,
    U32,
    U64,
    U128,
    Usize,

    F32,
    F64,

    Str,
}

#[cfg(feature = "userspace")]
mod userspace {
    use super::*;

    unsafe impl aya::Pod for RecordField {}
    unsafe impl aya::Pod for ArgType {}
}
