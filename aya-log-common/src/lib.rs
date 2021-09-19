#![no_std]

pub const LOG_BUF_CAPACITY: usize = 1024;

pub const LOG_FIELDS: usize = 6;

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
    Log,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for RecordField {}
