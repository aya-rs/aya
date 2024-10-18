//! Aya Error types.

use std::{error::Error, ffi::NulError, io, path::PathBuf};

use aya_obj::{
    btf::{BtfError, BtfRelocationError},
    relocation::EbpfRelocationError,
    InvalidTypeBinding, ParseError, VerifierLog,
};
use thiserror::Error;

/// The error type returned by [`Ebpf::load_file`] and [`Ebpf::load`].
#[derive(Debug, Error)]
#[cfg_attr(not(test), non_exhaustive)]
pub enum EbpfError {
    /// Error loading file.
    #[error("error loading {path}")]
    FileError {
        /// The file path.
        path: PathBuf,
        #[source]
        /// The original [`io::Error`].
        error: io::Error,
    },

    #[error("map error: {0}")]
    /// A map error.
    MapError(#[from] MapError),

    #[error("program error: {0}")]
    /// A program error.
    ProgramError(#[from] ProgramError),

    /// An irrecoverable error occurred.
    #[error(transparent)]
    Other(#[from] Box<dyn Error>),
}

#[derive(Debug, Error)]
pub(crate) enum EbpfInternalError {
    #[error("error parsing BPF object: {0}")]
    ParseError(#[from] ParseError),

    #[error("BTF error: {0}")]
    BtfError(#[from] BtfError),

    #[error("error relocating function")]
    RelocationError(#[from] EbpfRelocationError),

    #[error("error relocating section")]
    BtfRelocationError(#[from] BtfRelocationError),

    #[error("no BTF parsed for object")]
    NoBTF,
}

/// Error type returned when working with programs.
#[derive(Debug, Error)]
pub enum ProgramError {
    /// The program is already loaded.
    #[error("the program is already loaded")]
    AlreadyLoaded,

    /// The program is not loaded.
    #[error("the program is not loaded")]
    NotLoaded,

    /// Loading the program failed.
    #[error("the BPF_PROG_LOAD syscall failed. Verifier output: {verifier_log}")]
    LoadError {
        /// The [`SysError`] returned by the `BPF_PROG_LOAD` syscall.
        #[source]
        source: SysError,
        /// The error log produced by the kernel verifier.
        verifier_log: VerifierLog,
    },

    /// The program is not of the expected type.
    #[error("unexpected program type")]
    UnexpectedProgramType,

    /// A syscall failed.
    #[error("syscall failed")]
    Syscall(#[from] SysError),

    /// An irrecoverable error occurred.
    #[error(transparent)]
    Other(#[from] Box<dyn Error>),
}

impl From<EbpfInternalError> for ProgramError {
    fn from(e: EbpfInternalError) -> Self {
        Self::Other(Box::new(e))
    }
}

impl From<(i64, SysError)> for ProgramError {
    fn from((_, error): (i64, SysError)) -> Self {
        error.into()
    }
}

impl From<io::Error> for ProgramError {
    fn from(e: io::Error) -> Self {
        Self::Other(Box::new(e))
    }
}

impl From<BtfError> for ProgramError {
    fn from(e: BtfError) -> Self {
        Self::Other(Box::new(e))
    }
}

impl From<LinkError> for ProgramError {
    fn from(e: LinkError) -> Self {
        Self::Other(Box::new(e))
    }
}

impl From<NulError> for ProgramError {
    fn from(e: NulError) -> Self {
        Self::Other(Box::new(e))
    }
}

/// An error ocurred working with a pinned BPF object.
#[derive(Error, Debug)]
pub(crate) enum PinError {
    /// The path for the BPF object is not valid.
    #[error("invalid pin path `{}`", path.display())]
    InvalidPinPath {
        /// The path.
        path: std::path::PathBuf,

        #[source]
        /// The source error.
        error: std::ffi::NulError,
    },
    /// An irrecoverable error occurred.
    #[error(transparent)]
    Other(#[from] Box<dyn Error>),
}

impl From<InternalMapError> for MapError {
    fn from(e: InternalMapError) -> Self {
        Self::Other(Box::new(e))
    }
}

/// Errors from operations on maps.
#[derive(Error, Debug)]
pub enum MapError {
    /// Key not found
    #[error("key not found")]
    KeyNotFound,

    /// Element not found
    #[error("element not found")]
    ElementNotFound,

    /// Index is out of bounds
    #[error("the index is {index} but `max_entries` is {max_entries}")]
    OutOfBounds {
        /// Index accessed
        index: u32,
        /// Map size
        max_entries: u32,
    },

    /// Chained programs are not supported.
    #[error("chained programs are not supported by the current kernel")]
    ChainedProgramNotSupported,

    /// Invalid map type encontered
    #[error("invalid map type {map_type}")]
    InvalidMapType {
        /// The map type
        map_type: u32,
    },

    /// A syscall failed.
    #[error(transparent)]
    Syscall(#[from] SysError),

    /// An internal and irrecoverable error occurred.
    #[error(transparent)]
    Other(#[from] Box<dyn Error>),
}

impl From<(i64, SysError)> for MapError {
    fn from((_, error): (i64, SysError)) -> Self {
        error.into()
    }
}

impl From<io::Error> for MapError {
    fn from(e: io::Error) -> Self {
        Self::Other(Box::new(e))
    }
}

impl From<NulError> for MapError {
    fn from(e: NulError) -> Self {
        Self::Other(Box::new(e))
    }
}

impl From<PinError> for MapError {
    fn from(e: PinError) -> Self {
        Self::Other(Box::new(e))
    }
}

#[derive(Error, Debug)]
/// Errors occuring from working with Maps
pub(crate) enum InternalMapError {
    /// Invalid map name encountered
    #[error("invalid map name `{name}`")]
    InvalidName {
        /// The map name
        name: String,
    },

    /// Failed to create map
    #[error("failed to create map `{name}` with code {code}")]
    CreateError {
        /// Map name
        name: String,
        /// Error code
        code: i64,
        #[source]
        /// Original io::Error
        source: SysError,
    },

    /// Invalid key size
    #[error("invalid key size {size}, expected {expected}")]
    InvalidKeySize {
        /// Size encountered
        size: usize,
        /// Size expected
        expected: usize,
    },

    /// Invalid value size
    #[error("invalid value size {size}, expected {expected}")]
    InvalidValueSize {
        /// Size encountered
        size: usize,
        /// Size expected
        expected: usize,
    },

    /// An IO error occurred
    #[error(transparent)]
    IoError(#[from] io::Error),

    /// Syscall failed
    #[error(transparent)]
    SysError(#[from] SysError),

    /// Map type not supported
    #[error("map {0}: type is not supported")]
    Unsupported(String),
}

impl From<InvalidTypeBinding<u32>> for MapError {
    fn from(e: InvalidTypeBinding<u32>) -> Self {
        let InvalidTypeBinding { value } = e;
        Self::InvalidMapType { map_type: value }
    }
}

/// Perf buffer error.
#[derive(Error, Debug)]
pub enum PerfBufferError {
    /// the page count value passed to [`PerfEventArray::open`](crate::maps::PerfEventArray::open) is invalid.
    #[error("invalid page count {page_count}, the value must be a power of two")]
    InvalidPageCount {
        /// the page count
        page_count: usize,
    },

    /// `perf_event_open` failed.
    #[error("perf_event_open failed: {io_error}")]
    OpenError {
        /// the source of this error
        #[source]
        io_error: io::Error,
    },

    /// `mmap`-ping the buffer failed.
    #[error("mmap failed: {io_error}")]
    MMapError {
        /// the source of this error
        #[source]
        io_error: io::Error,
    },

    /// The `PERF_EVENT_IOC_ENABLE` ioctl failed
    #[error("PERF_EVENT_IOC_ENABLE failed: {io_error}")]
    PerfEventEnableError {
        #[source]
        /// the source of this error
        io_error: io::Error,
    },

    /// `read_events()` was called with no output buffers.
    #[error("read_events() was called with no output buffers")]
    NoBuffers,

    /// `read_events()` was called with a buffer that is not large enough to
    /// contain the next event in the perf buffer.
    #[deprecated(
        since = "0.10.8",
        note = "read_events() now calls BytesMut::reserve() internally, so this error is never returned"
    )]
    #[error("the buffer needs to be of at least {size} bytes")]
    MoreSpaceNeeded {
        /// expected size
        size: usize,
    },

    /// An IO error occurred.
    #[error(transparent)]
    IOError(#[from] io::Error),

    /// An irrecoverable error occurred.
    #[error(transparent)]
    Other(#[from] Box<dyn Error>),
}

impl From<SysError> for PerfBufferError {
    fn from(e: SysError) -> Self {
        match e {
            SysError::Syscall { call: _, io_error } => Self::Other(Box::new(io_error)),
            SysError::Mmap { io_error } => Self::MMapError { io_error },
            _ => Self::Other(Box::new(e)),
        }
    }
}

impl From<(i64, SysError)> for PerfBufferError {
    fn from((_, error): (i64, SysError)) -> Self {
        error.into()
    }
}

#[derive(Error, Debug)]
/// Errors from operations on links.
pub enum LinkError {
    /// Invalid link.
    #[error("Invalid link")]
    InvalidLink,

    /// The program is not attached.
    #[error("the program is not attached")]
    NotAttached,

    /// The program is already attached.
    #[error("the program is already attached")]
    AlreadyAttached,

    /// A file error.
    #[error("file error: {path}")]
    FileError {
        /// The file path.
        path: PathBuf,
        /// The original [`io::Error`].
        #[source]
        error: io::Error,
    },

    /// An irrecoverable error occurred.
    #[error(transparent)]
    Other(#[from] Box<dyn Error>),
}

impl From<(PathBuf, io::Error)> for LinkError {
    fn from((path, error): (PathBuf, io::Error)) -> Self {
        Self::FileError { path, error }
    }
}

impl From<SysError> for LinkError {
    fn from(e: SysError) -> Self {
        match e {
            SysError::Syscall { call: _, io_error } => Self::Other(Box::new(io_error)),
            _ => Self::Other(Box::new(e)),
        }
    }
}

impl From<(i64, SysError)> for LinkError {
    fn from((_, error): (i64, SysError)) -> Self {
        error.into()
    }
}

impl From<ProgramError> for LinkError {
    fn from(e: ProgramError) -> Self {
        Self::Other(Box::new(e))
    }
}

impl From<io::Error> for LinkError {
    fn from(e: io::Error) -> Self {
        Self::Other(Box::new(e))
    }
}

impl From<NulError> for LinkError {
    fn from(e: NulError) -> Self {
        Self::Other(Box::new(e))
    }
}

impl From<std::num::ParseIntError> for LinkError {
    fn from(e: std::num::ParseIntError) -> Self {
        Self::Other(Box::new(e))
    }
}

impl From<ResolveSymbolError> for LinkError {
    fn from(e: ResolveSymbolError) -> Self {
        Self::Other(Box::new(e))
    }
}

#[derive(Error, Debug)]
pub(crate) enum InternalLinkError {
    #[error("the target program is not loaded")]
    TargetProgramNotLoaded,

    #[error("target program does not have BTF")]
    TargetNoBtf,

    #[error("error reading ld.so.cache file")]
    LdSoCache {
        #[source]
        io_error: &'static io::Error,
    },

    #[error("could not resolve uprobe target `{path}`")]
    InvalidTarget {
        /// path to target
        path: PathBuf,
    },

    /// netlink error while attaching XDP program
    #[error("Netlink error")]
    NetlinkError {
        /// the [`io::Error`] from the netlink call
        #[source]
        io_error: io::Error,
    },

    /// operation not supported for programs loaded via tcx
    #[error("operation not supported for programs loaded via tcx")]
    InvalidLinkOperation,

    /// tcx links can only be attached to ingress or egress, custom attachment is not supported
    #[error("tcx links can only be attached to ingress or egress, custom attachment: {0} is not supported")]
    InvalidTcxAttach(u32),

    /// The network interface does not exist.
    #[error("unknown network interface {name}")]
    UnknownInterface {
        /// interface name
        name: String,
    },

    /// Setting the `SO_ATTACH_BPF` socket option failed.
    #[error("setsockopt SO_ATTACH_BPF failed")]
    SoAttachEbpf {
        /// original [`io::Error`]
        #[source]
        io_error: io::Error,
    },
}

impl From<InternalLinkError> for LinkError {
    fn from(e: InternalLinkError) -> Self {
        Self::Other(Box::new(e))
    }
}

#[derive(Error, Debug)]
pub(crate) enum ResolveSymbolError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("error parsing ELF")]
    Object(#[from] object::Error),

    #[error("unknown symbol `{0}`")]
    Unknown(String),

    #[error("symbol `{0}` does not appear in section")]
    NotInSection(String),

    #[error("symbol `{0}` in section `{1:?}` which has no offset")]
    SectionFileRangeNone(String, Result<String, object::Error>),

    #[error("failed to access debuglink file `{0}`: `{1}`")]
    DebuglinkAccessError(String, io::Error),

    #[error("symbol `{0}` not found, mismatched build IDs in main and debug files")]
    BuildIdMismatch(String),
}

/// Errors from Syscalls.
#[derive(Debug, Error)]
pub enum SysError {
    /// A syscall failed.
    #[error("{call} failed")]
    Syscall {
        /// The name of the syscall which failed.
        call: String,
        /// The [`io::Error`] returned by the syscall.
        #[source]
        io_error: io::Error,
    },
    /// A mmap operation failed.
    #[error("mmap failed")]
    Mmap {
        /// The [`io::Error`] returned by the mmap operation.
        #[source]
        io_error: io::Error,
    },
    /// An irecoverable error occurred.
    #[error(transparent)]
    Other(#[from] Box<dyn Error>),
}
