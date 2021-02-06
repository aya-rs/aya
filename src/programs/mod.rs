mod perf_attach;
mod probe;
mod socket_filter;
mod trace_point;
mod xdp;

use libc::{close, ENOSPC};
use std::{
    cell::RefCell,
    cmp,
    convert::TryFrom,
    ffi::CStr,
    io,
    os::raw::c_uint,
    path::PathBuf,
    rc::{Rc, Weak},
};
use thiserror::Error;

use perf_attach::*;
pub use probe::*;
pub use socket_filter::*;
pub use trace_point::*;
pub use xdp::*;

use crate::{obj, sys::bpf_load_program, RawFd};
#[derive(Debug, Error)]
pub enum ProgramError {
    #[error("the program {program} is already loaded")]
    AlreadyLoaded { program: String },

    #[error("the program {program} is not loaded")]
    NotLoaded { program: String },

    #[error("the BPF_PROG_LOAD syscall for `{program}` failed: {io_error}\nVerifier output:\n{verifier_log}")]
    LoadFailed {
        program: String,
        io_error: io::Error,
        verifier_log: String,
    },

    #[error("the program was already detached")]
    AlreadyDetached,

    #[error("the perf_event_open syscall failed: {io_error}")]
    PerfEventOpenFailed { io_error: io::Error },

    #[error("PERF_EVENT_IOC_SET_BPF/PERF_EVENT_IOC_ENABLE failed: {io_error}")]
    PerfEventAttachFailed { io_error: io::Error },

    #[error("the program {program} is not attached")]
    NotAttached { program: String },

    #[error("error attaching {program}: BPF_LINK_CREATE failed with {io_error}")]
    BpfLinkCreateFailed {
        program: String,
        #[source]
        io_error: io::Error,
    },

    #[error("unkown network interface {name}")]
    UnkownInterface { name: String },

    #[error("error reading ld.so.cache file")]
    InvalidLdSoCache { error_kind: io::ErrorKind },

    #[error("could not resolve uprobe target {path}")]
    InvalidUprobeTarget { path: PathBuf },

    #[error("error resolving symbol: {error}")]
    UprobeSymbolError { symbol: String, error: String },

    #[error("setsockopt SO_ATTACH_BPF failed: {io_error}")]
    SocketFilterError { io_error: io::Error },

    #[error("unexpected program type")]
    UnexpectedProgramType,

    #[error("{message}")]
    Other { message: String },
}

pub trait ProgramFd {
    fn fd(&self) -> Option<RawFd>;
}

#[derive(Debug)]
pub enum Program {
    KProbe(KProbe),
    UProbe(UProbe),
    TracePoint(TracePoint),
    SocketFilter(SocketFilter),
    Xdp(Xdp),
}

impl Program {
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(self.prog_type(), self.data_mut())
    }

    fn prog_type(&self) -> c_uint {
        use crate::generated::bpf_prog_type::*;
        match self {
            Program::KProbe(_) => BPF_PROG_TYPE_KPROBE,
            Program::UProbe(_) => BPF_PROG_TYPE_KPROBE,
            Program::TracePoint(_) => BPF_PROG_TYPE_TRACEPOINT,
            Program::SocketFilter(_) => BPF_PROG_TYPE_SOCKET_FILTER,
            Program::Xdp(_) => BPF_PROG_TYPE_XDP,
        }
    }

    pub(crate) fn data(&self) -> &ProgramData {
        match self {
            Program::KProbe(p) => &p.data,
            Program::UProbe(p) => &p.data,
            Program::TracePoint(p) => &p.data,
            Program::SocketFilter(p) => &p.data,
            Program::Xdp(p) => &p.data,
        }
    }

    fn data_mut(&mut self) -> &mut ProgramData {
        match self {
            Program::KProbe(p) => &mut p.data,
            Program::UProbe(p) => &mut p.data,
            Program::TracePoint(p) => &mut p.data,
            Program::SocketFilter(p) => &mut p.data,
            Program::Xdp(p) => &mut p.data,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProgramData {
    pub(crate) name: String,
    pub(crate) obj: obj::Program,
    pub(crate) fd: Option<RawFd>,
    pub(crate) links: Vec<Rc<RefCell<dyn Link>>>,
}

impl ProgramData {
    fn fd_or_err(&self) -> Result<RawFd, ProgramError> {
        self.fd.ok_or(ProgramError::NotLoaded {
            program: self.name.clone(),
        })
    }
}

const MAX_LOG_BUF_SIZE: usize = (std::u32::MAX >> 8) as usize;

pub struct VerifierLog {
    buf: Vec<u8>,
}

impl VerifierLog {
    fn new() -> VerifierLog {
        VerifierLog { buf: Vec::new() }
    }

    pub(crate) fn buf(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }

    fn grow(&mut self) {
        self.buf.reserve(cmp::max(
            1024 * 4,
            cmp::min(MAX_LOG_BUF_SIZE, self.buf.capacity() * 2),
        ));
        self.buf.resize(self.buf.capacity(), 0);
    }

    fn reset(&mut self) {
        if !self.buf.is_empty() {
            self.buf[0] = 0;
        }
    }

    fn truncate(&mut self) {
        if self.buf.is_empty() {
            return;
        }

        let pos = self
            .buf
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(self.buf.len() - 1);
        self.buf.truncate(pos + 1);
    }

    pub fn as_c_str(&self) -> Option<&CStr> {
        if self.buf.is_empty() {
            None
        } else {
            Some(CStr::from_bytes_with_nul(&self.buf).unwrap())
        }
    }
}

fn load_program(prog_type: c_uint, data: &mut ProgramData) -> Result<(), ProgramError> {
    let ProgramData { obj, fd, name, .. } = data;
    if fd.is_some() {
        return Err(ProgramError::AlreadyLoaded {
            program: name.to_string(),
        });
    }
    let crate::obj::Program {
        instructions,
        license,
        kernel_version,
        ..
    } = obj;

    let mut ret = Ok(1);
    let mut log_buf = VerifierLog::new();
    for i in 0..3 {
        log_buf.reset();

        ret = match bpf_load_program(
            prog_type,
            instructions,
            license,
            (*kernel_version).into(),
            &mut log_buf,
        ) {
            Ok(prog_fd) => {
                *fd = Some(prog_fd as RawFd);
                return Ok(());
            }
            Err((_, io_error)) if i == 0 || io_error.raw_os_error() == Some(ENOSPC) => {
                log_buf.grow();
                continue;
            }
            x => x,
        };
    }

    if let Err((_, io_error)) = ret {
        log_buf.truncate();
        return Err(ProgramError::LoadFailed {
            program: name.clone(),
            io_error,
            verifier_log: log_buf.as_c_str().unwrap().to_string_lossy().to_string(),
        });
    }

    Ok(())
}

pub trait Link: std::fmt::Debug {
    fn detach(&mut self) -> Result<(), ProgramError>;
}

#[derive(Debug)]
pub(crate) struct LinkRef<T: Link> {
    inner: Weak<RefCell<T>>,
}

impl<T: Link> LinkRef<T> {
    fn new(inner: &Rc<RefCell<T>>) -> LinkRef<T> {
        LinkRef {
            inner: Rc::downgrade(inner),
        }
    }
}

impl<T: Link> Link for LinkRef<T> {
    fn detach(&mut self) -> Result<(), ProgramError> {
        if let Some(inner) = self.inner.upgrade() {
            inner.borrow_mut().detach()
        } else {
            Err(ProgramError::AlreadyDetached)
        }
    }
}

#[derive(Debug)]
pub(crate) struct FdLink {
    fd: Option<RawFd>,
}

impl Link for FdLink {
    fn detach(&mut self) -> Result<(), ProgramError> {
        if let Some(fd) = self.fd.take() {
            unsafe { close(fd) };
            Ok(())
        } else {
            Err(ProgramError::AlreadyDetached)
        }
    }
}

impl Drop for FdLink {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

impl ProgramFd for Program {
    fn fd(&self) -> Option<RawFd> {
        self.data().fd
    }
}

macro_rules! impl_program_fd {
    ($($struct_name:ident),+ $(,)?) => {
        $(
            impl ProgramFd for $struct_name {
                fn fd(&self) -> Option<RawFd> {
                    self.data.fd
                }
            }
        )+
    }
}

impl_program_fd!(KProbe, UProbe, TracePoint, SocketFilter, Xdp);

macro_rules! impl_try_from_program {
    ($($ty:ident),+ $(,)?) => {
        $(
            impl<'a> TryFrom<&'a Program> for &'a $ty {
                type Error = ProgramError;

                fn try_from(program: &'a Program) -> Result<&'a $ty, ProgramError> {
                    match program {
                        Program::$ty(p) => Ok(p),
                        _ => Err(ProgramError::UnexpectedProgramType),
                    }
                }
            }

            impl<'a> TryFrom<&'a mut Program> for &'a mut $ty {
                type Error = ProgramError;

                fn try_from(program: &'a mut Program) -> Result<&'a mut $ty, ProgramError> {
                    match program {
                        Program::$ty(p) => Ok(p),
                        _ => Err(ProgramError::UnexpectedProgramType),
                    }
                }
            }
        )+
    }
}

impl_try_from_program!(KProbe, UProbe, TracePoint, SocketFilter, Xdp);
