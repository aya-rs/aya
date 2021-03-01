mod perf_attach;
pub mod probe;
pub mod socket_filter;
pub mod trace_point;
pub mod xdp;

use libc::{close, ENOSPC};
use std::{cell::RefCell, cmp, convert::TryFrom, ffi::CStr, io, os::unix::io::RawFd, rc::Rc};
use thiserror::Error;

use perf_attach::*;
pub use probe::{KProbe, KProbeError, UProbe, UProbeError};
pub use socket_filter::{SocketFilter, SocketFilterError};
pub use trace_point::{TracePoint, TracePointError};
pub use xdp::{Xdp, XdpError};

use crate::{
    generated::bpf_prog_type,
    obj::{self, Function},
    sys::bpf_load_program,
};
#[derive(Debug, Error)]
pub enum ProgramError {
    #[error("the program is already loaded")]
    AlreadyLoaded,

    #[error("the program is not loaded")]
    NotLoaded,

    #[error("the program was already detached")]
    AlreadyDetached,

    #[error("the program is not attached")]
    NotAttached,

    #[error("the BPF_PROG_LOAD syscall failed: {io_error}\nVerifier output:\n{verifier_log}")]
    LoadError {
        #[source]
        io_error: io::Error,
        verifier_log: String,
    },

    #[error("the perf_event_open syscall failed")]
    PerfEventOpenError {
        #[source]
        io_error: io::Error,
    },

    #[error("PERF_EVENT_IOC_SET_BPF/PERF_EVENT_IOC_ENABLE failed")]
    PerfEventAttachError {
        #[source]
        io_error: io::Error,
    },

    #[error("unknown network interface {name}")]
    UnknownInterface { name: String },

    #[error("BPF_LINK_CREATE failed")]
    BpfLinkCreateError {
        #[source]
        io_error: io::Error,
    },

    #[error("unexpected program type")]
    UnexpectedProgramType,

    #[error(transparent)]
    KProbeError(#[from] KProbeError),

    #[error(transparent)]
    UProbeError(#[from] UProbeError),

    #[error(transparent)]
    TracePointError(#[from] TracePointError),

    #[error(transparent)]
    SocketFilterError(#[from] SocketFilterError),

    #[error(transparent)]
    XdpError(#[from] XdpError),
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

    pub fn prog_type(&self) -> bpf_prog_type {
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

    pub fn name(&self) -> &str {
        &self.data().name
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
        self.fd.ok_or(ProgramError::NotLoaded)
    }

    pub fn link<T: Link + 'static>(&mut self, link: T) -> LinkRef {
        let link: Rc<RefCell<dyn Link>> = Rc::new(RefCell::new(link));
        self.links.push(Rc::clone(&link));
        LinkRef::new(link)
    }
}

const MIN_LOG_BUF_SIZE: usize = 1024 * 10;
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
            MIN_LOG_BUF_SIZE,
            cmp::min(MAX_LOG_BUF_SIZE, self.buf.capacity() * 3),
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

fn load_program(prog_type: bpf_prog_type, data: &mut ProgramData) -> Result<(), ProgramError> {
    let ProgramData { obj, fd, .. } = data;
    if fd.is_some() {
        return Err(ProgramError::AlreadyLoaded);
    }
    let crate::obj::Program {
        function: Function { instructions, .. },
        license,
        kernel_version,
        ..
    } = obj;

    let mut ret = Ok(-1);
    let mut log_buf = VerifierLog::new();
    for i in 0..3 {
        log_buf.reset();

        ret = bpf_load_program(
            prog_type,
            instructions,
            license,
            (*kernel_version).into(),
            &mut log_buf,
        );
        match &ret {
            Ok(prog_fd) => {
                *fd = Some(*prog_fd as RawFd);
                return Ok(());
            }
            Err((_, io_error)) if i == 0 || io_error.raw_os_error() == Some(ENOSPC) => {
                log_buf.grow();
                continue;
            }
            _ => break,
        };
    }

    if let Err((_, io_error)) = ret {
        log_buf.truncate();
        return Err(ProgramError::LoadError {
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
pub struct LinkRef {
    inner: Rc<RefCell<dyn Link>>,
}

impl LinkRef {
    fn new(link: Rc<RefCell<dyn Link>>) -> LinkRef {
        LinkRef { inner: link }
    }
}

impl Link for LinkRef {
    fn detach(&mut self) -> Result<(), ProgramError> {
        self.inner.borrow_mut().detach()
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
