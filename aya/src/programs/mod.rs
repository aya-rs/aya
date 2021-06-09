//! eBPF program types.
//!
//! eBPF programs are loaded inside the kernel and attached to one or more hook points. Whenever
//! the kernel or an application reaches those hook points, the programs are executed.
//!
//! # Loading programs
//!
//! When you call [`Bpf::load_file`] or [`Bpf::load`], all the programs present in the code are
//! parsed and can be retrieved using the [`Bpf::program`] and [`Bpf::program_mut`] methods. In
//! order to load a program, you need to get a handle to it and call the `load()` method, for
//! example:
//!
//! ```no_run
//! use aya::{Bpf, programs::KProbe};
//! use std::convert::TryInto;
//!
//! let mut bpf = Bpf::load_file("ebpf_programs.o")?;
//! // intercept_wakeups is the name of the program we want to load
//! let program: &mut KProbe = bpf.program_mut("intercept_wakeups")?.try_into()?;
//! program.load()?;
//! # Ok::<(), aya::BpfError>(())
//! ```
//!
//! # Attaching programs
//!
//! After being loaded, programs must be attached to their target hook points to be executed. The
//! eBPF platform supports many different program types, with each type providing different
//! attachment options. For example when attaching a [`KProbe`], you must provide the name of the
//! kernel function you want instrument; when loading an [`Xdp`] program, you need to specify the
//! network card name you want to hook into, and so forth.
//!
//! Currently aya supports [`KProbe`], [`UProbe`], [`SocketFilter`], [`TracePoint`] and [`Xdp`]
//! programs. To see how to attach them, see the documentation of the respective `attach()` method.
//!
//! # Interacting with programs
//!
//! eBPF programs are event-driven and execute when the hook points they are attached to are hit.
//! To communicate with user-space, programs use data structures provided by the eBPF platform,
//! which can be found in the [maps] module.
//!
//! [`Bpf::load_file`]: crate::Bpf::load_file
//! [`Bpf::load`]: crate::Bpf::load
//! [`Bpf::programs`]: crate::Bpf::programs
//! [`Bpf::program`]: crate::Bpf::program
//! [`Bpf::program_mut`]: crate::Bpf::program_mut
//! [maps]: crate::maps
mod tc;
mod kprobe;
mod perf_attach;
mod probe;
mod sk_msg;
mod sk_skb;
mod sock_ops;
mod socket_filter;
mod trace_point;
mod uprobe;
mod xdp;

use libc::{close, dup, ENOSPC};
use std::{cell::RefCell, cmp, convert::TryFrom, ffi::CStr, io, os::unix::io::RawFd, rc::Rc};
use thiserror::Error;

pub use tc::{SchedClassifier, TcError, TcAttachPoint};
pub use kprobe::{KProbe, KProbeError};
use perf_attach::*;
pub use probe::ProbeKind;
pub use sk_msg::SkMsg;
pub use sk_skb::{SkSkb, SkSkbKind};
pub use sock_ops::SockOps;
pub use socket_filter::{SocketFilter, SocketFilterError};
pub use trace_point::{TracePoint, TracePointError};
pub use uprobe::{UProbe, UProbeError};
pub use xdp::{Xdp, XdpError, XdpFlags};

use crate::{
    generated::{bpf_attach_type, bpf_prog_type},
    maps::MapError,
    obj::{self, Function},
    sys::{bpf_load_program, bpf_prog_detach},
};
#[derive(Debug, Error)]
pub enum ProgramError {
    #[error("program `{name}` not found")]
    NotFound { name: String },

    #[error("the program is already loaded")]
    AlreadyLoaded,

    #[error("the program is not loaded")]
    NotLoaded,

    #[error("the program was already detached")]
    AlreadyDetached,

    #[error("the program is not attached")]
    NotAttached,

    #[error("the BPF_PROG_LOAD syscall failed. Verifier output: {verifier_log}")]
    LoadError {
        #[source]
        io_error: io::Error,
        verifier_log: String,
    },

    #[error("`{call}` failed")]
    SyscallError {
        call: String,
        #[source]
        io_error: io::Error,
    },

    #[error("unknown network interface {name}")]
    UnknownInterface { name: String },

    #[error("unexpected program type")]
    UnexpectedProgramType,

    #[error(transparent)]
    MapError(#[from] MapError),

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

    #[error(transparent)]
    TcError(#[from] TcError),
}

pub trait ProgramFd {
    fn fd(&self) -> Option<RawFd>;
}

/// eBPF program type.
#[derive(Debug)]
pub enum Program {
    KProbe(KProbe),
    UProbe(UProbe),
    TracePoint(TracePoint),
    SocketFilter(SocketFilter),
    Xdp(Xdp),
    SkMsg(SkMsg),
    SkSkb(SkSkb),
    SockOps(SockOps),
    SchedClassifier(SchedClassifier),
}

impl Program {
    /// Loads the program in the kernel.
    ///
    /// # Errors
    ///
    /// If the load operation fails, the method returns
    /// [`ProgramError::LoadError`] and the error's `verifier_log` field
    /// contains the output from the kernel verifier.
    ///
    /// If the program is already loaded, [`ProgramError::AlreadyLoaded`] is
    /// returned.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(self.prog_type(), self.data_mut())
    }

    /// Returns the low level program type.
    pub fn prog_type(&self) -> bpf_prog_type {
        use crate::generated::bpf_prog_type::*;
        match self {
            Program::KProbe(_) => BPF_PROG_TYPE_KPROBE,
            Program::UProbe(_) => BPF_PROG_TYPE_KPROBE,
            Program::TracePoint(_) => BPF_PROG_TYPE_TRACEPOINT,
            Program::SocketFilter(_) => BPF_PROG_TYPE_SOCKET_FILTER,
            Program::Xdp(_) => BPF_PROG_TYPE_XDP,
            Program::SkMsg(_) => BPF_PROG_TYPE_SK_MSG,
            Program::SkSkb(_) => BPF_PROG_TYPE_SK_SKB,
            Program::SockOps(_) => BPF_PROG_TYPE_SOCK_OPS,
            Program::SchedClassifier(_) => BPF_PROG_TYPE_SCHED_CLS,
        }
    }

    /// Returns the name of the program.
    pub fn name(&self) -> &str {
        &self.data().name
    }

    fn data(&self) -> &ProgramData {
        match self {
            Program::KProbe(p) => &p.data,
            Program::UProbe(p) => &p.data,
            Program::TracePoint(p) => &p.data,
            Program::SocketFilter(p) => &p.data,
            Program::Xdp(p) => &p.data,
            Program::SkMsg(p) => &p.data,
            Program::SkSkb(p) => &p.data,
            Program::SockOps(p) => &p.data,
            Program::SchedClassifier(p) => &p.data,
        }
    }

    fn data_mut(&mut self) -> &mut ProgramData {
        match self {
            Program::KProbe(p) => &mut p.data,
            Program::UProbe(p) => &mut p.data,
            Program::TracePoint(p) => &mut p.data,
            Program::SocketFilter(p) => &mut p.data,
            Program::Xdp(p) => &mut p.data,
            Program::SkMsg(p) => &mut p.data,
            Program::SkSkb(p) => &mut p.data,
            Program::SockOps(p) => &mut p.data,
            Program::SchedClassifier(p) => &mut p.data,
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

pub(crate) struct VerifierLog {
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
        let len = cmp::max(
            MIN_LOG_BUF_SIZE,
            cmp::min(MAX_LOG_BUF_SIZE, self.buf.capacity() * 10),
        );
        self.buf.resize(len, 0);
        self.reset();
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
        self.buf[pos] = 0;
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

    let mut log_buf = VerifierLog::new();
    let mut retries = 0;
    let mut ret;
    loop {
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
            Err((_, io_error)) if retries == 0 || io_error.raw_os_error() == Some(ENOSPC) => {
                if retries == 10 {
                    break;
                }
                retries += 1;
                log_buf.grow();
            }
            Err(_) => break,
        };
    }

    if let Err((_, io_error)) = ret {
        log_buf.truncate();
        return Err(ProgramError::LoadError {
            io_error,
            verifier_log: log_buf
                .as_c_str()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "[none]".to_owned()),
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

#[derive(Debug)]
struct ProgAttachLink {
    prog_fd: Option<RawFd>,
    target_fd: Option<RawFd>,
    attach_type: bpf_attach_type,
}

impl ProgAttachLink {
    pub(crate) fn new(
        prog_fd: RawFd,
        target_fd: RawFd,
        attach_type: bpf_attach_type,
    ) -> ProgAttachLink {
        ProgAttachLink {
            prog_fd: Some(prog_fd),
            target_fd: Some(unsafe { dup(target_fd) }),
            attach_type,
        }
    }
}

impl Link for ProgAttachLink {
    fn detach(&mut self) -> Result<(), ProgramError> {
        if let Some(prog_fd) = self.prog_fd.take() {
            let target_fd = self.target_fd.take().unwrap();
            let _ = bpf_prog_detach(prog_fd, target_fd, self.attach_type);
            unsafe { close(target_fd) };
            Ok(())
        } else {
            Err(ProgramError::AlreadyDetached)
        }
    }
}

impl Drop for ProgAttachLink {
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

impl_program_fd!(
    KProbe,
    UProbe,
    TracePoint,
    SocketFilter,
    Xdp,
    SkMsg,
    SkSkb,
    SchedClassifier
);

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

impl_try_from_program!(
    KProbe,
    UProbe,
    TracePoint,
    SocketFilter,
    Xdp,
    SkMsg,
    SkSkb,
    SockOps,
    SchedClassifier
);
