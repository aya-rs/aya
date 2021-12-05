//! eBPF program types.
//!
//! eBPF programs are loaded inside the kernel and attached to one or more hook
//! points. Whenever the hook points are reached, the programs are executed.
//!
//! # Loading and attaching programs
//!
//! When you call [`Bpf::load_file`] or [`Bpf::load`], all the programs included
//! in the object code are parsed and relocated. Programs are not loaded
//! automatically though, since often you will need to do some application
//! specific setup before you can actually load them.
//!
//! In order to load and attach a program, you need to retrieve it using [`Bpf::program_mut`],
//! then call the `load()` and `attach()` methods, for example:
//!
//! ```no_run
//! use aya::{Bpf, programs::KProbe};
//! use std::convert::TryInto;
//!
//! let mut bpf = Bpf::load_file("ebpf_programs.o")?;
//! // intercept_wakeups is the name of the program we want to load
//! let program: &mut KProbe = bpf.program_mut("intercept_wakeups").unwrap().try_into()?;
//! program.load()?;
//! // intercept_wakeups will be called every time try_to_wake_up() is called
//! // inside the kernel
//! program.attach("try_to_wake_up", 0)?;
//! # Ok::<(), aya::BpfError>(())
//! ```
//!
//! The signature of the `attach()` method varies depending on what kind of
//! program you're trying to attach.
//!
//! [`Bpf::load_file`]: crate::Bpf::load_file
//! [`Bpf::load`]: crate::Bpf::load
//! [`Bpf::programs`]: crate::Bpf::programs
//! [`Bpf::program`]: crate::Bpf::program
//! [`Bpf::program_mut`]: crate::Bpf::program_mut
//! [`maps`]: crate::maps
mod cgroup_skb;
mod kprobe;
mod lirc_mode2;
mod lsm;
mod perf_attach;
pub mod perf_event;
mod probe;
mod raw_trace_point;
mod sk_msg;
mod sk_skb;
mod sock_ops;
mod socket_filter;
pub mod tc;
mod tp_btf;
mod trace_point;
mod uprobe;
mod xdp;

use libc::{close, dup, ENOSPC};
use std::{
    cmp,
    convert::TryFrom,
    ffi::{CStr, CString},
    io,
    mem::ManuallyDrop,
    os::unix::io::{AsRawFd, RawFd},
    path::Path,
};
use thiserror::Error;

pub use cgroup_skb::{CgroupSkb, CgroupSkbAttachType};
pub use kprobe::{KProbe, KProbeError};
use lirc_mode2::LircLink;
pub use lirc_mode2::LircMode2;
pub use lsm::{Lsm, LsmLoadError};
use perf_attach::*;
pub use perf_event::{PerfEvent, PerfEventScope, PerfTypeId, SamplePolicy};
pub use probe::ProbeKind;
pub use raw_trace_point::RawTracePoint;
pub use sk_msg::SkMsg;
pub use sk_skb::{SkSkb, SkSkbKind};
pub use sock_ops::SockOps;
use socket_filter::SocketFilterLink;
pub use socket_filter::{SocketFilter, SocketFilterError};
use tc::TcLink;
pub use tc::{SchedClassifier, TcAttachType, TcError};
pub use tp_btf::{BtfTracePoint, BtfTracePointError};
pub use trace_point::{TracePoint, TracePointError};
pub use uprobe::{UProbe, UProbeError};
use xdp::NlLink;
pub use xdp::{Xdp, XdpError, XdpFlags};

use crate::{
    generated::{bpf_attach_type, bpf_prog_info, bpf_prog_type},
    maps::MapError,
    obj::{self, Function, KernelVersion},
    sys::{bpf_load_program, bpf_pin_object, bpf_prog_detach, bpf_prog_query, BpfLoadProgramAttrs},
};

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
        /// The [`io::Error`] returned by the `BPF_PROG_LOAD` syscall.
        #[source]
        io_error: io::Error,
        /// The error log produced by the kernel verifier.
        verifier_log: String,
    },

    /// A syscall failed.
    #[error("`{call}` failed")]
    SyscallError {
        /// The name of the syscall which failed.
        call: String,
        /// The [`io::Error`] returned by the syscall.
        #[source]
        io_error: io::Error,
    },

    /// The network interface does not exist.
    #[error("unknown network interface {name}")]
    UnknownInterface { name: String },

    /// The program is not of the expected type.
    #[error("unexpected program type")]
    UnexpectedProgramType,

    #[error("invalid pin path `{error}`")]
    InvalidPinPath { error: String },

    /// A map error occurred while loading or attaching a program.
    #[error(transparent)]
    MapError(#[from] MapError),

    /// An error occurred while working with a [`KProbe`].
    #[error(transparent)]
    KProbeError(#[from] KProbeError),

    /// An error occurred while working with an [`UProbe`].
    #[error(transparent)]
    UProbeError(#[from] UProbeError),

    /// An error occurred while working with a [`TracePoint`].
    #[error(transparent)]
    TracePointError(#[from] TracePointError),

    /// An error occurred while working with a [`SocketFilter`].
    #[error(transparent)]
    SocketFilterError(#[from] SocketFilterError),

    /// An error occurred while working with an [`Xdp`] program.
    #[error(transparent)]
    XdpError(#[from] XdpError),

    /// An error occurred while working with a TC program.
    #[error(transparent)]
    TcError(#[from] TcError),

    /// An error occurred while working with a BTF raw tracepoint program.
    #[error(transparent)]
    BtfTracePointError(#[from] BtfTracePointError),
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
    CgroupSkb(CgroupSkb),
    LircMode2(LircMode2),
    PerfEvent(PerfEvent),
    RawTracePoint(RawTracePoint),
    Lsm(Lsm),
    BtfTracePoint(BtfTracePoint),
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
            Program::CgroupSkb(_) => BPF_PROG_TYPE_CGROUP_SKB,
            Program::LircMode2(_) => BPF_PROG_TYPE_LIRC_MODE2,
            Program::PerfEvent(_) => BPF_PROG_TYPE_PERF_EVENT,
            Program::RawTracePoint(_) => BPF_PROG_TYPE_RAW_TRACEPOINT,
            Program::Lsm(_) => BPF_PROG_TYPE_LSM,
            Program::BtfTracePoint(_) => BPF_PROG_TYPE_TRACING,
        }
    }

    /// Pin the program to the provided path
    pub fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<(), ProgramError> {
        self.data_mut().pin(path)
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
            Program::CgroupSkb(p) => &p.data,
            Program::LircMode2(p) => &p.data,
            Program::PerfEvent(p) => &p.data,
            Program::RawTracePoint(p) => &p.data,
            Program::Lsm(p) => &p.data,
            Program::BtfTracePoint(p) => &p.data,
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
            Program::CgroupSkb(p) => &mut p.data,
            Program::LircMode2(p) => &mut p.data,
            Program::PerfEvent(p) => &mut p.data,
            Program::RawTracePoint(p) => &mut p.data,
            Program::Lsm(p) => &mut p.data,
            Program::BtfTracePoint(p) => &mut p.data,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProgramData {
    pub(crate) obj: obj::Program,
    pub(crate) fd: Option<RawFd>,
    pub(crate) expected_attach_type: Option<bpf_attach_type>,
    pub(crate) attach_btf_obj_fd: Option<u32>,
    pub(crate) attach_btf_id: Option<u32>,
}

impl ProgramData {
    fn fd_or_err(&self) -> Result<RawFd, ProgramError> {
        self.fd.ok_or(ProgramError::NotLoaded)
    }

    pub fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<(), ProgramError> {
        let fd = self.fd_or_err()?;
        let path_string =
            CString::new(path.as_ref().to_string_lossy().into_owned()).map_err(|e| {
                MapError::InvalidPinPath {
                    error: e.to_string(),
                }
            })?;
        bpf_pin_object(fd, &path_string).map_err(|(_code, io_error)| {
            ProgramError::SyscallError {
                call: "BPF_OBJ_PIN".to_string(),
                io_error,
            }
        })?;
        Ok(())
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

    let target_kernel_version = match *kernel_version {
        KernelVersion::Any => {
            let (major, minor, patch) = crate::sys::kernel_version().unwrap();
            (major << 16) + (minor << 8) + patch
        }
        _ => (*kernel_version).into(),
    };

    let mut log_buf = VerifierLog::new();
    let mut retries = 0;
    let mut ret;
    loop {
        let attr = BpfLoadProgramAttrs {
            ty: prog_type,
            insns: instructions,
            license,
            kernel_version: target_kernel_version,
            expected_attach_type: data.expected_attach_type,
            attach_btf_obj_fd: data.attach_btf_obj_fd,
            attach_btf_id: data.attach_btf_id,
            log: &mut log_buf,
        };
        ret = bpf_load_program(attr);
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

pub(crate) fn query<T: AsRawFd>(
    target_fd: T,
    attach_type: bpf_attach_type,
    query_flags: u32,
    attach_flags: &mut Option<u32>,
) -> Result<Vec<u32>, ProgramError> {
    let mut prog_ids = vec![0u32; 64];
    let mut prog_cnt = prog_ids.len() as u32;

    let mut retries = 0;

    loop {
        match bpf_prog_query(
            target_fd.as_raw_fd(),
            attach_type,
            query_flags,
            attach_flags.as_mut(),
            &mut prog_ids,
            &mut prog_cnt,
        ) {
            Ok(_) => {
                prog_ids.resize(prog_cnt as usize, 0);
                return Ok(prog_ids);
            }
            Err((_, io_error)) if retries == 0 && io_error.raw_os_error() == Some(ENOSPC) => {
                prog_ids.resize(prog_cnt as usize, 0);
                retries += 1;
            }
            Err((_, io_error)) => {
                return Err(ProgramError::SyscallError {
                    call: "bpf_prog_query".to_owned(),
                    io_error,
                });
            }
        }
    }
}

/// A type implementing Link represents an attached eBPF program. It can be
/// either detached to terminate its execution, or forgotten so that it persists
/// in the kernel even without a companion userspace.
pub trait Link {
    /// Detach the program from the eBPF VM.
    fn detach(self) -> Result<(), ProgramError>;
    /// Perform any necessary cleanup to forget the program without leaking
    /// system resources, if possible.
    fn forget(self) -> Result<(), ProgramError>;
}

/// The private counterpart to Link for the enum members of OwnedLink. InnerLink functions are
/// permitted to put the implementing type in a state such that all subsequent method calls fail.
/// The intent is that InnerLink functions will only be publicly called through Link. This allows
/// us to cleanly handle Drop without exposing the &mut self methods to the public API.
pub(crate) trait InnerLink {
    /// Detach the program from the eBPF VM.
    fn detach(&mut self) -> Result<(), ProgramError>;
    /// Perform any necessary cleanup to forget the program without leaking
    /// system resources, if possible.
    fn forget(&mut self) -> Result<(), ProgramError> {
        Ok(())
    }
}

/// The return type of `program.attach(...)`.
///
/// [`OwnedLink`] implements the [`Link`] trait and can be used to detach or
/// forget a program.
/// An eBPF program's lifetime is directly connected to the OwnedLink's; it must
/// be in scope for as long as one wants the program to remain attached. When
/// dropped, OwnedLink will detach the program. In order to persist a program in
/// the kernel beyond the OwnedLink's lifetime, call the [forget](Link::forget) method.
#[derive(Debug)]
pub struct OwnedLink {
    inner: OwnedLinkImpl,
}

impl Link for OwnedLink {
    fn detach(self) -> Result<(), ProgramError> {
        let mut v = ManuallyDrop::new(self);
        v.inner.detach()
    }

    fn forget(self) -> Result<(), ProgramError> {
        let mut v = ManuallyDrop::new(self);
        v.inner.forget()
    }
}

impl From<OwnedLinkImpl> for OwnedLink {
    fn from(inner: OwnedLinkImpl) -> Self {
        Self { inner }
    }
}

impl From<FdLink> for OwnedLink {
    fn from(l: FdLink) -> Self {
        Self { inner: l.into() }
    }
}

impl From<LircLink> for OwnedLink {
    fn from(l: LircLink) -> Self {
        Self { inner: l.into() }
    }
}

impl From<NlLink> for OwnedLink {
    fn from(l: NlLink) -> Self {
        Self { inner: l.into() }
    }
}

impl From<PerfLink> for OwnedLink {
    fn from(l: PerfLink) -> Self {
        Self { inner: l.into() }
    }
}

impl From<ProgAttachLink> for OwnedLink {
    fn from(l: ProgAttachLink) -> Self {
        Self { inner: l.into() }
    }
}

impl From<SocketFilterLink> for OwnedLink {
    fn from(l: SocketFilterLink) -> Self {
        Self { inner: l.into() }
    }
}

impl From<TcLink> for OwnedLink {
    fn from(l: TcLink) -> Self {
        Self { inner: l.into() }
    }
}

impl Drop for OwnedLink {
    fn drop(&mut self) {
        let _ = self.inner.detach();
    }
}

#[derive(Debug)]
pub(crate) enum OwnedLinkImpl {
    Fd(FdLink),
    Lirc(LircLink),
    Nl(NlLink),
    Perf(PerfLink),
    ProgAttach(ProgAttachLink),
    SocketFilter(SocketFilterLink),
    Tc(TcLink),
}

impl OwnedLinkImpl {
    fn detach(&mut self) -> Result<(), ProgramError> {
        match self {
            Self::Fd(link) => link.detach(),
            Self::Lirc(link) => link.detach(),
            Self::Nl(link) => link.detach(),
            Self::Perf(link) => link.detach(),
            Self::ProgAttach(link) => link.detach(),
            Self::SocketFilter(link) => link.detach(),
            Self::Tc(link) => link.detach(),
        }
    }

    fn forget(&mut self) -> Result<(), ProgramError> {
        match self {
            Self::Fd(link) => link.forget(),
            Self::Lirc(link) => link.forget(),
            Self::Nl(link) => link.forget(),
            Self::Perf(link) => link.forget(),
            Self::ProgAttach(link) => link.forget(),
            Self::SocketFilter(link) => link.forget(),
            Self::Tc(link) => link.forget(),
        }
    }
}

impl From<FdLink> for OwnedLinkImpl {
    fn from(l: FdLink) -> Self {
        Self::Fd(l)
    }
}

impl From<LircLink> for OwnedLinkImpl {
    fn from(l: LircLink) -> Self {
        Self::Lirc(l)
    }
}

impl From<NlLink> for OwnedLinkImpl {
    fn from(l: NlLink) -> Self {
        Self::Nl(l)
    }
}

impl From<PerfLink> for OwnedLinkImpl {
    fn from(l: PerfLink) -> Self {
        Self::Perf(l)
    }
}

impl From<ProgAttachLink> for OwnedLinkImpl {
    fn from(l: ProgAttachLink) -> Self {
        Self::ProgAttach(l)
    }
}

impl From<SocketFilterLink> for OwnedLinkImpl {
    fn from(l: SocketFilterLink) -> Self {
        Self::SocketFilter(l)
    }
}

impl From<TcLink> for OwnedLinkImpl {
    fn from(l: TcLink) -> Self {
        Self::Tc(l)
    }
}

#[derive(Debug)]
pub(crate) struct FdLink {
    fd: RawFd,
}

impl InnerLink for FdLink {
    fn detach(&mut self) -> Result<(), ProgramError> {
        // TODO: Actually wrap this return code.
        unsafe { close(self.fd) };
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct ProgAttachLink {
    prog_fd: RawFd,
    target_fd: RawFd,
    attach_type: bpf_attach_type,
}

impl ProgAttachLink {
    pub(crate) fn new(
        prog_fd: RawFd,
        target_fd: RawFd,
        attach_type: bpf_attach_type,
    ) -> ProgAttachLink {
        ProgAttachLink {
            prog_fd,
            target_fd: unsafe { dup(target_fd) },
            attach_type,
        }
    }
}

impl InnerLink for ProgAttachLink {
    fn detach(&mut self) -> Result<(), ProgramError> {
        // TODO: Actually wrap this return code.
        let _ = bpf_prog_detach(self.prog_fd, self.target_fd, self.attach_type);
        self.forget()
    }

    fn forget(&mut self) -> Result<(), ProgramError> {
        // TODO: Actually wrap this return code.
        unsafe { close(self.target_fd) };
        Ok(())
    }
}

impl ProgramFd for Program {
    fn fd(&self) -> Option<RawFd> {
        self.data().fd
    }
}

impl<'a, P: ProgramFd> ProgramFd for &'a P {
    fn fd(&self) -> Option<RawFd> {
        (*self).fd()
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
    SchedClassifier,
    CgroupSkb,
    LircMode2,
    PerfEvent,
    Lsm,
    RawTracePoint,
    BtfTracePoint,
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
    SchedClassifier,
    CgroupSkb,
    LircMode2,
    PerfEvent,
    Lsm,
    RawTracePoint,
    BtfTracePoint,
);

/// Provides information about a loaded program, like name, id and statistics
pub struct ProgramInfo(bpf_prog_info);

impl ProgramInfo {
    /// The name of the program as was provided when it was load. This is limited to 16 bytes
    pub fn name(&self) -> &[u8] {
        let length = self
            .0
            .name
            .iter()
            .rposition(|ch| *ch != 0)
            .map(|pos| pos + 1)
            .unwrap_or(0);

        // The name field is defined as [std::os::raw::c_char; 16]. c_char may be signed or
        // unsigned depending on the platform; that's why we're using from_raw_parts here
        unsafe { std::slice::from_raw_parts(self.0.name.as_ptr() as *const _, length) }
    }

    /// The name of the program as a &str. If the name was not valid unicode, None is returned
    pub fn name_as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.name()).ok()
    }

    /// The program id for this program. Each program has a unique id.
    pub fn id(&self) -> u32 {
        self.0.id
    }
}
