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
mod extension;
mod fentry;
mod fexit;
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
mod utils;
mod xdp;

use libc::{close, dup, ENOSPC};
use std::{
    cell::RefCell,
    convert::TryFrom,
    ffi::CString,
    io,
    os::unix::io::{AsRawFd, RawFd},
    path::Path,
    rc::Rc,
};
use thiserror::Error;

pub use cgroup_skb::{CgroupSkb, CgroupSkbAttachType};
pub use extension::{Extension, ExtensionError};
pub use fentry::FEntry;
pub use fexit::FExit;
pub use kprobe::{KProbe, KProbeError};
pub use lirc_mode2::LircMode2;
pub use lsm::Lsm;
use perf_attach::*;
pub use perf_event::{PerfEvent, PerfEventScope, PerfTypeId, SamplePolicy};
pub use probe::ProbeKind;
pub use raw_trace_point::RawTracePoint;
pub use sk_msg::SkMsg;
pub use sk_skb::{SkSkb, SkSkbKind};
pub use sock_ops::SockOps;
pub use socket_filter::{SocketFilter, SocketFilterError};
pub use tc::{SchedClassifier, TcAttachType, TcError};
pub use tp_btf::BtfTracePoint;
pub use trace_point::{TracePoint, TracePointError};
pub use uprobe::{UProbe, UProbeError};
pub use xdp::{Xdp, XdpError, XdpFlags};

use crate::{
    generated::{bpf_attach_type, bpf_prog_info, bpf_prog_type},
    maps::MapError,
    obj::{self, btf::BtfError, Function, KernelVersion},
    sys::{
        bpf_get_object, bpf_load_program, bpf_obj_get_info_by_fd, bpf_pin_object, bpf_prog_detach,
        bpf_prog_get_fd_by_id, bpf_prog_query, BpfLoadProgramAttrs,
    },
    util::VerifierLog,
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

    /// The program is already detached.
    #[error("the program was already detached")]
    AlreadyDetached,

    /// The program is not attached.
    #[error("the program is not attached")]
    NotAttached,

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

    /// An error occurred while working with an [`Extension`] program.
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),

    /// An error occurred while working with BTF.
    #[error(transparent)]
    Btf(#[from] BtfError),

    /// The program is not attached.
    #[error("the program name `{name}` is invalid")]
    InvalidName { name: String },

    /// The program is too long.
    #[error("the program name `{name}` it longer than 16 characters")]
    NameTooLong { name: String },
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
    FEntry(FEntry),
    FExit(FExit),
    Extension(Extension),
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
            Program::FEntry(_) => BPF_PROG_TYPE_TRACING,
            Program::FExit(_) => BPF_PROG_TYPE_TRACING,
            Program::Extension(_) => BPF_PROG_TYPE_EXT,
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
            Program::FEntry(p) => &p.data,
            Program::FExit(p) => &p.data,
            Program::Extension(p) => &p.data,
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
            Program::FEntry(p) => &mut p.data,
            Program::FExit(p) => &mut p.data,
            Program::Extension(p) => &mut p.data,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ProgramData {
    pub(crate) name: Option<String>,
    pub(crate) obj: obj::Program,
    pub(crate) fd: Option<RawFd>,
    pub(crate) links: Vec<Rc<RefCell<dyn Link>>>,
    pub(crate) expected_attach_type: Option<bpf_attach_type>,
    pub(crate) attach_btf_obj_fd: Option<u32>,
    pub(crate) attach_btf_id: Option<u32>,
    pub(crate) attach_prog_fd: Option<RawFd>,
    pub(crate) btf_fd: Option<RawFd>,
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

fn load_program(prog_type: bpf_prog_type, data: &mut ProgramData) -> Result<(), ProgramError> {
    let ProgramData { obj, fd, .. } = data;
    if fd.is_some() {
        return Err(ProgramError::AlreadyLoaded);
    }
    let crate::obj::Program {
        function:
            Function {
                instructions,
                func_info,
                line_info,
                func_info_rec_size,
                line_info_rec_size,
                ..
            },
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

    let prog_name = if let Some(name) = &data.name {
        let name = name.clone();
        let prog_name = CString::new(name.clone())
            .map_err(|_| ProgramError::InvalidName { name: name.clone() })?;

        if prog_name.to_bytes().len() > 16 {
            return Err(ProgramError::NameTooLong { name });
        }
        Some(prog_name)
    } else {
        None
    };

    loop {
        let attr = BpfLoadProgramAttrs {
            name: prog_name.clone(),
            ty: prog_type,
            insns: instructions,
            license,
            kernel_version: target_kernel_version,
            expected_attach_type: data.expected_attach_type,
            prog_btf_fd: data.btf_fd,
            attach_btf_obj_fd: data.attach_btf_obj_fd,
            attach_btf_id: data.attach_btf_id,
            attach_prog_fd: data.attach_prog_fd,
            log: &mut log_buf,
            func_info_rec_size: *func_info_rec_size,
            func_info: func_info.clone(),
            line_info_rec_size: *line_info_rec_size,
            line_info: line_info.clone(),
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

/// Detach an attached program
pub trait Link: std::fmt::Debug {
    fn detach(&mut self) -> Result<(), ProgramError>;
}

/// The return type of `program.attach(...)`.
///
/// [`LinkRef`] implements the [`Link`] trait and can be used to detach a
/// program.
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

            impl ProgramFd for &mut $struct_name {
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
    FEntry,
    FExit,
    Extension,
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
    FEntry,
    FExit,
    Extension,
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

    /// Returns the fd associated with the program.
    ///
    /// The returned fd must be closed when no longer needed.
    pub fn fd(&self) -> Result<RawFd, ProgramError> {
        let fd =
            bpf_prog_get_fd_by_id(self.0.id).map_err(|io_error| ProgramError::SyscallError {
                call: "bpf_prog_get_fd_by_id".to_owned(),
                io_error,
            })?;
        Ok(fd as RawFd)
    }

    /// Loads a program from a pinned path in bpffs.
    pub fn from_pinned<P: AsRef<Path>>(path: P) -> Result<ProgramInfo, ProgramError> {
        let path_string = match CString::new(path.as_ref().to_str().unwrap()) {
            Ok(s) => s,
            Err(e) => {
                return Err(ProgramError::InvalidPinPath {
                    error: e.to_string(),
                })
            }
        };
        let fd =
            bpf_get_object(&path_string).map_err(|(_, io_error)| ProgramError::SyscallError {
                call: "bpf_obj_get".to_owned(),
                io_error,
            })? as RawFd;

        let info = bpf_obj_get_info_by_fd(fd).map_err(|io_error| ProgramError::SyscallError {
            call: "bpf_obj_get_info_by_fd".to_owned(),
            io_error,
        })?;

        unsafe {
            libc::close(fd);
        }

        Ok(ProgramInfo(info))
    }
}
