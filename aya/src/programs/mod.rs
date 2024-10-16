//! eBPF program types.
//!
//! eBPF programs are loaded inside the kernel and attached to one or more hook
//! points. Whenever the hook points are reached, the programs are executed.
//!
//! # Loading and attaching programs
//!
//! When you call [`Ebpf::load_file`] or [`Ebpf::load`], all the programs included
//! in the object code are parsed and relocated. Programs are not loaded
//! automatically though, since often you will need to do some application
//! specific setup before you can actually load them.
//!
//! In order to load and attach a program, you need to retrieve it using [`Ebpf::program_mut`],
//! then call the `load()` and `attach()` methods, for example:
//!
//! ```no_run
//! use aya::{Ebpf, programs::KProbe};
//!
//! let mut bpf = Ebpf::load_file("ebpf_programs.o")?;
//! // intercept_wakeups is the name of the program we want to load
//! let program: &mut KProbe = bpf.program_mut("intercept_wakeups").unwrap().try_into()?;
//! program.load()?;
//! // intercept_wakeups will be called every time try_to_wake_up() is called
//! // inside the kernel
//! program.attach("try_to_wake_up", 0)?;
//! # Ok::<(), aya::EbpfError>(())
//! ```
//!
//! The signature of the `attach()` method varies depending on what kind of
//! program you're trying to attach.
//!
//! [`Ebpf::load_file`]: crate::Ebpf::load_file
//! [`Ebpf::load`]: crate::Ebpf::load
//! [`Ebpf::programs`]: crate::Ebpf::programs
//! [`Ebpf::program`]: crate::Ebpf::program
//! [`Ebpf::program_mut`]: crate::Ebpf::program_mut
//! [`maps`]: crate::maps

// modules we don't export
mod info;
mod probe;
mod utils;

// modules we explicitly export so their pub items (Links etc) get exported too
pub mod cgroup_device;
pub mod cgroup_skb;
pub mod cgroup_sock;
pub mod cgroup_sock_addr;
pub mod cgroup_sockopt;
pub mod cgroup_sysctl;
pub mod extension;
pub mod fentry;
pub mod fexit;
pub mod kprobe;
pub mod links;
pub mod lirc_mode2;
pub mod lsm;
pub mod perf_attach;
pub mod perf_event;
pub mod raw_trace_point;
pub mod sk_lookup;
pub mod sk_msg;
pub mod sk_skb;
pub mod sock_ops;
pub mod socket_filter;
pub mod tc;
pub mod tp_btf;
pub mod trace_point;
pub mod uprobe;
pub mod xdp;

use std::{
    ffi::CString,
    io,
    os::fd::{AsFd, BorrowedFd},
    path::{Path, PathBuf},
    sync::Arc,
};

use info::impl_info;
pub use info::{loaded_programs, ProgramInfo, ProgramType};
use libc::ENOSPC;
use tc::SchedClassifierLink;
use thiserror::Error;

// re-export the main items needed to load and attach
pub use crate::programs::{
    cgroup_device::CgroupDevice,
    cgroup_skb::{CgroupSkb, CgroupSkbAttachType},
    cgroup_sock::{CgroupSock, CgroupSockAttachType},
    cgroup_sock_addr::{CgroupSockAddr, CgroupSockAddrAttachType},
    cgroup_sockopt::{CgroupSockopt, CgroupSockoptAttachType},
    cgroup_sysctl::CgroupSysctl,
    extension::{Extension, ExtensionError},
    fentry::FEntry,
    fexit::FExit,
    kprobe::{KProbe, KProbeError},
    links::{CgroupAttachMode, Link, LinkOrder},
    lirc_mode2::LircMode2,
    lsm::Lsm,
    perf_event::{PerfEvent, PerfEventScope, PerfTypeId, SamplePolicy},
    probe::ProbeKind,
    raw_trace_point::RawTracePoint,
    sk_lookup::SkLookup,
    sk_msg::SkMsg,
    sk_skb::{SkSkb, SkSkbKind},
    sock_ops::SockOps,
    socket_filter::{SocketFilter, SocketFilterError},
    tc::{SchedClassifier, TcAttachType, TcError},
    tp_btf::BtfTracePoint,
    trace_point::{TracePoint, TracePointError},
    uprobe::{UProbe, UProbeError},
    xdp::{Xdp, XdpError, XdpFlags},
};
use crate::{
    generated::{bpf_attach_type, bpf_link_info, bpf_prog_info, bpf_prog_type},
    maps::MapError,
    obj::{self, btf::BtfError, VerifierLog},
    pin::PinError,
    programs::{links::*, perf_attach::*},
    sys::{
        bpf_btf_get_fd_by_id, bpf_get_object, bpf_link_get_fd_by_id, bpf_link_get_info_by_fd,
        bpf_load_program, bpf_pin_object, bpf_prog_get_fd_by_id, bpf_prog_query, iter_link_ids,
        retry_with_verifier_logs, EbpfLoadProgramAttrs, ProgQueryTarget, SyscallError,
    },
    util::KernelVersion,
    VerifierLogLevel,
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

    /// The program is already attached.
    #[error("the program was already attached")]
    AlreadyAttached,

    /// The program is not attached.
    #[error("the program is not attached")]
    NotAttached,

    /// The program cannot be auto attached.
    #[error("the program cannot be auto attached")]
    CannotAutoAttach,

    /// Loading the program failed.
    #[error("the BPF_PROG_LOAD syscall failed. Verifier output: {verifier_log}")]
    LoadError {
        /// The [`io::Error`] returned by the `BPF_PROG_LOAD` syscall.
        #[source]
        io_error: io::Error,
        /// The error log produced by the kernel verifier.
        verifier_log: VerifierLog,
    },

    /// A syscall failed.
    #[error(transparent)]
    SyscallError(#[from] SyscallError),

    /// The network interface does not exist.
    #[error("unknown network interface {name}")]
    UnknownInterface {
        /// interface name
        name: String,
    },

    /// The program is not of the expected type.
    #[error("unexpected program type")]
    UnexpectedProgramType,

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
    InvalidName {
        /// program name
        name: String,
    },

    /// An error occurred while working with IO.
    #[error(transparent)]
    IOError(#[from] io::Error),
}

/// A [`Program`] file descriptor.
#[derive(Debug)]
pub struct ProgramFd(crate::MockableFd);

impl ProgramFd {
    /// Creates a new instance that shares the same underlying file description as [`self`].
    pub fn try_clone(&self) -> io::Result<Self> {
        let Self(inner) = self;
        let inner = inner.try_clone()?;
        Ok(Self(inner))
    }
}

impl AsFd for ProgramFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        let Self(fd) = self;
        fd.as_fd()
    }
}

/// A [`Program`] identifier.
pub struct ProgramId(u32);

impl ProgramId {
    /// Create a new program id.  
    ///  
    /// This method is unsafe since it doesn't check that the given `id` is a
    /// valid program id.
    pub unsafe fn new(id: u32) -> Self {
        Self(id)
    }
}

/// eBPF program type.
#[derive(Debug)]
pub enum Program {
    /// A [`KProbe`] program
    KProbe(KProbe),
    /// A [`UProbe`] program
    UProbe(UProbe),
    /// A [`TracePoint`] program
    TracePoint(TracePoint),
    /// A [`SocketFilter`] program
    SocketFilter(SocketFilter),
    /// A [`Xdp`] program
    Xdp(Xdp),
    /// A [`SkMsg`] program
    SkMsg(SkMsg),
    /// A [`SkSkb`] program
    SkSkb(SkSkb),
    /// A [`CgroupSockAddr`] program
    CgroupSockAddr(CgroupSockAddr),
    /// A [`SockOps`] program
    SockOps(SockOps),
    /// A [`SchedClassifier`] program
    SchedClassifier(SchedClassifier),
    /// A [`CgroupSkb`] program
    CgroupSkb(CgroupSkb),
    /// A [`CgroupSysctl`] program
    CgroupSysctl(CgroupSysctl),
    /// A [`CgroupSockopt`] program
    CgroupSockopt(CgroupSockopt),
    /// A [`LircMode2`] program
    LircMode2(LircMode2),
    /// A [`PerfEvent`] program
    PerfEvent(PerfEvent),
    /// A [`RawTracePoint`] program
    RawTracePoint(RawTracePoint),
    /// A [`Lsm`] program
    Lsm(Lsm),
    /// A [`BtfTracePoint`] program
    BtfTracePoint(BtfTracePoint),
    /// A [`FEntry`] program
    FEntry(FEntry),
    /// A [`FExit`] program
    FExit(FExit),
    /// A [`Extension`] program
    Extension(Extension),
    /// A [`SkLookup`] program
    SkLookup(SkLookup),
    /// A [`CgroupSock`] program
    CgroupSock(CgroupSock),
    /// A [`CgroupDevice`] program
    CgroupDevice(CgroupDevice),
}

impl Program {
    /// Returns the program type.
    pub fn prog_type(&self) -> ProgramType {
        match self {
            Self::KProbe(_) | Self::UProbe(_) => ProgramType::KProbe,
            Self::TracePoint(_) => ProgramType::TracePoint,
            Self::SocketFilter(_) => ProgramType::SocketFilter,
            Self::Xdp(_) => ProgramType::Xdp,
            Self::SkMsg(_) => ProgramType::SkMsg,
            Self::SkSkb(_) => ProgramType::SkSkb,
            Self::SockOps(_) => ProgramType::SockOps,
            Self::SchedClassifier(_) => ProgramType::SchedClassifier,
            Self::CgroupSkb(_) => ProgramType::CgroupSkb,
            Self::CgroupSysctl(_) => ProgramType::CgroupSysctl,
            Self::CgroupSockopt(_) => ProgramType::CgroupSockopt,
            Self::LircMode2(_) => ProgramType::LircMode2,
            Self::PerfEvent(_) => ProgramType::PerfEvent,
            Self::RawTracePoint(_) => ProgramType::RawTracePoint,
            Self::Lsm(_) => ProgramType::Lsm,
            Self::BtfTracePoint(_) | Self::FEntry(_) | Self::FExit(_) => ProgramType::Tracing,
            Self::Extension(_) => ProgramType::Extension,
            Self::CgroupSockAddr(_) => ProgramType::CgroupSockAddr,
            Self::SkLookup(_) => ProgramType::SkLookup,
            Self::CgroupSock(_) => ProgramType::CgroupSock,
            Self::CgroupDevice(_) => ProgramType::CgroupDevice,
        }
    }

    /// Pin the program to the provided path
    pub fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<(), PinError> {
        match self {
            Self::KProbe(p) => p.pin(path),
            Self::UProbe(p) => p.pin(path),
            Self::TracePoint(p) => p.pin(path),
            Self::SocketFilter(p) => p.pin(path),
            Self::Xdp(p) => p.pin(path),
            Self::SkMsg(p) => p.pin(path),
            Self::SkSkb(p) => p.pin(path),
            Self::SockOps(p) => p.pin(path),
            Self::SchedClassifier(p) => p.pin(path),
            Self::CgroupSkb(p) => p.pin(path),
            Self::CgroupSysctl(p) => p.pin(path),
            Self::CgroupSockopt(p) => p.pin(path),
            Self::LircMode2(p) => p.pin(path),
            Self::PerfEvent(p) => p.pin(path),
            Self::RawTracePoint(p) => p.pin(path),
            Self::Lsm(p) => p.pin(path),
            Self::BtfTracePoint(p) => p.pin(path),
            Self::FEntry(p) => p.pin(path),
            Self::FExit(p) => p.pin(path),
            Self::Extension(p) => p.pin(path),
            Self::CgroupSockAddr(p) => p.pin(path),
            Self::SkLookup(p) => p.pin(path),
            Self::CgroupSock(p) => p.pin(path),
            Self::CgroupDevice(p) => p.pin(path),
        }
    }

    /// Unloads the program from the kernel.
    pub fn unload(self) -> Result<(), ProgramError> {
        match self {
            Self::KProbe(mut p) => p.unload(),
            Self::UProbe(mut p) => p.unload(),
            Self::TracePoint(mut p) => p.unload(),
            Self::SocketFilter(mut p) => p.unload(),
            Self::Xdp(mut p) => p.unload(),
            Self::SkMsg(mut p) => p.unload(),
            Self::SkSkb(mut p) => p.unload(),
            Self::SockOps(mut p) => p.unload(),
            Self::SchedClassifier(mut p) => p.unload(),
            Self::CgroupSkb(mut p) => p.unload(),
            Self::CgroupSysctl(mut p) => p.unload(),
            Self::CgroupSockopt(mut p) => p.unload(),
            Self::LircMode2(mut p) => p.unload(),
            Self::PerfEvent(mut p) => p.unload(),
            Self::RawTracePoint(mut p) => p.unload(),
            Self::Lsm(mut p) => p.unload(),
            Self::BtfTracePoint(mut p) => p.unload(),
            Self::FEntry(mut p) => p.unload(),
            Self::FExit(mut p) => p.unload(),
            Self::Extension(mut p) => p.unload(),
            Self::CgroupSockAddr(mut p) => p.unload(),
            Self::SkLookup(mut p) => p.unload(),
            Self::CgroupSock(mut p) => p.unload(),
            Self::CgroupDevice(mut p) => p.unload(),
        }
    }

    /// Returns the file descriptor of a program.
    ///
    /// Can be used to add a program to a [`crate::maps::ProgramArray`] or attach an [`Extension`] program.
    pub fn fd(&self) -> Result<&ProgramFd, ProgramError> {
        match self {
            Self::KProbe(p) => p.fd(),
            Self::UProbe(p) => p.fd(),
            Self::TracePoint(p) => p.fd(),
            Self::SocketFilter(p) => p.fd(),
            Self::Xdp(p) => p.fd(),
            Self::SkMsg(p) => p.fd(),
            Self::SkSkb(p) => p.fd(),
            Self::SockOps(p) => p.fd(),
            Self::SchedClassifier(p) => p.fd(),
            Self::CgroupSkb(p) => p.fd(),
            Self::CgroupSysctl(p) => p.fd(),
            Self::CgroupSockopt(p) => p.fd(),
            Self::LircMode2(p) => p.fd(),
            Self::PerfEvent(p) => p.fd(),
            Self::RawTracePoint(p) => p.fd(),
            Self::Lsm(p) => p.fd(),
            Self::BtfTracePoint(p) => p.fd(),
            Self::FEntry(p) => p.fd(),
            Self::FExit(p) => p.fd(),
            Self::Extension(p) => p.fd(),
            Self::CgroupSockAddr(p) => p.fd(),
            Self::SkLookup(p) => p.fd(),
            Self::CgroupSock(p) => p.fd(),
            Self::CgroupDevice(p) => p.fd(),
        }
    }

    /// Returns information about a loaded program with the [`ProgramInfo`] structure.
    ///
    /// This information is populated at load time by the kernel and can be used
    /// to get kernel details for a given [`Program`].
    pub fn info(&self) -> Result<ProgramInfo, ProgramError> {
        match self {
            Self::KProbe(p) => p.info(),
            Self::UProbe(p) => p.info(),
            Self::TracePoint(p) => p.info(),
            Self::SocketFilter(p) => p.info(),
            Self::Xdp(p) => p.info(),
            Self::SkMsg(p) => p.info(),
            Self::SkSkb(p) => p.info(),
            Self::SockOps(p) => p.info(),
            Self::SchedClassifier(p) => p.info(),
            Self::CgroupSkb(p) => p.info(),
            Self::CgroupSysctl(p) => p.info(),
            Self::CgroupSockopt(p) => p.info(),
            Self::LircMode2(p) => p.info(),
            Self::PerfEvent(p) => p.info(),
            Self::RawTracePoint(p) => p.info(),
            Self::Lsm(p) => p.info(),
            Self::BtfTracePoint(p) => p.info(),
            Self::FEntry(p) => p.info(),
            Self::FExit(p) => p.info(),
            Self::Extension(p) => p.info(),
            Self::CgroupSockAddr(p) => p.info(),
            Self::SkLookup(p) => p.info(),
            Self::CgroupSock(p) => p.info(),
            Self::CgroupDevice(p) => p.info(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProgramData<T: Link> {
    pub(crate) name: Option<String>,
    pub(crate) obj: Option<(obj::Program, obj::Function)>,
    pub(crate) fd: Option<ProgramFd>,
    pub(crate) links: LinkMap<T>,
    pub(crate) expected_attach_type: Option<bpf_attach_type>,
    pub(crate) attach_btf_obj_fd: Option<crate::MockableFd>,
    pub(crate) attach_btf_id: Option<u32>,
    pub(crate) attach_prog_fd: Option<ProgramFd>,
    pub(crate) btf_fd: Option<Arc<crate::MockableFd>>,
    pub(crate) verifier_log_level: VerifierLogLevel,
    pub(crate) path: Option<PathBuf>,
    pub(crate) flags: u32,
}

impl<T: Link> ProgramData<T> {
    pub(crate) fn new(
        name: Option<String>,
        obj: (obj::Program, obj::Function),
        btf_fd: Option<Arc<crate::MockableFd>>,
        verifier_log_level: VerifierLogLevel,
    ) -> Self {
        Self {
            name,
            obj: Some(obj),
            fd: None,
            links: LinkMap::new(),
            expected_attach_type: None,
            attach_btf_obj_fd: None,
            attach_btf_id: None,
            attach_prog_fd: None,
            btf_fd,
            verifier_log_level,
            path: None,
            flags: 0,
        }
    }

    pub(crate) fn from_bpf_prog_info(
        name: Option<String>,
        fd: crate::MockableFd,
        path: &Path,
        info: bpf_prog_info,
        verifier_log_level: VerifierLogLevel,
    ) -> Result<Self, ProgramError> {
        let attach_btf_id = if info.attach_btf_id > 0 {
            Some(info.attach_btf_id)
        } else {
            None
        };
        let attach_btf_obj_fd = (info.attach_btf_obj_id != 0)
            .then(|| bpf_btf_get_fd_by_id(info.attach_btf_obj_id))
            .transpose()?;

        Ok(Self {
            name,
            obj: None,
            fd: Some(ProgramFd(fd)),
            links: LinkMap::new(),
            expected_attach_type: None,
            attach_btf_obj_fd,
            attach_btf_id,
            attach_prog_fd: None,
            btf_fd: None,
            verifier_log_level,
            path: Some(path.to_path_buf()),
            flags: 0,
        })
    }

    pub(crate) fn from_pinned_path<P: AsRef<Path>>(
        path: P,
        verifier_log_level: VerifierLogLevel,
    ) -> Result<Self, ProgramError> {
        use std::os::unix::ffi::OsStrExt as _;

        // TODO: avoid this unwrap by adding a new error variant.
        let path_string = CString::new(path.as_ref().as_os_str().as_bytes()).unwrap();
        let fd = bpf_get_object(&path_string).map_err(|(_, io_error)| SyscallError {
            call: "bpf_obj_get",
            io_error,
        })?;

        let info = ProgramInfo::new_from_fd(fd.as_fd())?;
        let name = info.name_as_str().map(|s| s.to_string());
        Self::from_bpf_prog_info(name, fd, path.as_ref(), info.0, verifier_log_level)
    }
}

impl<T: Link> ProgramData<T> {
    fn fd(&self) -> Result<&ProgramFd, ProgramError> {
        self.fd.as_ref().ok_or(ProgramError::NotLoaded)
    }

    pub(crate) fn take_link(&mut self, link_id: T::Id) -> Result<T, ProgramError> {
        self.links.forget(link_id)
    }
}

fn unload_program<T: Link>(data: &mut ProgramData<T>) -> Result<(), ProgramError> {
    data.links.remove_all()?;
    data.fd
        .take()
        .ok_or(ProgramError::NotLoaded)
        .map(|ProgramFd { .. }| ())
}

fn pin_program<T: Link, P: AsRef<Path>>(data: &ProgramData<T>, path: P) -> Result<(), PinError> {
    use std::os::unix::ffi::OsStrExt as _;

    let fd = data.fd.as_ref().ok_or(PinError::NoFd {
        name: data
            .name
            .as_deref()
            .unwrap_or("<unknown program>")
            .to_string(),
    })?;
    let path = path.as_ref();
    let path_string =
        CString::new(path.as_os_str().as_bytes()).map_err(|error| PinError::InvalidPinPath {
            path: path.into(),
            error,
        })?;
    bpf_pin_object(fd.as_fd(), &path_string).map_err(|(_, io_error)| SyscallError {
        call: "BPF_OBJ_PIN",
        io_error,
    })?;
    Ok(())
}

fn load_program<T: Link>(
    prog_type: bpf_prog_type,
    data: &mut ProgramData<T>,
) -> Result<(), ProgramError> {
    let ProgramData {
        name,
        obj,
        fd,
        links: _,
        expected_attach_type,
        attach_btf_obj_fd,
        attach_btf_id,
        attach_prog_fd,
        btf_fd,
        verifier_log_level,
        path: _,
        flags,
    } = data;
    if fd.is_some() {
        return Err(ProgramError::AlreadyLoaded);
    }
    if obj.is_none() {
        // This program was loaded from a pin in bpffs
        return Err(ProgramError::AlreadyLoaded);
    }
    let obj = obj.as_ref().unwrap();
    let (
        obj::Program {
            license,
            kernel_version,
            ..
        },
        obj::Function {
            instructions,
            func_info,
            line_info,
            func_info_rec_size,
            line_info_rec_size,
            ..
        },
    ) = obj;

    let target_kernel_version =
        kernel_version.unwrap_or_else(|| KernelVersion::current().unwrap().code());

    let prog_name = if let Some(name) = name {
        let mut name = name.clone();
        if name.len() > 15 {
            name.truncate(15);
        }
        let prog_name = CString::new(name.clone())
            .map_err(|_| ProgramError::InvalidName { name: name.clone() })?;
        Some(prog_name)
    } else {
        None
    };

    let attr = EbpfLoadProgramAttrs {
        name: prog_name,
        ty: prog_type,
        insns: instructions,
        license,
        kernel_version: target_kernel_version,
        expected_attach_type: *expected_attach_type,
        prog_btf_fd: btf_fd.as_ref().map(|f| f.as_fd()),
        attach_btf_obj_fd: attach_btf_obj_fd.as_ref().map(|fd| fd.as_fd()),
        attach_btf_id: *attach_btf_id,
        attach_prog_fd: attach_prog_fd.as_ref().map(|fd| fd.as_fd()),
        func_info_rec_size: *func_info_rec_size,
        func_info: func_info.clone(),
        line_info_rec_size: *line_info_rec_size,
        line_info: line_info.clone(),
        flags: *flags,
    };

    let (ret, verifier_log) = retry_with_verifier_logs(10, |logger| {
        bpf_load_program(&attr, logger, *verifier_log_level)
    });

    match ret {
        Ok(prog_fd) => {
            *fd = Some(ProgramFd(prog_fd));
            Ok(())
        }
        Err((_, io_error)) => Err(ProgramError::LoadError {
            io_error,
            verifier_log,
        }),
    }
}

pub(crate) fn query(
    target: ProgQueryTarget<'_>,
    attach_type: bpf_attach_type,
    query_flags: u32,
    attach_flags: &mut Option<u32>,
) -> Result<(u64, Vec<u32>), ProgramError> {
    let mut prog_ids = vec![0u32; 64];
    let mut prog_cnt = prog_ids.len() as u32;
    let mut revision = 0;

    let mut retries = 0;

    loop {
        match bpf_prog_query(
            &target,
            attach_type,
            query_flags,
            attach_flags.as_mut(),
            &mut prog_ids,
            &mut prog_cnt,
            &mut revision,
        ) {
            Ok(_) => {
                prog_ids.resize(prog_cnt as usize, 0);
                return Ok((revision, prog_ids));
            }
            Err((_, io_error)) => {
                if retries == 0 && io_error.raw_os_error() == Some(ENOSPC) {
                    prog_ids.resize(prog_cnt as usize, 0);
                    retries += 1;
                } else {
                    return Err(SyscallError {
                        call: "bpf_prog_query",
                        io_error,
                    }
                    .into());
                }
            }
        }
    }
}

macro_rules! impl_program_unload {
    ($($struct_name:ident),+ $(,)?) => {
        $(
            impl $struct_name {
                /// Unloads the program from the kernel.
                ///
                /// Links will be detached before unloading the program.  Note
                /// that owned links obtained using `take_link()` will not be
                /// detached.
                pub fn unload(&mut self) -> Result<(), ProgramError> {
                    unload_program(&mut self.data)
                }
            }

            impl Drop for $struct_name {
                fn drop(&mut self) {
                    let _ = self.unload();
                }
            }
        )+
    }
}

impl_program_unload!(
    KProbe,
    UProbe,
    TracePoint,
    SocketFilter,
    Xdp,
    SkMsg,
    SkSkb,
    SchedClassifier,
    CgroupSkb,
    CgroupSysctl,
    CgroupSockopt,
    LircMode2,
    PerfEvent,
    Lsm,
    RawTracePoint,
    BtfTracePoint,
    FEntry,
    FExit,
    Extension,
    CgroupSockAddr,
    SkLookup,
    SockOps,
    CgroupSock,
    CgroupDevice,
);

macro_rules! impl_fd {
    ($($struct_name:ident),+ $(,)?) => {
        $(
            impl $struct_name {
                /// Returns the file descriptor of this Program.
                pub fn fd(&self) -> Result<&ProgramFd, ProgramError> {
                    self.data.fd()
                }
            }
        )+
    }
}

impl_fd!(
    KProbe,
    UProbe,
    TracePoint,
    SocketFilter,
    Xdp,
    SkMsg,
    SkSkb,
    SchedClassifier,
    CgroupSkb,
    CgroupSysctl,
    CgroupSockopt,
    LircMode2,
    PerfEvent,
    Lsm,
    RawTracePoint,
    BtfTracePoint,
    FEntry,
    FExit,
    Extension,
    CgroupSockAddr,
    SkLookup,
    SockOps,
    CgroupSock,
    CgroupDevice,
);

/// Trait implemented by the [`Program`] types which support the kernel's
/// [generic multi-prog API](https://github.com/torvalds/linux/commit/053c8e1f235dc3f69d13375b32f4209228e1cb96).
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 6.6.0.
pub trait MultiProgram {
    /// Borrows the file descriptor.
    fn fd(&self) -> Result<BorrowedFd<'_>, ProgramError>;
}

macro_rules! impl_multiprog_fd {
    ($($struct_name:ident),+ $(,)?) => {
        $(
            impl MultiProgram for $struct_name {
                fn fd(&self) -> Result<BorrowedFd<'_>, ProgramError> {
                    Ok(self.fd()?.as_fd())
                }
            }
        )+
    }
}

impl_multiprog_fd!(SchedClassifier);

/// Trait implemented by the [`Link`] types which support the kernel's
/// [generic multi-prog API](https://github.com/torvalds/linux/commit/053c8e1f235dc3f69d13375b32f4209228e1cb96).
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 6.6.0.
pub trait MultiProgLink {
    /// Borrows the file descriptor.
    fn fd(&self) -> Result<BorrowedFd<'_>, LinkError>;
}

macro_rules! impl_multiproglink_fd {
    ($($struct_name:ident),+ $(,)?) => {
        $(
            impl MultiProgLink for $struct_name {
                fn fd(&self) -> Result<BorrowedFd<'_>, LinkError> {
                    let link: &FdLink = self.try_into()?;
                    Ok(link.fd.as_fd())
                }
            }
        )+
    }
}

impl_multiproglink_fd!(SchedClassifierLink);

macro_rules! impl_program_pin{
    ($($struct_name:ident),+ $(,)?) => {
        $(
            impl $struct_name {
                /// Pins the program to a BPF filesystem.
                ///
                /// When a BPF object is pinned to a BPF filesystem it will remain loaded after
                /// Aya has unloaded the program.
                /// To remove the program, the file on the BPF filesystem must be removed.
                /// Any directories in the the path provided should have been created by the caller.
                pub fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<(), PinError> {
                    self.data.path = Some(path.as_ref().to_path_buf());
                    pin_program(&self.data, path)
                }

                /// Removes the pinned link from the filesystem.
                pub fn unpin(mut self) -> Result<(), io::Error> {
                    if let Some(path) = self.data.path.take() {
                        std::fs::remove_file(path)?;
                    }
                    Ok(())
                }
            }
        )+
    }
}

impl_program_pin!(
    KProbe,
    UProbe,
    TracePoint,
    SocketFilter,
    Xdp,
    SkMsg,
    SkSkb,
    SchedClassifier,
    CgroupSkb,
    CgroupSysctl,
    CgroupSockopt,
    LircMode2,
    PerfEvent,
    Lsm,
    RawTracePoint,
    BtfTracePoint,
    FEntry,
    FExit,
    Extension,
    CgroupSockAddr,
    SkLookup,
    SockOps,
    CgroupSock,
    CgroupDevice,
);

macro_rules! impl_from_pin {
    ($($struct_name:ident),+ $(,)?) => {
        $(
            impl $struct_name {
                /// Creates a program from a pinned entry on a bpffs.
                ///
                /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
                ///
                /// On drop, any managed links are detached and the program is unloaded. This will not result in
                /// the program being unloaded from the kernel if it is still pinned.
                pub fn from_pin<P: AsRef<Path>>(path: P) -> Result<Self, ProgramError> {
                    let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
                    Ok(Self { data })
                }
            }
        )+
    }
}

// Use impl_from_pin if the program doesn't require additional data
impl_from_pin!(
    SocketFilter,
    SkMsg,
    CgroupSysctl,
    LircMode2,
    PerfEvent,
    Lsm,
    RawTracePoint,
    BtfTracePoint,
    FEntry,
    FExit,
    Extension,
    SkLookup,
    SockOps,
    CgroupDevice,
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
    CgroupSysctl,
    CgroupSockopt,
    LircMode2,
    PerfEvent,
    Lsm,
    RawTracePoint,
    BtfTracePoint,
    FEntry,
    FExit,
    Extension,
    CgroupSockAddr,
    SkLookup,
    CgroupSock,
    CgroupDevice,
);

impl_info!(
    KProbe,
    UProbe,
    TracePoint,
    SocketFilter,
    Xdp,
    SkMsg,
    SkSkb,
    SchedClassifier,
    CgroupSkb,
    CgroupSysctl,
    CgroupSockopt,
    LircMode2,
    PerfEvent,
    Lsm,
    RawTracePoint,
    BtfTracePoint,
    FEntry,
    FExit,
    Extension,
    CgroupSockAddr,
    SkLookup,
    SockOps,
    CgroupSock,
    CgroupDevice,
);

// TODO(https://github.com/aya-rs/aya/issues/645): this API is currently used in tests. Stabilize
// and remove doc(hidden).
#[doc(hidden)]
pub fn loaded_links() -> impl Iterator<Item = Result<bpf_link_info, ProgramError>> {
    iter_link_ids()
        .map(|id| {
            let id = id?;
            bpf_link_get_fd_by_id(id)
        })
        .map(|fd| {
            let fd = fd?;
            bpf_link_get_info_by_fd(fd.as_fd())
        })
        .map(|result| result.map_err(Into::into))
}
