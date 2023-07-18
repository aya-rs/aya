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
mod probe;
mod raw_trace_point;
mod sk_lookup;
mod sk_msg;
mod sk_skb;
mod sock_ops;
mod socket_filter;
pub mod tc;
pub mod tp_btf;
pub mod trace_point;
pub mod uprobe;
mod utils;
pub mod xdp;

use crate::util::KernelVersion;
use libc::ENOSPC;
use std::{
    ffi::CString,
    io,
    os::unix::io::{AsRawFd, RawFd},
    path::{Path, PathBuf},
};
use thiserror::Error;

pub use cgroup_device::CgroupDevice;
pub use cgroup_skb::{CgroupSkb, CgroupSkbAttachType};
pub use cgroup_sock::{CgroupSock, CgroupSockAttachType};
pub use cgroup_sock_addr::{CgroupSockAddr, CgroupSockAddrAttachType};
pub use cgroup_sockopt::{CgroupSockopt, CgroupSockoptAttachType};
pub use cgroup_sysctl::CgroupSysctl;
pub use extension::{Extension, ExtensionError};
pub use fentry::FEntry;
pub use fexit::FExit;
pub use kprobe::{KProbe, KProbeError};
pub use links::Link;
use links::*;
pub use lirc_mode2::LircMode2;
pub use lsm::Lsm;
use perf_attach::*;
pub use perf_event::{PerfEvent, PerfEventScope, PerfTypeId, SamplePolicy};
pub use probe::ProbeKind;
pub use raw_trace_point::RawTracePoint;
pub use sk_lookup::SkLookup;
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
    obj::{self, btf::BtfError, Function},
    pin::PinError,
    sys::{
        bpf_btf_get_fd_by_id, bpf_get_object, bpf_load_program, bpf_pin_object,
        bpf_prog_get_fd_by_id, bpf_prog_get_info_by_fd, bpf_prog_get_next_id, bpf_prog_query,
        retry_with_verifier_logs, BpfLoadProgramAttrs,
    },
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
        call: &'static str,
        /// The [`io::Error`] returned by the syscall.
        #[source]
        io_error: io::Error,
    },

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
#[derive(Copy, Clone)]
pub struct ProgramFd(RawFd);

impl AsRawFd for ProgramFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
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
            Program::CgroupSysctl(_) => BPF_PROG_TYPE_CGROUP_SYSCTL,
            Program::CgroupSockopt(_) => BPF_PROG_TYPE_CGROUP_SOCKOPT,
            Program::LircMode2(_) => BPF_PROG_TYPE_LIRC_MODE2,
            Program::PerfEvent(_) => BPF_PROG_TYPE_PERF_EVENT,
            Program::RawTracePoint(_) => BPF_PROG_TYPE_RAW_TRACEPOINT,
            Program::Lsm(_) => BPF_PROG_TYPE_LSM,
            Program::BtfTracePoint(_) => BPF_PROG_TYPE_TRACING,
            Program::FEntry(_) => BPF_PROG_TYPE_TRACING,
            Program::FExit(_) => BPF_PROG_TYPE_TRACING,
            Program::Extension(_) => BPF_PROG_TYPE_EXT,
            Program::CgroupSockAddr(_) => BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
            Program::SkLookup(_) => BPF_PROG_TYPE_SK_LOOKUP,
            Program::CgroupSock(_) => BPF_PROG_TYPE_CGROUP_SOCK,
            Program::CgroupDevice(_) => BPF_PROG_TYPE_CGROUP_DEVICE,
        }
    }

    /// Pin the program to the provided path
    pub fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<(), PinError> {
        match self {
            Program::KProbe(p) => p.pin(path),
            Program::UProbe(p) => p.pin(path),
            Program::TracePoint(p) => p.pin(path),
            Program::SocketFilter(p) => p.pin(path),
            Program::Xdp(p) => p.pin(path),
            Program::SkMsg(p) => p.pin(path),
            Program::SkSkb(p) => p.pin(path),
            Program::SockOps(p) => p.pin(path),
            Program::SchedClassifier(p) => p.pin(path),
            Program::CgroupSkb(p) => p.pin(path),
            Program::CgroupSysctl(p) => p.pin(path),
            Program::CgroupSockopt(p) => p.pin(path),
            Program::LircMode2(p) => p.pin(path),
            Program::PerfEvent(p) => p.pin(path),
            Program::RawTracePoint(p) => p.pin(path),
            Program::Lsm(p) => p.pin(path),
            Program::BtfTracePoint(p) => p.pin(path),
            Program::FEntry(p) => p.pin(path),
            Program::FExit(p) => p.pin(path),
            Program::Extension(p) => p.pin(path),
            Program::CgroupSockAddr(p) => p.pin(path),
            Program::SkLookup(p) => p.pin(path),
            Program::CgroupSock(p) => p.pin(path),
            Program::CgroupDevice(p) => p.pin(path),
        }
    }

    /// Unloads the program from the kernel.
    pub fn unload(self) -> Result<(), ProgramError> {
        match self {
            Program::KProbe(mut p) => p.unload(),
            Program::UProbe(mut p) => p.unload(),
            Program::TracePoint(mut p) => p.unload(),
            Program::SocketFilter(mut p) => p.unload(),
            Program::Xdp(mut p) => p.unload(),
            Program::SkMsg(mut p) => p.unload(),
            Program::SkSkb(mut p) => p.unload(),
            Program::SockOps(mut p) => p.unload(),
            Program::SchedClassifier(mut p) => p.unload(),
            Program::CgroupSkb(mut p) => p.unload(),
            Program::CgroupSysctl(mut p) => p.unload(),
            Program::CgroupSockopt(mut p) => p.unload(),
            Program::LircMode2(mut p) => p.unload(),
            Program::PerfEvent(mut p) => p.unload(),
            Program::RawTracePoint(mut p) => p.unload(),
            Program::Lsm(mut p) => p.unload(),
            Program::BtfTracePoint(mut p) => p.unload(),
            Program::FEntry(mut p) => p.unload(),
            Program::FExit(mut p) => p.unload(),
            Program::Extension(mut p) => p.unload(),
            Program::CgroupSockAddr(mut p) => p.unload(),
            Program::SkLookup(mut p) => p.unload(),
            Program::CgroupSock(mut p) => p.unload(),
            Program::CgroupDevice(mut p) => p.unload(),
        }
    }

    /// Returns the file descriptor of a program.
    ///
    /// Can be used to add a program to a [`crate::maps::ProgramArray`] or attach an [`Extension`] program.
    /// Can be converted to [`RawFd`] using [`AsRawFd`].
    pub fn fd(&self) -> Option<ProgramFd> {
        match self {
            Program::KProbe(p) => p.fd(),
            Program::UProbe(p) => p.fd(),
            Program::TracePoint(p) => p.fd(),
            Program::SocketFilter(p) => p.fd(),
            Program::Xdp(p) => p.fd(),
            Program::SkMsg(p) => p.fd(),
            Program::SkSkb(p) => p.fd(),
            Program::SockOps(p) => p.fd(),
            Program::SchedClassifier(p) => p.fd(),
            Program::CgroupSkb(p) => p.fd(),
            Program::CgroupSysctl(p) => p.fd(),
            Program::CgroupSockopt(p) => p.fd(),
            Program::LircMode2(p) => p.fd(),
            Program::PerfEvent(p) => p.fd(),
            Program::RawTracePoint(p) => p.fd(),
            Program::Lsm(p) => p.fd(),
            Program::BtfTracePoint(p) => p.fd(),
            Program::FEntry(p) => p.fd(),
            Program::FExit(p) => p.fd(),
            Program::Extension(p) => p.fd(),
            Program::CgroupSockAddr(p) => p.fd(),
            Program::SkLookup(p) => p.fd(),
            Program::CgroupSock(p) => p.fd(),
            Program::CgroupDevice(p) => p.fd(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProgramData<T: Link> {
    pub(crate) name: Option<String>,
    pub(crate) obj: Option<(obj::Program, obj::Function)>,
    pub(crate) fd: Option<RawFd>,
    pub(crate) links: LinkMap<T>,
    pub(crate) expected_attach_type: Option<bpf_attach_type>,
    pub(crate) attach_btf_obj_fd: Option<u32>,
    pub(crate) attach_btf_id: Option<u32>,
    pub(crate) attach_prog_fd: Option<RawFd>,
    pub(crate) btf_fd: Option<RawFd>,
    pub(crate) verifier_log_level: VerifierLogLevel,
    pub(crate) path: Option<PathBuf>,
    pub(crate) flags: u32,
}

impl<T: Link> ProgramData<T> {
    pub(crate) fn new(
        name: Option<String>,
        obj: (obj::Program, obj::Function),
        btf_fd: Option<RawFd>,
        verifier_log_level: VerifierLogLevel,
    ) -> ProgramData<T> {
        ProgramData {
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
        fd: RawFd,
        path: &Path,
        info: bpf_prog_info,
        verifier_log_level: VerifierLogLevel,
    ) -> Result<ProgramData<T>, ProgramError> {
        let attach_btf_id = if info.attach_btf_id > 0 {
            Some(info.attach_btf_id)
        } else {
            None
        };
        let attach_btf_obj_fd = if info.attach_btf_obj_id > 0 {
            let fd = bpf_btf_get_fd_by_id(info.attach_btf_obj_id).map_err(|io_error| {
                ProgramError::SyscallError {
                    call: "bpf_btf_get_fd_by_id",
                    io_error,
                }
            })?;
            Some(fd as u32)
        } else {
            None
        };

        Ok(ProgramData {
            name,
            obj: None,
            fd: Some(fd),
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
    ) -> Result<ProgramData<T>, ProgramError> {
        let path_string =
            CString::new(path.as_ref().as_os_str().to_string_lossy().as_bytes()).unwrap();
        let fd =
            bpf_get_object(&path_string).map_err(|(_, io_error)| ProgramError::SyscallError {
                call: "bpf_obj_get",
                io_error,
            })? as RawFd;

        let info = bpf_prog_get_info_by_fd(fd).map_err(|io_error| ProgramError::SyscallError {
            call: "bpf_prog_get_info_by_fd",
            io_error,
        })?;

        let name = ProgramInfo(info).name_as_str().map(|s| s.to_string());
        ProgramData::from_bpf_prog_info(name, fd, path.as_ref(), info, verifier_log_level)
    }
}

impl<T: Link> ProgramData<T> {
    fn fd_or_err(&self) -> Result<RawFd, ProgramError> {
        self.fd.ok_or(ProgramError::NotLoaded)
    }

    pub(crate) fn take_link(&mut self, link_id: T::Id) -> Result<T, ProgramError> {
        self.links.forget(link_id)
    }
}

fn unload_program<T: Link>(data: &mut ProgramData<T>) -> Result<(), ProgramError> {
    data.links.remove_all()?;
    let fd = data.fd.take().ok_or(ProgramError::NotLoaded)?;
    unsafe {
        libc::close(fd);
    }
    Ok(())
}

fn pin_program<T: Link, P: AsRef<Path>>(data: &ProgramData<T>, path: P) -> Result<(), PinError> {
    let fd = data.fd.ok_or(PinError::NoFd {
        name: data
            .name
            .as_deref()
            .unwrap_or("<unknown program>")
            .to_string(),
    })?;
    let path_string = CString::new(path.as_ref().to_string_lossy().into_owned()).map_err(|e| {
        PinError::InvalidPinPath {
            error: e.to_string(),
        }
    })?;
    bpf_pin_object(fd, &path_string).map_err(|(_, io_error)| PinError::SyscallError {
        name: "BPF_OBJ_PIN",
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
        crate::obj::Program {
            license,
            kernel_version,
            ..
        },
        Function {
            instructions,
            func_info,
            line_info,
            func_info_rec_size,
            line_info_rec_size,
            ..
        },
    ) = obj;

    let target_kernel_version = kernel_version.unwrap_or_else(|| {
        let KernelVersion {
            major,
            minor,
            patch,
        } = KernelVersion::current().unwrap();
        (u32::from(major) << 16) + (u32::from(minor) << 8) + u32::from(patch)
    });

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

    let attr = BpfLoadProgramAttrs {
        name: prog_name,
        ty: prog_type,
        insns: instructions,
        license,
        kernel_version: target_kernel_version,
        expected_attach_type: *expected_attach_type,
        prog_btf_fd: *btf_fd,
        attach_btf_obj_fd: *attach_btf_obj_fd,
        attach_btf_id: *attach_btf_id,
        attach_prog_fd: *attach_prog_fd,
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
            *fd = Some(prog_fd as RawFd);
            Ok(())
        }
        Err((_, io_error)) => Err(ProgramError::LoadError {
            io_error,
            verifier_log,
        }),
    }
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
                    call: "bpf_prog_query",
                    io_error,
                });
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
                pub fn fd(&self) -> Option<ProgramFd> {
                    self.data.fd.map(|fd| ProgramFd(fd))
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
    TracePoint,
    SocketFilter,
    Xdp,
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

/// Provides information about a loaded program, like name, id and statistics
#[derive(Debug)]
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
                call: "bpf_prog_get_fd_by_id",
                io_error,
            })?;
        Ok(fd as RawFd)
    }

    /// Loads a program from a pinned path in bpffs.
    pub fn from_pin<P: AsRef<Path>>(path: P) -> Result<ProgramInfo, ProgramError> {
        let path_string = CString::new(path.as_ref().to_str().unwrap()).unwrap();
        let fd =
            bpf_get_object(&path_string).map_err(|(_, io_error)| ProgramError::SyscallError {
                call: "BPF_OBJ_GET",
                io_error,
            })? as RawFd;

        let info = bpf_prog_get_info_by_fd(fd).map_err(|io_error| ProgramError::SyscallError {
            call: "bpf_prog_get_info_by_fd",
            io_error,
        })?;
        unsafe {
            libc::close(fd);
        }
        Ok(ProgramInfo(info))
    }
}

/// ProgramsIter is an Iterator over loaded eBPF programs.
pub struct ProgramsIter {
    current: u32,
    error: bool,
}

impl Iterator for ProgramsIter {
    type Item = Result<ProgramInfo, ProgramError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.error {
            return None;
        }
        let current = self.current;

        match bpf_prog_get_next_id(current) {
            Ok(Some(next)) => {
                self.current = next;
                Some(
                    bpf_prog_get_fd_by_id(next)
                        .map_err(|io_error| ProgramError::SyscallError {
                            call: "bpf_prog_get_fd_by_id",
                            io_error,
                        })
                        .and_then(|fd| {
                            let info = bpf_prog_get_info_by_fd(fd)
                                .map_err(|io_error| ProgramError::SyscallError {
                                    call: "bpf_prog_get_info_by_fd",
                                    io_error,
                                })
                                .map(ProgramInfo);
                            unsafe { libc::close(fd) };
                            info
                        }),
                )
            }
            Ok(None) => None,
            Err((_, io_error)) => {
                // If getting the next program failed, we have to yield None in our next
                // iteration to avoid an infinite loop.
                self.error = true;
                Some(Err(ProgramError::SyscallError {
                    call: "bpf_prog_get_fd_by_id",
                    io_error,
                }))
            }
        }
    }
}

/// Returns an iterator over all loaded bpf programs.
///
/// This differs from [`crate::Bpf::programs`] since it will return all programs
/// listed on the host system and not only programs a specific [`crate::Bpf`] instance.
///
/// # Example
/// ```
/// # use aya::programs::loaded_programs;
///
/// for p in loaded_programs() {
///     match p {
///         Ok(program) => println!("{}", String::from_utf8_lossy(program.name())),
///         Err(e) => println!("Error iterating programs: {:?}", e),
///     }
/// }
/// ```
///
/// # Errors
///
/// Returns [`ProgramError::SyscallError`] if any of the syscalls required to either get
/// next program id, get the program fd, or the [`ProgramInfo`] fail. In cases where
/// iteration can't be performed, for example the caller does not have the necessary privileges,
/// a single item will be yielded containing the error that occurred.
pub fn loaded_programs() -> ProgramsIter {
    ProgramsIter {
        current: 0,
        error: false,
    }
}
