//! Metadata information about an eBPF program.

use std::{
    ffi::CString,
    os::fd::{AsFd as _, BorrowedFd},
    path::Path,
    sync::OnceLock,
    time::{Duration, SystemTime},
};

use aya_obj::generated::{bpf_prog_info, bpf_prog_type};

use super::{
    ProgramError, ProgramFd,
    utils::{boot_time, get_fdinfo},
};
use crate::{
    FEATURES,
    sys::{
        SyscallError, bpf_get_object, bpf_prog_get_fd_by_id, bpf_prog_get_info_by_fd,
        feature_probe::{is_prog_info_license_supported, is_prog_info_map_ids_supported},
        iter_prog_ids,
    },
    util::bytes_of_bpf_name,
};

/// Provides metadata information about a loaded eBPF program.
///
/// Introduced in kernel v4.13.
#[doc(alias = "bpf_prog_info")]
#[derive(Debug)]
pub struct ProgramInfo(pub(crate) bpf_prog_info);

impl ProgramInfo {
    pub(crate) fn new_from_fd(fd: BorrowedFd<'_>) -> Result<Self, ProgramError> {
        let info = bpf_prog_get_info_by_fd(fd, &mut [])?;
        Ok(Self(info))
    }

    /// The type of program.
    ///
    /// Introduced in kernel v4.13.
    pub fn program_type(&self) -> bpf_prog_type {
        bpf_prog_type::try_from(self.0.type_).unwrap_or(bpf_prog_type::__MAX_BPF_PROG_TYPE)
    }

    /// The unique ID for this program.
    ///
    /// Introduced in kernel v4.13.
    pub fn id(&self) -> u32 {
        self.0.id
    }

    /// The program tag.
    ///
    /// The tag is a SHA sum of the program's instructions which be used as an alternative to
    /// [`Self::id()`]. A program's ID can vary every time it's loaded or unloaded, but the tag
    /// will remain the same.
    ///
    /// Introduced in kernel v4.13.
    pub fn tag(&self) -> u64 {
        u64::from_be_bytes(self.0.tag)
    }

    /// The size in bytes of the program's JIT-compiled machine code.
    ///
    /// Note that this field is only updated when BPF JIT compiler is enabled. Kernels v4.15 and
    /// above may already have it enabled by default.
    ///
    /// Introduced in kernel v4.13.
    pub fn size_jitted(&self) -> u32 {
        self.0.jited_prog_len
    }

    /// The size in bytes of the program's translated eBPF bytecode.
    ///
    /// The translated bytecode is after it has been passed though the verifier where it was
    /// possibly modified by the kernel.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.15.
    pub fn size_translated(&self) -> Option<u32> {
        (self.0.xlated_prog_len > 0).then_some(self.0.xlated_prog_len)
    }

    /// The time when the program was loaded.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.15.
    pub fn loaded_at(&self) -> Option<SystemTime> {
        (self.0.load_time > 0).then_some(boot_time() + Duration::from_nanos(self.0.load_time))
    }

    /// The user ID of the process who loaded the program.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.15.
    pub fn created_by_uid(&self) -> Option<u32> {
        // This field was introduced in the same commit as `load_time`.
        (self.0.load_time > 0).then_some(self.0.created_by_uid)
    }

    /// The IDs of the maps used by the program.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.15.
    pub fn map_ids(&self) -> Result<Option<Vec<u32>>, ProgramError> {
        static CACHE: OnceLock<bool> = OnceLock::new();
        CACHE
            .get_or_init(|| {
                self.0.nr_map_ids > 0 || matches!(is_prog_info_map_ids_supported(), Ok(true))
            })
            .then(|| {
                let mut map_ids = vec![0u32; self.0.nr_map_ids as usize];
                bpf_prog_get_info_by_fd(self.fd()?.as_fd(), &mut map_ids)?;
                Ok(map_ids)
            })
            .transpose()
    }

    /// The name of the program as was provided when it was load. This is limited to 16 bytes.
    ///
    /// Introduced in kernel v4.15.
    pub fn name(&self) -> &[u8] {
        bytes_of_bpf_name(&self.0.name)
    }

    /// The name of the program as a &str.
    ///
    /// `None` is returned if the name was not valid unicode or if field is not available.
    ///
    /// Introduced in kernel v4.15.
    pub fn name_as_str(&self) -> Option<&str> {
        let name = std::str::from_utf8(self.name()).ok()?;
        (FEATURES.bpf_name() || !name.is_empty()).then_some(name)
    }

    /// Returns true if the program is defined with a GPL-compatible license.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.18.
    pub fn gpl_compatible(&self) -> Option<bool> {
        static CACHE: OnceLock<bool> = OnceLock::new();
        CACHE
            .get_or_init(|| {
                self.0.gpl_compatible() != 0 || matches!(is_prog_info_license_supported(), Ok(true))
            })
            .then_some(self.0.gpl_compatible() != 0)
    }

    /// The BTF ID for the program.
    ///
    /// Introduced in kernel v5.0.
    pub fn btf_id(&self) -> Option<u32> {
        (self.0.btf_id > 0).then_some(self.0.btf_id)
    }

    /// The accumulated time that the program has been actively running.
    ///
    /// This is not to be confused with the duration since the program was
    /// first loaded on the host.
    ///
    /// Note this field is only updated for as long as
    /// [`enable_stats`](crate::sys::enable_stats) is enabled
    /// with [`Stats::RunTime`](crate::sys::Stats::RunTime).
    ///
    /// Introduced in kernel v5.1.
    pub fn run_time(&self) -> Duration {
        Duration::from_nanos(self.0.run_time_ns)
    }

    /// The accumulated execution count of the program.
    ///
    /// Note this field is only updated for as long as
    /// [`enable_stats`](crate::sys::enable_stats) is enabled
    /// with [`Stats::RunTime`](crate::sys::Stats::RunTime).
    ///
    /// Introduced in kernel v5.1.
    pub fn run_count(&self) -> u64 {
        self.0.run_cnt
    }

    /// The number of verified instructions in the program.
    ///
    /// This may be less than the total number of instructions in the compiled program due to dead
    /// code elimination in the verifier.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v5.16.
    pub fn verified_instruction_count(&self) -> Option<u32> {
        (self.0.verified_insns > 0).then_some(self.0.verified_insns)
    }

    /// How much memory in bytes has been allocated and locked for the program.
    pub fn memory_locked(&self) -> Result<u32, ProgramError> {
        get_fdinfo(self.fd()?.as_fd(), "memlock")
    }

    /// Returns a file descriptor referencing the program.
    ///
    /// The returned file descriptor can be closed at any time and doing so does
    /// not influence the life cycle of the program.
    ///
    /// Uses kernel v4.13 features.
    pub fn fd(&self) -> Result<ProgramFd, ProgramError> {
        let Self(info) = self;
        let fd = bpf_prog_get_fd_by_id(info.id)?;
        Ok(ProgramFd(fd))
    }

    /// Loads a program from a pinned path in bpffs.
    ///
    /// Uses kernel v4.4 and v4.13 features.
    pub fn from_pin<P: AsRef<Path>>(path: P) -> Result<Self, ProgramError> {
        use std::os::unix::ffi::OsStrExt as _;

        // TODO: avoid this unwrap by adding a new error variant.
        let path_string = CString::new(path.as_ref().as_os_str().as_bytes()).unwrap();
        let fd = bpf_get_object(&path_string).map_err(|io_error| SyscallError {
            call: "BPF_OBJ_GET",
            io_error,
        })?;

        Self::new_from_fd(fd.as_fd())
    }
}

/// Returns information about a loaded program with the [`ProgramInfo`] structure.
///
/// This information is populated at load time by the kernel and can be used
/// to correlate a given [`crate::programs::Program`] to it's corresponding [`ProgramInfo`]
/// metadata.
macro_rules! impl_info {
    ($($struct_name:ident),+ $(,)?) => {
        $(
            impl $struct_name {
                /// Returns metadata information of this program.
                ///
                /// Uses kernel v4.13 features.
                pub fn info(&self) -> Result<ProgramInfo, ProgramError> {
                    let ProgramFd(fd) = self.fd()?;
                    ProgramInfo::new_from_fd(fd.as_fd())
                }
            }
        )+
    }
}

pub(crate) use impl_info;

/// Returns an iterator of [`ProgramInfo`] over all eBPF programs loaded on the host.
///
/// Unlike [`Ebpf::programs`](crate::Ebpf::programs), this includes **all** programs on the host
/// system, not just those tied to a specific [`crate::Ebpf`] instance.
///
/// Uses kernel v4.13 features.
///
/// # Example
/// ```
/// # use aya::programs::loaded_programs;
/// #
/// for p in loaded_programs() {
///     match p {
///         Ok(program) => println!("{}", String::from_utf8_lossy(program.name())),
///         Err(e) => println!("error iterating programs: {:?}", e),
///     }
/// }
/// ```
///
/// # Errors
///
/// Returns [`ProgramError::SyscallError`] if any of the syscalls required to either get
/// next program id, get the program fd, or the [`ProgramInfo`] fail.
///
/// In cases where iteration can't be performed, for example the caller does not have the necessary
/// privileges, a single item will be yielded containing the error that occurred.
pub fn loaded_programs() -> impl Iterator<Item = Result<ProgramInfo, ProgramError>> {
    iter_prog_ids()
        .map(|id| {
            let id = id?;
            bpf_prog_get_fd_by_id(id)
        })
        .map(|fd| {
            let fd = fd?;
            bpf_prog_get_info_by_fd(fd.as_fd(), &mut [])
        })
        .map(|result| result.map(ProgramInfo).map_err(Into::into))
}

/// The type of LSM program.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LsmAttachType {
    /// A MAC (Mandatory Access Control) LSM program.
    Mac,
    /// A cGroup LSM program.
    Cgroup,
}

/// The type of eBPF program.
#[non_exhaustive]
#[doc(alias = "bpf_prog_type")]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProgramType {
    /// An unspecified program type.
    #[doc(alias = "BPF_PROG_TYPE_UNSPEC")]
    Unspecified,
    /// A Socket Filter program type. See [`SocketFilter`](super::socket_filter::SocketFilter)
    /// for the program implementation.
    ///
    /// Introduced in kernel v3.19.
    #[doc(alias = "BPF_PROG_TYPE_SOCKET_FILTER")]
    SocketFilter,
    /// A Kernel Probe program type. See [`KProbe`](super::kprobe::KProbe) and
    /// [`UProbe`](super::uprobe::UProbe) for the program implementations.
    ///
    /// Introduced in kernel v4.1.
    #[doc(alias = "BPF_PROG_TYPE_KPROBE")]
    KProbe,
    /// A Traffic Control (TC) Classifier program type. See
    /// [`SchedClassifier`](super::tc::SchedClassifier) for the program implementation.
    ///
    /// Introduced in kernel v4.1.
    #[doc(alias = "BPF_PROG_TYPE_SCHED_CLS")]
    SchedClassifier,
    /// A Traffic Control (TC) Action program type.
    ///
    /// Introduced in kernel v4.1.
    #[doc(alias = "BPF_PROG_TYPE_SCHED_ACT")]
    SchedAction,
    /// A Tracepoint program type. See [`TracePoint`](super::trace_point::TracePoint) for the
    /// program implementation.
    ///
    /// Introduced in kernel v4.7.
    #[doc(alias = "BPF_PROG_TYPE_TRACEPOINT")]
    TracePoint,
    /// An Express Data Path (XDP) program type. See [`Xdp`](super::xdp::Xdp) for the program
    /// implementation.
    ///
    /// Introduced in kernel v4.8.
    #[doc(alias = "BPF_PROG_TYPE_XDP")]
    Xdp,
    /// A Perf Event program type. See [`PerfEvent`](super::perf_event::PerfEvent) for the program
    /// implementation.
    ///
    /// Introduced in kernel v4.9.
    #[doc(alias = "BPF_PROG_TYPE_PERF_EVENT")]
    PerfEvent,
    /// A cGroup Socket Buffer program type. See [`CgroupSkb`](super::cgroup_skb::CgroupSkb) for
    /// the program implementation.
    ///
    /// Introduced in kernel v4.10.
    #[doc(alias = "BPF_PROG_TYPE_CGROUP_SKB")]
    CgroupSkb,
    /// A cGroup Socket program type. See [`CgroupSock`](super::cgroup_sock::CgroupSock) for the
    /// program implementation.
    ///
    /// Introduced in kernel v4.10.
    #[doc(alias = "BPF_PROG_TYPE_CGROUP_SOCK")]
    CgroupSock,
    /// A Lightweight Tunnel (LWT) Input program type.
    ///
    /// Introduced in kernel v4.10.
    #[doc(alias = "BPF_PROG_TYPE_LWT_IN")]
    LwtInput,
    /// A Lightweight Tunnel (LWT) Output program type.
    ///
    /// Introduced in kernel v4.10.
    #[doc(alias = "BPF_PROG_TYPE_LWT_OUT")]
    LwtOutput,
    /// A Lightweight Tunnel (LWT) Transmit program type.
    ///
    /// Introduced in kernel v4.10.
    #[doc(alias = "BPF_PROG_TYPE_LWT_XMIT")]
    LwtXmit,
    /// A Socket Operation program type. See [`SockOps`](super::sock_ops::SockOps) for the program
    /// implementation.
    ///
    /// Introduced in kernel v4.13.
    #[doc(alias = "BPF_PROG_TYPE_SOCK_OPS")]
    SockOps,
    /// A Socket-to-Socket Buffer program type. See [`SkSkb`](super::sk_skb::SkSkb) for the program
    /// implementation.
    ///
    /// Introduced in kernel v4.14.
    #[doc(alias = "BPF_PROG_TYPE_SK_SKB")]
    SkSkb,
    /// A cGroup Device program type. See [`CgroupDevice`](super::cgroup_device::CgroupDevice)
    /// for the program implementation.
    ///
    /// Introduced in kernel v4.15.
    #[doc(alias = "BPF_PROG_TYPE_CGROUP_DEVICE")]
    CgroupDevice,
    /// A Socket Message program type. See [`SkMsg`](super::sk_msg::SkMsg) for the program
    /// implementation.
    ///
    /// Introduced in kernel v4.17.
    #[doc(alias = "BPF_PROG_TYPE_SK_MSG")]
    SkMsg,
    /// A Raw Tracepoint program type. See [`RawTracePoint`](super::raw_trace_point::RawTracePoint)
    /// for the program implementation.
    ///
    /// Introduced in kernel v4.17.
    #[doc(alias = "BPF_PROG_TYPE_RAW_TRACEPOINT")]
    RawTracePoint,
    /// A cGroup Socket Address program type. See
    /// [`CgroupSockAddr`](super::cgroup_sock_addr::CgroupSockAddr) for the program implementation.
    ///
    /// Introduced in kernel v4.17.
    #[doc(alias = "BPF_PROG_TYPE_CGROUP_SOCK_ADDR")]
    CgroupSockAddr,
    /// A Lightweight Tunnel (LWT) Seg6local program type.
    ///
    /// Introduced in kernel v4.18.
    #[doc(alias = "BPF_PROG_TYPE_LWT_SEG6LOCAL")]
    LwtSeg6local,
    /// A Linux Infrared Remote Control (LIRC) Mode2 program type. See
    /// [`LircMode2`](super::lirc_mode2::LircMode2) for the program implementation.
    ///
    /// Introduced in kernel v4.18.
    #[doc(alias = "BPF_PROG_TYPE_LIRC_MODE2")]
    LircMode2,
    /// A Socket Reuseport program type.
    ///
    /// Introduced in kernel v4.19.
    #[doc(alias = "BPF_PROG_TYPE_SK_REUSEPORT")]
    SkReuseport,
    /// A Flow Dissector program type.
    ///
    /// Introduced in kernel v4.20.
    #[doc(alias = "BPF_PROG_TYPE_FLOW_DISSECTOR")]
    FlowDissector,
    /// A cGroup Sysctl program type. See [`CgroupSysctl`](super::cgroup_sysctl::CgroupSysctl) for
    /// the program implementation.
    ///
    /// Introduced in kernel v5.2.
    #[doc(alias = "BPF_PROG_TYPE_CGROUP_SYSCTL")]
    CgroupSysctl,
    /// A Writable Raw Tracepoint program type.
    ///
    /// Introduced in kernel v5.2.
    #[doc(alias = "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE")]
    RawTracePointWritable,
    /// A cGroup Socket Option program type. See [`CgroupSockopt`](super::cgroup_sockopt::CgroupSockopt)
    /// for the program implementation.
    ///
    /// Introduced in kernel v5.3.
    #[doc(alias = "BPF_PROG_TYPE_CGROUP_SOCKOPT")]
    CgroupSockopt,
    /// A Tracing program type. See [`FEntry`](super::fentry::FEntry), [`FExit`](super::fexit::FExit),
    /// and [`BtfTracePoint`](super::tp_btf::BtfTracePoint) for the program implementations.
    ///
    /// Introduced in kernel v5.5.
    #[doc(alias = "BPF_PROG_TYPE_TRACING")]
    Tracing,
    /// A Struct Ops program type.
    ///
    /// Introduced in kernel v5.6.
    #[doc(alias = "BPF_PROG_TYPE_STRUCT_OPS")]
    StructOps,
    /// A Extension program type. See [`Extension`](super::extension::Extension) for the program
    /// implementation.
    ///
    /// Introduced in kernel v5.6.
    #[doc(alias = "BPF_PROG_TYPE_EXT")]
    Extension,
    /// A Linux Security Module (LSM) program type. See [`Lsm`](super::lsm::Lsm) for the program
    /// implementation.
    ///
    /// Introduced in kernel v5.7.
    #[doc(alias = "BPF_PROG_TYPE_LSM")]
    Lsm(LsmAttachType),
    /// A Socket Lookup program type. See [`SkLookup`](super::sk_lookup::SkLookup) for the program
    /// implementation.
    ///
    /// Introduced in kernel v5.9.
    #[doc(alias = "BPF_PROG_TYPE_SK_LOOKUP")]
    SkLookup,
    /// A Syscall program type.
    ///
    /// Introduced in kernel v5.14.
    #[doc(alias = "BPF_PROG_TYPE_SYSCALL")]
    Syscall,
    /// A Netfilter program type.
    ///
    /// Introduced in kernel v6.4.
    #[doc(alias = "BPF_PROG_TYPE_NETFILTER")]
    Netfilter,
}

impl From<ProgramType> for bpf_prog_type {
    fn from(value: ProgramType) -> Self {
        match value {
            ProgramType::Unspecified => Self::BPF_PROG_TYPE_UNSPEC,
            ProgramType::SocketFilter => Self::BPF_PROG_TYPE_SOCKET_FILTER,
            ProgramType::KProbe => Self::BPF_PROG_TYPE_KPROBE,
            ProgramType::SchedClassifier => Self::BPF_PROG_TYPE_SCHED_CLS,
            ProgramType::SchedAction => Self::BPF_PROG_TYPE_SCHED_ACT,
            ProgramType::TracePoint => Self::BPF_PROG_TYPE_TRACEPOINT,
            ProgramType::Xdp => Self::BPF_PROG_TYPE_XDP,
            ProgramType::PerfEvent => Self::BPF_PROG_TYPE_PERF_EVENT,
            ProgramType::CgroupSkb => Self::BPF_PROG_TYPE_CGROUP_SKB,
            ProgramType::CgroupSock => Self::BPF_PROG_TYPE_CGROUP_SOCK,
            ProgramType::LwtInput => Self::BPF_PROG_TYPE_LWT_IN,
            ProgramType::LwtOutput => Self::BPF_PROG_TYPE_LWT_OUT,
            ProgramType::LwtXmit => Self::BPF_PROG_TYPE_LWT_XMIT,
            ProgramType::SockOps => Self::BPF_PROG_TYPE_SOCK_OPS,
            ProgramType::SkSkb => Self::BPF_PROG_TYPE_SK_SKB,
            ProgramType::CgroupDevice => Self::BPF_PROG_TYPE_CGROUP_DEVICE,
            ProgramType::SkMsg => Self::BPF_PROG_TYPE_SK_MSG,
            ProgramType::RawTracePoint => Self::BPF_PROG_TYPE_RAW_TRACEPOINT,
            ProgramType::CgroupSockAddr => Self::BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
            ProgramType::LwtSeg6local => Self::BPF_PROG_TYPE_LWT_SEG6LOCAL,
            ProgramType::LircMode2 => Self::BPF_PROG_TYPE_LIRC_MODE2,
            ProgramType::SkReuseport => Self::BPF_PROG_TYPE_SK_REUSEPORT,
            ProgramType::FlowDissector => Self::BPF_PROG_TYPE_FLOW_DISSECTOR,
            ProgramType::CgroupSysctl => Self::BPF_PROG_TYPE_CGROUP_SYSCTL,
            ProgramType::RawTracePointWritable => Self::BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
            ProgramType::CgroupSockopt => Self::BPF_PROG_TYPE_CGROUP_SOCKOPT,
            ProgramType::Tracing => Self::BPF_PROG_TYPE_TRACING,
            ProgramType::StructOps => Self::BPF_PROG_TYPE_STRUCT_OPS,
            ProgramType::Extension => Self::BPF_PROG_TYPE_EXT,
            ProgramType::Lsm(_) => Self::BPF_PROG_TYPE_LSM,
            ProgramType::SkLookup => Self::BPF_PROG_TYPE_SK_LOOKUP,
            ProgramType::Syscall => Self::BPF_PROG_TYPE_SYSCALL,
            ProgramType::Netfilter => Self::BPF_PROG_TYPE_NETFILTER,
        }
    }
}
