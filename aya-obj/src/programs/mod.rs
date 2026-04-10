//! Program struct and type bindings.

use crate::generated::bpf_prog_type;

pub mod cgroup_skb;
pub mod cgroup_sock;
pub mod cgroup_sock_addr;
pub mod cgroup_sockopt;
pub mod sk_skb;
mod types;
pub mod xdp;

pub use cgroup_skb::CgroupSkbAttachType;
pub use cgroup_sock::CgroupSockAttachType;
pub use cgroup_sock_addr::CgroupSockAddrAttachType;
pub use cgroup_sockopt::CgroupSockoptAttachType;
pub use sk_skb::SkSkbKind;
pub use xdp::XdpAttachType;

/// The type of BPF program
#[derive(Copy, Clone, Debug)]
pub enum BpfProgType {
    /// Not Specified
    Unspecified,
    /// Socket Filter
    SocketFilter,
    /// Kprobe
    Kprobe,
    /// Sched Cls
    SchedCls,
    /// Sched Act
    SchedAct,
    /// Tracepoint
    Tracepoint,
    /// XDP
    Xdp,
    /// Perf Event
    PerfEvent,
    /// Cgroup Skb
    CgroupSkb,
    /// Cgroup Sock
    CgroupSock,
    /// Lwt In
    LwtIn,
    /// Lwt Out
    LwtOut,
    /// Lwt Xmit
    LwtXmit,
    /// Sock Ops
    SockOps,
    /// Sk Skb
    SkSkb,
    /// Cgroup Device
    CgroupDevice,
    /// Sk Msg
    SkMsg,
    /// Raw Tracepoint
    RawTracepoint,
    /// Cgroup Sock Addr
    CgroupSockAddr,
    /// Lwt Seg6 Local
    LwtSeg6Local,
    /// Lirc Mode2
    LircMode2,
    /// Sk Reuseport
    SkReuseport,
    /// Flow Dissector
    FlowDissector,
    /// Cgroup Sysctl
    CgroupSysctl,
    /// Raw Tracepoint Writable
    RawTracepointWritable,
    /// Cgroup Sockopt
    CgroupSockopt,
    /// Tracing
    Tracing,
    /// Struct Ops
    StructOps,
    /// Ext
    Ext,
    /// Lsm
    Lsm,
    /// Sk Lookup
    SkLookup,
    /// Syscall
    Syscall,
    /// Netfilter
    Netfilter,
}

impl From<BpfProgType> for bpf_prog_type {
    fn from(value: BpfProgType) -> Self {
        match value {
            BpfProgType::Unspecified => Self::BPF_PROG_TYPE_UNSPEC,
            BpfProgType::SocketFilter => Self::BPF_PROG_TYPE_SOCKET_FILTER,
            BpfProgType::Kprobe => Self::BPF_PROG_TYPE_KPROBE,
            BpfProgType::SchedCls => Self::BPF_PROG_TYPE_SCHED_CLS,
            BpfProgType::SchedAct => Self::BPF_PROG_TYPE_SCHED_ACT,
            BpfProgType::Tracepoint => Self::BPF_PROG_TYPE_TRACEPOINT,
            BpfProgType::Xdp => Self::BPF_PROG_TYPE_XDP,
            BpfProgType::PerfEvent => Self::BPF_PROG_TYPE_PERF_EVENT,
            BpfProgType::CgroupSkb => Self::BPF_PROG_TYPE_CGROUP_SKB,
            BpfProgType::CgroupSock => Self::BPF_PROG_TYPE_CGROUP_SOCK,
            BpfProgType::LwtIn => Self::BPF_PROG_TYPE_LWT_IN,
            BpfProgType::LwtOut => Self::BPF_PROG_TYPE_LWT_OUT,
            BpfProgType::LwtXmit => Self::BPF_PROG_TYPE_LWT_XMIT,
            BpfProgType::SockOps => Self::BPF_PROG_TYPE_SOCK_OPS,
            BpfProgType::SkSkb => Self::BPF_PROG_TYPE_SK_SKB,
            BpfProgType::CgroupDevice => Self::BPF_PROG_TYPE_CGROUP_DEVICE,
            BpfProgType::SkMsg => Self::BPF_PROG_TYPE_SK_MSG,
            BpfProgType::RawTracepoint => Self::BPF_PROG_TYPE_RAW_TRACEPOINT,
            BpfProgType::CgroupSockAddr => Self::BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
            BpfProgType::LwtSeg6Local => Self::BPF_PROG_TYPE_LWT_SEG6LOCAL,
            BpfProgType::LircMode2 => Self::BPF_PROG_TYPE_LIRC_MODE2,
            BpfProgType::SkReuseport => Self::BPF_PROG_TYPE_SK_REUSEPORT,
            BpfProgType::FlowDissector => Self::BPF_PROG_TYPE_FLOW_DISSECTOR,
            BpfProgType::CgroupSysctl => Self::BPF_PROG_TYPE_CGROUP_SYSCTL,
            BpfProgType::RawTracepointWritable => Self::BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
            BpfProgType::CgroupSockopt => Self::BPF_PROG_TYPE_CGROUP_SOCKOPT,
            BpfProgType::Tracing => Self::BPF_PROG_TYPE_TRACING,
            BpfProgType::StructOps => Self::BPF_PROG_TYPE_STRUCT_OPS,
            BpfProgType::Ext => Self::BPF_PROG_TYPE_EXT,
            BpfProgType::Lsm => Self::BPF_PROG_TYPE_LSM,
            BpfProgType::SkLookup => Self::BPF_PROG_TYPE_SK_LOOKUP,
            BpfProgType::Syscall => Self::BPF_PROG_TYPE_SYSCALL,
            BpfProgType::Netfilter => Self::BPF_PROG_TYPE_NETFILTER,
        }
    }
}
