//! Program struct and type bindings.

use crate::generated::bpf_prog_type;

pub mod cgroup_sock;
pub mod cgroup_sock_addr;
pub mod cgroup_sockopt;
pub mod xdp;

pub use cgroup_sock::CgroupSockAttachType;
pub use cgroup_sock_addr::CgroupSockAddrAttachType;
pub use cgroup_sockopt::CgroupSockoptAttachType;
pub use xdp::XdpAttachType;

/// The type of BPF statistic to enable.
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
            BpfProgType::Unspecified => bpf_prog_type::BPF_PROG_TYPE_UNSPEC,
            BpfProgType::SocketFilter => bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER,
            BpfProgType::Kprobe => bpf_prog_type::BPF_PROG_TYPE_KPROBE,
            BpfProgType::SchedCls => bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS,
            BpfProgType::SchedAct => bpf_prog_type::BPF_PROG_TYPE_SCHED_ACT,
            BpfProgType::Tracepoint => bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT,
            BpfProgType::Xdp => bpf_prog_type::BPF_PROG_TYPE_XDP,
            BpfProgType::PerfEvent => bpf_prog_type::BPF_PROG_TYPE_PERF_EVENT,
            BpfProgType::CgroupSkb => bpf_prog_type::BPF_PROG_TYPE_CGROUP_SKB,
            BpfProgType::CgroupSock => bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK,
            BpfProgType::LwtIn => bpf_prog_type::BPF_PROG_TYPE_LWT_IN,
            BpfProgType::LwtOut => bpf_prog_type::BPF_PROG_TYPE_LWT_OUT,
            BpfProgType::LwtXmit => bpf_prog_type::BPF_PROG_TYPE_LWT_XMIT,
            BpfProgType::SockOps => bpf_prog_type::BPF_PROG_TYPE_SOCK_OPS,
            BpfProgType::SkSkb => bpf_prog_type::BPF_PROG_TYPE_SK_SKB,
            BpfProgType::CgroupDevice => bpf_prog_type::BPF_PROG_TYPE_CGROUP_DEVICE,
            BpfProgType::SkMsg => bpf_prog_type::BPF_PROG_TYPE_SK_MSG,
            BpfProgType::RawTracepoint => bpf_prog_type::BPF_PROG_TYPE_RAW_TRACEPOINT,
            BpfProgType::CgroupSockAddr => bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
            BpfProgType::LwtSeg6Local => bpf_prog_type::BPF_PROG_TYPE_LWT_SEG6LOCAL,
            BpfProgType::LircMode2 => bpf_prog_type::BPF_PROG_TYPE_LIRC_MODE2,
            BpfProgType::SkReuseport => bpf_prog_type::BPF_PROG_TYPE_SK_REUSEPORT,
            BpfProgType::FlowDissector => bpf_prog_type::BPF_PROG_TYPE_FLOW_DISSECTOR,
            BpfProgType::CgroupSysctl => bpf_prog_type::BPF_PROG_TYPE_CGROUP_SYSCTL,
            BpfProgType::RawTracepointWritable => {
                bpf_prog_type::BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
            }
            BpfProgType::CgroupSockopt => bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCKOPT,
            BpfProgType::Tracing => bpf_prog_type::BPF_PROG_TYPE_TRACING,
            BpfProgType::StructOps => bpf_prog_type::BPF_PROG_TYPE_STRUCT_OPS,
            BpfProgType::Ext => bpf_prog_type::BPF_PROG_TYPE_EXT,
            BpfProgType::Lsm => bpf_prog_type::BPF_PROG_TYPE_LSM,
            BpfProgType::SkLookup => bpf_prog_type::BPF_PROG_TYPE_SK_LOOKUP,
            BpfProgType::Syscall => bpf_prog_type::BPF_PROG_TYPE_SYSCALL,
            BpfProgType::Netfilter => bpf_prog_type::BPF_PROG_TYPE_NETFILTER,
        }
    }
}
