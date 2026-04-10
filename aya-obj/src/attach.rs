//! Attach types for BPFFS Permissions

use crate::generated::bpf_attach_type;

/// The type of BPF attach
#[derive(Copy, Clone, Debug)]
pub enum BpfAttachType {
    /// Cgroup Inet Ingress
    CgroupInetIngress,
    /// Cgroup Inet Egress
    CgroupInetEgress,
    /// Cgroup Inet Sock Create
    CgroupInetSockCreate,
    /// Cgroup Sock Ops
    CgroupSockOps,
    /// Sk Skb Stream Parser
    SkSkbStreamParser,
    /// Sk Skb Stream Verdict
    SkSkbStreamVerdict,
    /// Cgroup Device
    CgroupDevice,
    /// Sk Msg Verdict
    SkMsgVerdict,
    /// Cgroup Inet4 Bind
    CgroupInet4Bind,
    /// Cgroup Inet6 Bind
    CgroupInet6Bind,
    /// Cgroup Inet4 Connect
    CgroupInet4Connect,
    /// Cgroup Inet6 Connect
    CgroupInet6Connect,
    /// Cgroup Inet4 Post Bind
    CgroupInet4PostBind,
    /// Cgroup Inet6 Post Bind
    CgroupInet6PostBind,
    /// Cgroup Udp4 Sendmsg
    CgroupUdp4Sendmsg,
    /// Cgroup Udp6 Sendmsg
    CgroupUdp6Sendmsg,
    /// Lirc Mode2
    LircMode2,
    /// Flow Dissector
    FlowDissector,
    /// Cgroup Sysctl
    CgroupSysctl,
    /// Cgroup Udp4 Recvmsg
    CgroupUdp4Recvmsg,
    /// Cgroup Udp6 Recvmsg
    CgroupUdp6Recvmsg,
    /// Cgroup Getsockopt
    CgroupGetsockopt,
    /// Cgroup Setsockopt
    CgroupSetsockopt,
    /// Trace Raw Tp
    TraceRawTp,
    /// Trace Fentry
    TraceFentry,
    /// Trace Fexit
    TraceFexit,
    /// Modify Return
    ModifyReturn,
    /// Lsm Mac
    LsmMac,
    /// Trace Iter
    TraceIter,
    /// Cgroup Inet4 Getpeername
    CgroupInet4Getpeername,
    /// Cgroup Inet6 Getpeername
    CgroupInet6Getpeername,
    /// Cgroup Inet4 Getsockname
    CgroupInet4Getsockname,
    /// Cgroup Inet6 Getsockname
    CgroupInet6Getsockname,
    /// Xdp Devmap
    XdpDevmap,
    /// Cgroup Inet Sock Release
    CgroupInetSockRelease,
    /// Xdp Cpumap
    XdpCpumap,
    /// Sk Lookup
    SkLookup,
    /// Xdp
    Xdp,
    /// Sk Skb Verdict
    SkSkbVerdict,
    /// Sk Reuseport Select
    SkReuseportSelect,
    /// Sk Reuseport Select Or Migrate
    SkReuseportSelectOrMigrate,
    /// Perf Event
    PerfEvent,
    /// Trace Kprobe Multi
    TraceKprobeMulti,
    /// Lsm Cgroup
    LsmCgroup,
    /// Struct Ops
    StructOps,
    /// Netfilter
    Netfilter,
    /// Tcx Ingress
    TcxIngress,
    /// Tcx Egress
    TcxEgress,
    /// Trace Uprobe Multi
    TraceUprobeMulti,
    /// Cgroup Unix Connect
    CgroupUnixConnect,
    /// Cgroup Unix Sendmsg
    CgroupUnixSendmsg,
    /// Cgroup Unix Recvmsg
    CgroupUnixRecvmsg,
    /// Cgroup Unix Getpeername
    CgroupUnixGetpeername,
    /// Cgroup Unix Getsockname
    CgroupUnixGetsockname,
    /// Netkit Primary
    NetkitPrimary,
    /// Netkit Peer
    NetkitPeer,
}

impl From<BpfAttachType> for bpf_attach_type {
    fn from(attach_type: BpfAttachType) -> Self {
        match attach_type {
            BpfAttachType::CgroupInetIngress => Self::BPF_CGROUP_INET_INGRESS,
            BpfAttachType::CgroupInetEgress => Self::BPF_CGROUP_INET_EGRESS,
            BpfAttachType::CgroupInetSockCreate => Self::BPF_CGROUP_INET_SOCK_CREATE,
            BpfAttachType::CgroupSockOps => Self::BPF_CGROUP_SOCK_OPS,
            BpfAttachType::SkSkbStreamParser => Self::BPF_SK_SKB_STREAM_PARSER,
            BpfAttachType::SkSkbStreamVerdict => Self::BPF_SK_SKB_STREAM_VERDICT,
            BpfAttachType::CgroupDevice => Self::BPF_CGROUP_DEVICE,
            BpfAttachType::SkMsgVerdict => Self::BPF_SK_MSG_VERDICT,
            BpfAttachType::CgroupInet4Bind => Self::BPF_CGROUP_INET4_BIND,
            BpfAttachType::CgroupInet6Bind => Self::BPF_CGROUP_INET6_BIND,
            BpfAttachType::CgroupInet4Connect => Self::BPF_CGROUP_INET4_CONNECT,
            BpfAttachType::CgroupInet6Connect => Self::BPF_CGROUP_INET6_CONNECT,
            BpfAttachType::CgroupInet4PostBind => Self::BPF_CGROUP_INET4_POST_BIND,
            BpfAttachType::CgroupInet6PostBind => Self::BPF_CGROUP_INET6_POST_BIND,
            BpfAttachType::CgroupUdp4Sendmsg => Self::BPF_CGROUP_UDP4_SENDMSG,
            BpfAttachType::CgroupUdp6Sendmsg => Self::BPF_CGROUP_UDP6_SENDMSG,
            BpfAttachType::LircMode2 => Self::BPF_LIRC_MODE2,
            BpfAttachType::FlowDissector => Self::BPF_FLOW_DISSECTOR,
            BpfAttachType::CgroupSysctl => Self::BPF_CGROUP_SYSCTL,
            BpfAttachType::CgroupUdp4Recvmsg => Self::BPF_CGROUP_UDP4_RECVMSG,
            BpfAttachType::CgroupUdp6Recvmsg => Self::BPF_CGROUP_UDP6_RECVMSG,
            BpfAttachType::CgroupGetsockopt => Self::BPF_CGROUP_GETSOCKOPT,
            BpfAttachType::CgroupSetsockopt => Self::BPF_CGROUP_SETSOCKOPT,
            BpfAttachType::TraceRawTp => Self::BPF_TRACE_RAW_TP,
            BpfAttachType::TraceFentry => Self::BPF_TRACE_FENTRY,
            BpfAttachType::TraceFexit => Self::BPF_TRACE_FEXIT,
            BpfAttachType::ModifyReturn => Self::BPF_MODIFY_RETURN,
            BpfAttachType::LsmMac => Self::BPF_LSM_MAC,
            BpfAttachType::TraceIter => Self::BPF_TRACE_ITER,
            BpfAttachType::CgroupInet4Getpeername => Self::BPF_CGROUP_INET4_GETPEERNAME,
            BpfAttachType::CgroupInet6Getpeername => Self::BPF_CGROUP_INET6_GETPEERNAME,
            BpfAttachType::CgroupInet4Getsockname => Self::BPF_CGROUP_INET4_GETSOCKNAME,
            BpfAttachType::CgroupInet6Getsockname => Self::BPF_CGROUP_INET6_GETSOCKNAME,
            BpfAttachType::XdpDevmap => Self::BPF_XDP_DEVMAP,
            BpfAttachType::CgroupInetSockRelease => Self::BPF_CGROUP_INET_SOCK_RELEASE,
            BpfAttachType::XdpCpumap => Self::BPF_XDP_CPUMAP,
            BpfAttachType::SkLookup => Self::BPF_SK_LOOKUP,
            BpfAttachType::Xdp => Self::BPF_XDP,
            BpfAttachType::SkSkbVerdict => Self::BPF_SK_SKB_VERDICT,
            BpfAttachType::SkReuseportSelect => Self::BPF_SK_REUSEPORT_SELECT,
            BpfAttachType::SkReuseportSelectOrMigrate => Self::BPF_SK_REUSEPORT_SELECT_OR_MIGRATE,
            BpfAttachType::PerfEvent => Self::BPF_PERF_EVENT,
            BpfAttachType::TraceKprobeMulti => Self::BPF_TRACE_KPROBE_MULTI,
            BpfAttachType::LsmCgroup => Self::BPF_LSM_CGROUP,
            BpfAttachType::StructOps => Self::BPF_STRUCT_OPS,
            BpfAttachType::Netfilter => Self::BPF_NETFILTER,
            BpfAttachType::TcxIngress => Self::BPF_TCX_INGRESS,
            BpfAttachType::TcxEgress => Self::BPF_TCX_EGRESS,
            BpfAttachType::TraceUprobeMulti => Self::BPF_TRACE_UPROBE_MULTI,
            BpfAttachType::CgroupUnixConnect => Self::BPF_CGROUP_UNIX_CONNECT,
            BpfAttachType::CgroupUnixSendmsg => Self::BPF_CGROUP_UNIX_SENDMSG,
            BpfAttachType::CgroupUnixRecvmsg => Self::BPF_CGROUP_UNIX_RECVMSG,
            BpfAttachType::CgroupUnixGetpeername => Self::BPF_CGROUP_UNIX_GETPEERNAME,
            BpfAttachType::CgroupUnixGetsockname => Self::BPF_CGROUP_UNIX_GETSOCKNAME,
            BpfAttachType::NetkitPrimary => Self::BPF_NETKIT_PRIMARY,
            BpfAttachType::NetkitPeer => Self::BPF_NETKIT_PEER,
        }
    }
}
