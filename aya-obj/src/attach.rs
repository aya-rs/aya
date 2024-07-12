//! Link types for BPFFS Permissions

use crate::generated::bpf_attach_type;

/// The type of BPF link
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
            BpfAttachType::CgroupInetIngress => bpf_attach_type::BPF_CGROUP_INET_INGRESS,
            BpfAttachType::CgroupInetEgress => bpf_attach_type::BPF_CGROUP_INET_EGRESS,
            BpfAttachType::CgroupInetSockCreate => bpf_attach_type::BPF_CGROUP_INET_SOCK_CREATE,
            BpfAttachType::CgroupSockOps => bpf_attach_type::BPF_CGROUP_SOCK_OPS,
            BpfAttachType::SkSkbStreamParser => bpf_attach_type::BPF_SK_SKB_STREAM_PARSER,
            BpfAttachType::SkSkbStreamVerdict => bpf_attach_type::BPF_SK_SKB_STREAM_VERDICT,
            BpfAttachType::CgroupDevice => bpf_attach_type::BPF_CGROUP_DEVICE,
            BpfAttachType::SkMsgVerdict => bpf_attach_type::BPF_SK_MSG_VERDICT,
            BpfAttachType::CgroupInet4Bind => bpf_attach_type::BPF_CGROUP_INET4_BIND,
            BpfAttachType::CgroupInet6Bind => bpf_attach_type::BPF_CGROUP_INET6_BIND,
            BpfAttachType::CgroupInet4Connect => bpf_attach_type::BPF_CGROUP_INET4_CONNECT,
            BpfAttachType::CgroupInet6Connect => bpf_attach_type::BPF_CGROUP_INET6_CONNECT,
            BpfAttachType::CgroupInet4PostBind => bpf_attach_type::BPF_CGROUP_INET4_POST_BIND,
            BpfAttachType::CgroupInet6PostBind => bpf_attach_type::BPF_CGROUP_INET6_POST_BIND,
            BpfAttachType::CgroupUdp4Sendmsg => bpf_attach_type::BPF_CGROUP_UDP4_SENDMSG,
            BpfAttachType::CgroupUdp6Sendmsg => bpf_attach_type::BPF_CGROUP_UDP6_SENDMSG,
            BpfAttachType::LircMode2 => bpf_attach_type::BPF_LIRC_MODE2,
            BpfAttachType::FlowDissector => bpf_attach_type::BPF_FLOW_DISSECTOR,
            BpfAttachType::CgroupSysctl => bpf_attach_type::BPF_CGROUP_SYSCTL,
            BpfAttachType::CgroupUdp4Recvmsg => bpf_attach_type::BPF_CGROUP_UDP4_RECVMSG,
            BpfAttachType::CgroupUdp6Recvmsg => bpf_attach_type::BPF_CGROUP_UDP6_RECVMSG,
            BpfAttachType::CgroupGetsockopt => bpf_attach_type::BPF_CGROUP_GETSOCKOPT,
            BpfAttachType::CgroupSetsockopt => bpf_attach_type::BPF_CGROUP_SETSOCKOPT,
            BpfAttachType::TraceRawTp => bpf_attach_type::BPF_TRACE_RAW_TP,
            BpfAttachType::TraceFentry => bpf_attach_type::BPF_TRACE_FENTRY,
            BpfAttachType::TraceFexit => bpf_attach_type::BPF_TRACE_FEXIT,
            BpfAttachType::ModifyReturn => bpf_attach_type::BPF_MODIFY_RETURN,
            BpfAttachType::LsmMac => bpf_attach_type::BPF_LSM_MAC,
            BpfAttachType::TraceIter => bpf_attach_type::BPF_TRACE_ITER,
            BpfAttachType::CgroupInet4Getpeername => bpf_attach_type::BPF_CGROUP_INET4_GETPEERNAME,
            BpfAttachType::CgroupInet6Getpeername => bpf_attach_type::BPF_CGROUP_INET6_GETPEERNAME,
            BpfAttachType::CgroupInet4Getsockname => bpf_attach_type::BPF_CGROUP_INET4_GETSOCKNAME,
            BpfAttachType::CgroupInet6Getsockname => bpf_attach_type::BPF_CGROUP_INET6_GETSOCKNAME,
            BpfAttachType::XdpDevmap => bpf_attach_type::BPF_XDP_DEVMAP,
            BpfAttachType::CgroupInetSockRelease => bpf_attach_type::BPF_CGROUP_INET_SOCK_RELEASE,
            BpfAttachType::XdpCpumap => bpf_attach_type::BPF_XDP_CPUMAP,
            BpfAttachType::SkLookup => bpf_attach_type::BPF_SK_LOOKUP,
            BpfAttachType::Xdp => bpf_attach_type::BPF_XDP,
            BpfAttachType::SkSkbVerdict => bpf_attach_type::BPF_SK_SKB_VERDICT,
            BpfAttachType::SkReuseportSelect => bpf_attach_type::BPF_SK_REUSEPORT_SELECT,
            BpfAttachType::SkReuseportSelectOrMigrate => {
                bpf_attach_type::BPF_SK_REUSEPORT_SELECT_OR_MIGRATE
            }
            BpfAttachType::PerfEvent => bpf_attach_type::BPF_PERF_EVENT,
            BpfAttachType::TraceKprobeMulti => bpf_attach_type::BPF_TRACE_KPROBE_MULTI,
            BpfAttachType::LsmCgroup => bpf_attach_type::BPF_LSM_CGROUP,
            BpfAttachType::StructOps => bpf_attach_type::BPF_STRUCT_OPS,
            BpfAttachType::Netfilter => bpf_attach_type::BPF_NETFILTER,
            BpfAttachType::TcxIngress => bpf_attach_type::BPF_TCX_INGRESS,
            BpfAttachType::TcxEgress => bpf_attach_type::BPF_TCX_EGRESS,
            BpfAttachType::TraceUprobeMulti => bpf_attach_type::BPF_TRACE_UPROBE_MULTI,
            BpfAttachType::CgroupUnixConnect => bpf_attach_type::BPF_CGROUP_UNIX_CONNECT,
            BpfAttachType::CgroupUnixSendmsg => bpf_attach_type::BPF_CGROUP_UNIX_SENDMSG,
            BpfAttachType::CgroupUnixRecvmsg => bpf_attach_type::BPF_CGROUP_UNIX_RECVMSG,
            BpfAttachType::CgroupUnixGetpeername => bpf_attach_type::BPF_CGROUP_UNIX_GETPEERNAME,
            BpfAttachType::CgroupUnixGetsockname => bpf_attach_type::BPF_CGROUP_UNIX_GETSOCKNAME,
            BpfAttachType::NetkitPrimary => bpf_attach_type::BPF_NETKIT_PRIMARY,
            BpfAttachType::NetkitPeer => bpf_attach_type::BPF_NETKIT_PEER,
        }
    }
}
