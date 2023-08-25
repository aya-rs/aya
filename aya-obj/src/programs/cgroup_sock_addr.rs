//! Cgroup socket address programs.
use crate::generated::bpf_attach_type;

/// Defines where to attach a `CgroupSockAddr` program.
#[derive(Copy, Clone, Debug)]
pub enum CgroupSockAddrAttachType {
    /// Attach to IPv4 bind events.
    Bind4,
    /// Attach to IPv6 bind events.
    Bind6,
    /// Attach to IPv4 connect events.
    Connect4,
    /// Attach to IPv6 connect events.
    Connect6,
    /// Attach to IPv4 getpeername events.
    GetPeerName4,
    /// Attach to IPv6 getpeername events.
    GetPeerName6,
    /// Attach to IPv4 getsockname events.
    GetSockName4,
    /// Attach to IPv6 getsockname events.
    GetSockName6,
    /// Attach to IPv4 udp_sendmsg events.
    UDPSendMsg4,
    /// Attach to IPv6 udp_sendmsg events.
    UDPSendMsg6,
    /// Attach to IPv4 udp_recvmsg events.
    UDPRecvMsg4,
    /// Attach to IPv6 udp_recvmsg events.
    UDPRecvMsg6,
}

impl From<CgroupSockAddrAttachType> for bpf_attach_type {
    fn from(s: CgroupSockAddrAttachType) -> bpf_attach_type {
        match s {
            CgroupSockAddrAttachType::Bind4 => bpf_attach_type::BPF_CGROUP_INET4_BIND,
            CgroupSockAddrAttachType::Bind6 => bpf_attach_type::BPF_CGROUP_INET6_BIND,
            CgroupSockAddrAttachType::Connect4 => bpf_attach_type::BPF_CGROUP_INET4_CONNECT,
            CgroupSockAddrAttachType::Connect6 => bpf_attach_type::BPF_CGROUP_INET6_CONNECT,
            CgroupSockAddrAttachType::GetPeerName4 => bpf_attach_type::BPF_CGROUP_INET4_GETPEERNAME,
            CgroupSockAddrAttachType::GetPeerName6 => bpf_attach_type::BPF_CGROUP_INET6_GETPEERNAME,
            CgroupSockAddrAttachType::GetSockName4 => bpf_attach_type::BPF_CGROUP_INET4_GETSOCKNAME,
            CgroupSockAddrAttachType::GetSockName6 => bpf_attach_type::BPF_CGROUP_INET6_GETSOCKNAME,
            CgroupSockAddrAttachType::UDPSendMsg4 => bpf_attach_type::BPF_CGROUP_UDP4_SENDMSG,
            CgroupSockAddrAttachType::UDPSendMsg6 => bpf_attach_type::BPF_CGROUP_UDP6_SENDMSG,
            CgroupSockAddrAttachType::UDPRecvMsg4 => bpf_attach_type::BPF_CGROUP_UDP4_RECVMSG,
            CgroupSockAddrAttachType::UDPRecvMsg6 => bpf_attach_type::BPF_CGROUP_UDP6_RECVMSG,
        }
    }
}
