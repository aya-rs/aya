//! Cgroup socket programs.
use crate::generated::bpf_attach_type;

/// Defines where to attach a `CgroupSock` program.
#[derive(Copy, Clone, Debug, Default)]
pub enum CgroupSockAttachType {
    /// Called after the IPv4 bind events.
    PostBind4,
    /// Called after the IPv6 bind events.
    PostBind6,
    /// Attach to IPv4 connect events.
    #[default]
    SockCreate,
    /// Attach to IPv6 connect events.
    SockRelease,
}

impl From<CgroupSockAttachType> for bpf_attach_type {
    fn from(s: CgroupSockAttachType) -> Self {
        match s {
            CgroupSockAttachType::PostBind4 => Self::BPF_CGROUP_INET4_POST_BIND,
            CgroupSockAttachType::PostBind6 => Self::BPF_CGROUP_INET6_POST_BIND,
            CgroupSockAttachType::SockCreate => Self::BPF_CGROUP_INET_SOCK_CREATE,
            CgroupSockAttachType::SockRelease => Self::BPF_CGROUP_INET_SOCK_RELEASE,
        }
    }
}
