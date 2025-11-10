//! Cgroup socket option programs.
use crate::generated::bpf_attach_type;

/// Defines where to attach a `CgroupSockopt` program.
#[derive(Copy, Clone, Debug)]
pub enum CgroupSockoptAttachType {
    /// Attach to GetSockopt.
    Get,
    /// Attach to SetSockopt.
    Set,
}

impl From<CgroupSockoptAttachType> for bpf_attach_type {
    fn from(s: CgroupSockoptAttachType) -> Self {
        match s {
            CgroupSockoptAttachType::Get => Self::BPF_CGROUP_GETSOCKOPT,
            CgroupSockoptAttachType::Set => Self::BPF_CGROUP_SETSOCKOPT,
        }
    }
}
