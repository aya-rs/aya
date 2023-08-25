//! Cgroup socket option programs.
use crate::generated::bpf_attach_type;

#[cfg(not(feature = "std"))]
use crate::std;

/// Defines where to attach a `CgroupSockopt` program.
#[derive(Copy, Clone, Debug)]
pub enum CgroupSockoptAttachType {
    /// Attach to GetSockopt.
    Get,
    /// Attach to SetSockopt.
    Set,
}

impl From<CgroupSockoptAttachType> for bpf_attach_type {
    fn from(s: CgroupSockoptAttachType) -> bpf_attach_type {
        match s {
            CgroupSockoptAttachType::Get => bpf_attach_type::BPF_CGROUP_GETSOCKOPT,
            CgroupSockoptAttachType::Set => bpf_attach_type::BPF_CGROUP_SETSOCKOPT,
        }
    }
}
