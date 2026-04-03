//! Cgroup skb programs.
use crate::generated::bpf_attach_type;

/// Defines where to attach a `CgroupSkb` program.
#[derive(Copy, Clone, Debug)]
pub enum CgroupSkbAttachType {
    /// Attach to ingress.
    Ingress,
    /// Attach to egress.
    Egress,
}

impl From<CgroupSkbAttachType> for bpf_attach_type {
    fn from(s: CgroupSkbAttachType) -> Self {
        match s {
            CgroupSkbAttachType::Ingress => Self::BPF_CGROUP_INET_INGRESS,
            CgroupSkbAttachType::Egress => Self::BPF_CGROUP_INET_EGRESS,
        }
    }
}
