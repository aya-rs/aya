//! XDP programs.

use crate::generated::bpf_attach_type;

/// Defines where to attach an `XDP` program.
#[derive(Copy, Clone, Debug)]
pub enum LsmAttachType {
    /// Cgroup based LSM program
    Cgroup,
    /// MAC based LSM program
    Mac,
}

impl From<LsmAttachType> for bpf_attach_type {
    fn from(value: LsmAttachType) -> Self {
        match value {
            LsmAttachType::Cgroup => bpf_attach_type::BPF_LSM_CGROUP,
            LsmAttachType::Mac => bpf_attach_type::BPF_LSM_MAC,
        }
    }
}
