//! XDP programs.

use crate::generated::bpf_attach_type;

/// Defines where to attach an `XDP` program.
#[derive(Copy, Clone, Debug)]
pub enum XdpAttachType {
    /// Attach to a network interface.
    Interface,
    /// Attach to a cpumap. Requires kernel 5.9 or later.
    CpuMap,
    /// Attach to a devmap. Requires kernel 5.8 or later.
    DevMap,
}

impl From<XdpAttachType> for bpf_attach_type {
    fn from(value: XdpAttachType) -> Self {
        match value {
            XdpAttachType::Interface => Self::BPF_XDP,
            XdpAttachType::CpuMap => Self::BPF_XDP_CPUMAP,
            XdpAttachType::DevMap => Self::BPF_XDP_DEVMAP,
        }
    }
}
