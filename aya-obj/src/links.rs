//! Link types for BPFFS Permissions

use crate::generated::bpf_link_type;

/// The type of BPF link
#[derive(Copy, Clone, Debug)]
pub enum BpfLinkType {
    /// Not Specified
    Unspecified,
    /// Raw Tracepoint
    RawTracepoint,
    /// Tracing
    Tracing,
    /// Cgroup
    Cgroup,
    /// Iter
    Iter,
    /// Netns
    Netns,
    /// Xdp
    Xdp,
    /// Perf Event
    PerfEvent,
    /// Kprobe Multi
    KprobeMulti,
    /// Struct Ops
    StructOps,
    /// Netfilter
    Netfilter,
    /// Tcx
    Tcx,
    /// Uprobe Multi
    UprobeMulti,
    /// Netkit
    Netkit,
}

impl From<BpfLinkType> for bpf_link_type {
    fn from(value: BpfLinkType) -> Self {
        match value {
            BpfLinkType::Unspecified => bpf_link_type::BPF_LINK_TYPE_UNSPEC,
            BpfLinkType::RawTracepoint => bpf_link_type::BPF_LINK_TYPE_RAW_TRACEPOINT,
            BpfLinkType::Tracing => bpf_link_type::BPF_LINK_TYPE_TRACING,
            BpfLinkType::Cgroup => bpf_link_type::BPF_LINK_TYPE_CGROUP,
            BpfLinkType::Iter => bpf_link_type::BPF_LINK_TYPE_ITER,
            BpfLinkType::Netns => bpf_link_type::BPF_LINK_TYPE_NETNS,
            BpfLinkType::Xdp => bpf_link_type::BPF_LINK_TYPE_XDP,
            BpfLinkType::PerfEvent => bpf_link_type::BPF_LINK_TYPE_PERF_EVENT,
            BpfLinkType::KprobeMulti => bpf_link_type::BPF_LINK_TYPE_KPROBE_MULTI,
            BpfLinkType::StructOps => bpf_link_type::BPF_LINK_TYPE_STRUCT_OPS,
            BpfLinkType::Netfilter => bpf_link_type::BPF_LINK_TYPE_NETFILTER,
            BpfLinkType::Tcx => bpf_link_type::BPF_LINK_TYPE_TCX,
            BpfLinkType::UprobeMulti => bpf_link_type::BPF_LINK_TYPE_UPROBE_MULTI,
            BpfLinkType::Netkit => bpf_link_type::BPF_LINK_TYPE_NETKIT,
        }
    }
}
