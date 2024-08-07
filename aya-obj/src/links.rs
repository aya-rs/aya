//! Link related object bindings and helpers.

impl From<u32> for crate::generated::bpf_link_type {
    fn from(link_type: u32) -> Self {
        use crate::generated::bpf_link_type::*;

        match link_type {
            x if x == BPF_LINK_TYPE_UNSPEC as u32 => BPF_LINK_TYPE_UNSPEC,
            x if x == BPF_LINK_TYPE_RAW_TRACEPOINT as u32 => BPF_LINK_TYPE_RAW_TRACEPOINT,
            x if x == BPF_LINK_TYPE_TRACING as u32 => BPF_LINK_TYPE_TRACING,
            x if x == BPF_LINK_TYPE_CGROUP as u32 => BPF_LINK_TYPE_CGROUP,
            x if x == BPF_LINK_TYPE_ITER as u32 => BPF_LINK_TYPE_ITER,
            x if x == BPF_LINK_TYPE_NETNS as u32 => BPF_LINK_TYPE_NETNS,
            x if x == BPF_LINK_TYPE_XDP as u32 => BPF_LINK_TYPE_XDP,
            x if x == BPF_LINK_TYPE_PERF_EVENT as u32 => BPF_LINK_TYPE_PERF_EVENT,
            x if x == BPF_LINK_TYPE_KPROBE_MULTI as u32 => BPF_LINK_TYPE_KPROBE_MULTI,
            x if x == BPF_LINK_TYPE_STRUCT_OPS as u32 => BPF_LINK_TYPE_STRUCT_OPS,
            x if x == BPF_LINK_TYPE_NETFILTER as u32 => BPF_LINK_TYPE_NETFILTER,
            x if x == BPF_LINK_TYPE_TCX as u32 => BPF_LINK_TYPE_TCX,
            x if x == BPF_LINK_TYPE_UPROBE_MULTI as u32 => BPF_LINK_TYPE_UPROBE_MULTI,
            x if x == BPF_LINK_TYPE_NETKIT as u32 => BPF_LINK_TYPE_NETKIT,
            _ => __MAX_BPF_LINK_TYPE,
        }
    }
}
