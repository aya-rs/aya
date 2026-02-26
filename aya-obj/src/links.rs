//! Link type bindings.

use crate::{
    InvalidTypeBinding,
    generated::{bpf_attach_type, bpf_link_type},
};

impl TryFrom<u32> for bpf_link_type {
    type Error = InvalidTypeBinding<u32>;

    fn try_from(link_type: u32) -> Result<Self, Self::Error> {
        Ok(match link_type {
            x if x == Self::BPF_LINK_TYPE_UNSPEC as u32 => Self::BPF_LINK_TYPE_UNSPEC,
            x if x == Self::BPF_LINK_TYPE_RAW_TRACEPOINT as u32 => {
                Self::BPF_LINK_TYPE_RAW_TRACEPOINT
            }
            x if x == Self::BPF_LINK_TYPE_TRACING as u32 => Self::BPF_LINK_TYPE_TRACING,
            x if x == Self::BPF_LINK_TYPE_CGROUP as u32 => Self::BPF_LINK_TYPE_CGROUP,
            x if x == Self::BPF_LINK_TYPE_ITER as u32 => Self::BPF_LINK_TYPE_ITER,
            x if x == Self::BPF_LINK_TYPE_NETNS as u32 => Self::BPF_LINK_TYPE_NETNS,
            x if x == Self::BPF_LINK_TYPE_XDP as u32 => Self::BPF_LINK_TYPE_XDP,
            x if x == Self::BPF_LINK_TYPE_PERF_EVENT as u32 => Self::BPF_LINK_TYPE_PERF_EVENT,
            x if x == Self::BPF_LINK_TYPE_KPROBE_MULTI as u32 => Self::BPF_LINK_TYPE_KPROBE_MULTI,
            x if x == Self::BPF_LINK_TYPE_STRUCT_OPS as u32 => Self::BPF_LINK_TYPE_STRUCT_OPS,
            x if x == Self::BPF_LINK_TYPE_NETFILTER as u32 => Self::BPF_LINK_TYPE_NETFILTER,
            x if x == Self::BPF_LINK_TYPE_TCX as u32 => Self::BPF_LINK_TYPE_TCX,
            x if x == Self::BPF_LINK_TYPE_UPROBE_MULTI as u32 => Self::BPF_LINK_TYPE_UPROBE_MULTI,
            x if x == Self::BPF_LINK_TYPE_NETKIT as u32 => Self::BPF_LINK_TYPE_NETKIT,
            _ => return Err(InvalidTypeBinding { value: link_type }),
        })
    }
}

impl TryFrom<u32> for bpf_attach_type {
    type Error = InvalidTypeBinding<u32>;

    fn try_from(attach_type: u32) -> Result<Self, Self::Error> {
        Ok(match attach_type {
            x if x == Self::BPF_CGROUP_INET_INGRESS as u32 => Self::BPF_CGROUP_INET_INGRESS,
            x if x == Self::BPF_CGROUP_INET_EGRESS as u32 => Self::BPF_CGROUP_INET_EGRESS,
            x if x == Self::BPF_CGROUP_INET_SOCK_CREATE as u32 => Self::BPF_CGROUP_INET_SOCK_CREATE,
            x if x == Self::BPF_CGROUP_SOCK_OPS as u32 => Self::BPF_CGROUP_SOCK_OPS,
            x if x == Self::BPF_SK_SKB_STREAM_PARSER as u32 => Self::BPF_SK_SKB_STREAM_PARSER,
            x if x == Self::BPF_SK_SKB_STREAM_VERDICT as u32 => Self::BPF_SK_SKB_STREAM_VERDICT,
            x if x == Self::BPF_CGROUP_DEVICE as u32 => Self::BPF_CGROUP_DEVICE,
            x if x == Self::BPF_SK_MSG_VERDICT as u32 => Self::BPF_SK_MSG_VERDICT,
            x if x == Self::BPF_CGROUP_INET4_BIND as u32 => Self::BPF_CGROUP_INET4_BIND,
            x if x == Self::BPF_CGROUP_INET6_BIND as u32 => Self::BPF_CGROUP_INET6_BIND,
            x if x == Self::BPF_CGROUP_INET4_CONNECT as u32 => Self::BPF_CGROUP_INET4_CONNECT,
            x if x == Self::BPF_CGROUP_INET6_CONNECT as u32 => Self::BPF_CGROUP_INET6_CONNECT,
            x if x == Self::BPF_CGROUP_INET4_POST_BIND as u32 => Self::BPF_CGROUP_INET4_POST_BIND,
            x if x == Self::BPF_CGROUP_INET6_POST_BIND as u32 => Self::BPF_CGROUP_INET6_POST_BIND,
            x if x == Self::BPF_CGROUP_UDP4_SENDMSG as u32 => Self::BPF_CGROUP_UDP4_SENDMSG,
            x if x == Self::BPF_CGROUP_UDP6_SENDMSG as u32 => Self::BPF_CGROUP_UDP6_SENDMSG,
            x if x == Self::BPF_LIRC_MODE2 as u32 => Self::BPF_LIRC_MODE2,
            x if x == Self::BPF_FLOW_DISSECTOR as u32 => Self::BPF_FLOW_DISSECTOR,
            x if x == Self::BPF_CGROUP_SYSCTL as u32 => Self::BPF_CGROUP_SYSCTL,
            x if x == Self::BPF_CGROUP_UDP4_RECVMSG as u32 => Self::BPF_CGROUP_UDP4_RECVMSG,
            x if x == Self::BPF_CGROUP_UDP6_RECVMSG as u32 => Self::BPF_CGROUP_UDP6_RECVMSG,
            x if x == Self::BPF_CGROUP_GETSOCKOPT as u32 => Self::BPF_CGROUP_GETSOCKOPT,
            x if x == Self::BPF_CGROUP_SETSOCKOPT as u32 => Self::BPF_CGROUP_SETSOCKOPT,
            x if x == Self::BPF_TRACE_RAW_TP as u32 => Self::BPF_TRACE_RAW_TP,
            x if x == Self::BPF_TRACE_FENTRY as u32 => Self::BPF_TRACE_FENTRY,
            x if x == Self::BPF_TRACE_FEXIT as u32 => Self::BPF_TRACE_FEXIT,
            x if x == Self::BPF_MODIFY_RETURN as u32 => Self::BPF_MODIFY_RETURN,
            x if x == Self::BPF_LSM_MAC as u32 => Self::BPF_LSM_MAC,
            x if x == Self::BPF_TRACE_ITER as u32 => Self::BPF_TRACE_ITER,
            x if x == Self::BPF_CGROUP_INET4_GETPEERNAME as u32 => {
                Self::BPF_CGROUP_INET4_GETPEERNAME
            }
            x if x == Self::BPF_CGROUP_INET6_GETPEERNAME as u32 => {
                Self::BPF_CGROUP_INET6_GETPEERNAME
            }
            x if x == Self::BPF_CGROUP_INET4_GETSOCKNAME as u32 => {
                Self::BPF_CGROUP_INET4_GETSOCKNAME
            }
            x if x == Self::BPF_CGROUP_INET6_GETSOCKNAME as u32 => {
                Self::BPF_CGROUP_INET6_GETSOCKNAME
            }
            x if x == Self::BPF_XDP_DEVMAP as u32 => Self::BPF_XDP_DEVMAP,
            x if x == Self::BPF_CGROUP_INET_SOCK_RELEASE as u32 => {
                Self::BPF_CGROUP_INET_SOCK_RELEASE
            }
            x if x == Self::BPF_XDP_CPUMAP as u32 => Self::BPF_XDP_CPUMAP,
            x if x == Self::BPF_SK_LOOKUP as u32 => Self::BPF_SK_LOOKUP,
            x if x == Self::BPF_XDP as u32 => Self::BPF_XDP,
            x if x == Self::BPF_SK_SKB_VERDICT as u32 => Self::BPF_SK_SKB_VERDICT,
            x if x == Self::BPF_SK_REUSEPORT_SELECT as u32 => Self::BPF_SK_REUSEPORT_SELECT,
            x if x == Self::BPF_SK_REUSEPORT_SELECT_OR_MIGRATE as u32 => {
                Self::BPF_SK_REUSEPORT_SELECT_OR_MIGRATE
            }
            x if x == Self::BPF_PERF_EVENT as u32 => Self::BPF_PERF_EVENT,
            x if x == Self::BPF_TRACE_KPROBE_MULTI as u32 => Self::BPF_TRACE_KPROBE_MULTI,
            x if x == Self::BPF_LSM_CGROUP as u32 => Self::BPF_LSM_CGROUP,
            x if x == Self::BPF_STRUCT_OPS as u32 => Self::BPF_STRUCT_OPS,
            x if x == Self::BPF_NETFILTER as u32 => Self::BPF_NETFILTER,
            x if x == Self::BPF_TCX_INGRESS as u32 => Self::BPF_TCX_INGRESS,
            x if x == Self::BPF_TCX_EGRESS as u32 => Self::BPF_TCX_EGRESS,
            x if x == Self::BPF_TRACE_UPROBE_MULTI as u32 => Self::BPF_TRACE_UPROBE_MULTI,
            x if x == Self::BPF_CGROUP_UNIX_CONNECT as u32 => Self::BPF_CGROUP_UNIX_CONNECT,
            x if x == Self::BPF_CGROUP_UNIX_SENDMSG as u32 => Self::BPF_CGROUP_UNIX_SENDMSG,
            x if x == Self::BPF_CGROUP_UNIX_RECVMSG as u32 => Self::BPF_CGROUP_UNIX_RECVMSG,
            x if x == Self::BPF_CGROUP_UNIX_GETPEERNAME as u32 => Self::BPF_CGROUP_UNIX_GETPEERNAME,
            x if x == Self::BPF_CGROUP_UNIX_GETSOCKNAME as u32 => Self::BPF_CGROUP_UNIX_GETSOCKNAME,
            x if x == Self::BPF_NETKIT_PRIMARY as u32 => Self::BPF_NETKIT_PRIMARY,
            x if x == Self::BPF_NETKIT_PEER as u32 => Self::BPF_NETKIT_PEER,
            _ => return Err(InvalidTypeBinding { value: attach_type }),
        })
    }
}
