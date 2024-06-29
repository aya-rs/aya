//! Program type bindings.

use core::fmt::Display;

use crate::generated::bpf_prog_type::{self, *};

impl From<u32> for bpf_prog_type {
    fn from(prog_type: u32) -> Self {
        match prog_type {
            x if x == BPF_PROG_TYPE_UNSPEC as u32 => BPF_PROG_TYPE_UNSPEC,
            x if x == BPF_PROG_TYPE_SOCKET_FILTER as u32 => BPF_PROG_TYPE_SOCKET_FILTER,
            x if x == BPF_PROG_TYPE_KPROBE as u32 => BPF_PROG_TYPE_KPROBE,
            x if x == BPF_PROG_TYPE_SCHED_CLS as u32 => BPF_PROG_TYPE_SCHED_CLS,
            x if x == BPF_PROG_TYPE_SCHED_ACT as u32 => BPF_PROG_TYPE_SCHED_ACT,
            x if x == BPF_PROG_TYPE_TRACEPOINT as u32 => BPF_PROG_TYPE_TRACEPOINT,
            x if x == BPF_PROG_TYPE_XDP as u32 => BPF_PROG_TYPE_XDP,
            x if x == BPF_PROG_TYPE_PERF_EVENT as u32 => BPF_PROG_TYPE_PERF_EVENT,
            x if x == BPF_PROG_TYPE_CGROUP_SKB as u32 => BPF_PROG_TYPE_CGROUP_SKB,
            x if x == BPF_PROG_TYPE_CGROUP_SOCK as u32 => BPF_PROG_TYPE_CGROUP_SOCK,
            x if x == BPF_PROG_TYPE_LWT_IN as u32 => BPF_PROG_TYPE_LWT_IN,
            x if x == BPF_PROG_TYPE_LWT_OUT as u32 => BPF_PROG_TYPE_LWT_OUT,
            x if x == BPF_PROG_TYPE_LWT_XMIT as u32 => BPF_PROG_TYPE_LWT_XMIT,
            x if x == BPF_PROG_TYPE_SOCK_OPS as u32 => BPF_PROG_TYPE_SOCK_OPS,
            x if x == BPF_PROG_TYPE_SK_SKB as u32 => BPF_PROG_TYPE_SK_SKB,
            x if x == BPF_PROG_TYPE_CGROUP_DEVICE as u32 => BPF_PROG_TYPE_CGROUP_DEVICE,
            x if x == BPF_PROG_TYPE_SK_MSG as u32 => BPF_PROG_TYPE_SK_MSG,
            x if x == BPF_PROG_TYPE_RAW_TRACEPOINT as u32 => BPF_PROG_TYPE_RAW_TRACEPOINT,
            x if x == BPF_PROG_TYPE_CGROUP_SOCK_ADDR as u32 => BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
            x if x == BPF_PROG_TYPE_LWT_SEG6LOCAL as u32 => BPF_PROG_TYPE_LWT_SEG6LOCAL,
            x if x == BPF_PROG_TYPE_LIRC_MODE2 as u32 => BPF_PROG_TYPE_LIRC_MODE2,
            x if x == BPF_PROG_TYPE_SK_REUSEPORT as u32 => BPF_PROG_TYPE_SK_REUSEPORT,
            x if x == BPF_PROG_TYPE_FLOW_DISSECTOR as u32 => BPF_PROG_TYPE_FLOW_DISSECTOR,
            x if x == BPF_PROG_TYPE_CGROUP_SYSCTL as u32 => BPF_PROG_TYPE_CGROUP_SYSCTL,
            x if x == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE as u32 => {
                BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
            }
            x if x == BPF_PROG_TYPE_CGROUP_SOCKOPT as u32 => BPF_PROG_TYPE_CGROUP_SOCKOPT,
            x if x == BPF_PROG_TYPE_TRACING as u32 => BPF_PROG_TYPE_TRACING,
            x if x == BPF_PROG_TYPE_STRUCT_OPS as u32 => BPF_PROG_TYPE_STRUCT_OPS,
            x if x == BPF_PROG_TYPE_EXT as u32 => BPF_PROG_TYPE_EXT,
            x if x == BPF_PROG_TYPE_LSM as u32 => BPF_PROG_TYPE_LSM,
            x if x == BPF_PROG_TYPE_SK_LOOKUP as u32 => BPF_PROG_TYPE_SK_LOOKUP,
            x if x == BPF_PROG_TYPE_SYSCALL as u32 => BPF_PROG_TYPE_SYSCALL,
            x if x == BPF_PROG_TYPE_NETFILTER as u32 => BPF_PROG_TYPE_NETFILTER,
            _ => __MAX_BPF_PROG_TYPE,
        }
    }
}

impl Display for bpf_prog_type {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                BPF_PROG_TYPE_UNSPEC => "Unspec",
                BPF_PROG_TYPE_SOCKET_FILTER => "SocketFilter",
                BPF_PROG_TYPE_KPROBE => "KProbe",
                BPF_PROG_TYPE_SCHED_CLS => "SchedCls",
                BPF_PROG_TYPE_SCHED_ACT => "SchedAct",
                BPF_PROG_TYPE_TRACEPOINT => "TracePoint",
                BPF_PROG_TYPE_XDP => "Xdp",
                BPF_PROG_TYPE_PERF_EVENT => "PerfEvent",
                BPF_PROG_TYPE_CGROUP_SKB => "CgroupSkb",
                BPF_PROG_TYPE_CGROUP_SOCK => "CgroupSock",
                BPF_PROG_TYPE_LWT_IN => "LwtIn",
                BPF_PROG_TYPE_LWT_OUT => "LwtOut",
                BPF_PROG_TYPE_LWT_XMIT => "LwtXmit",
                BPF_PROG_TYPE_SOCK_OPS => "SockOps",
                BPF_PROG_TYPE_SK_SKB => "SkSkb",
                BPF_PROG_TYPE_CGROUP_DEVICE => "CgroupDevice",
                BPF_PROG_TYPE_SK_MSG => "SkMsg",
                BPF_PROG_TYPE_RAW_TRACEPOINT => "RawTracePoint",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR => "CgroupSockAddr",
                BPF_PROG_TYPE_LWT_SEG6LOCAL => "LwtSeg6local",
                BPF_PROG_TYPE_LIRC_MODE2 => "LircMode2",
                BPF_PROG_TYPE_SK_REUSEPORT => "SkReusePort",
                BPF_PROG_TYPE_FLOW_DISSECTOR => "FlowDissector",
                BPF_PROG_TYPE_CGROUP_SYSCTL => "CgroupSysctl",
                BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE => "RawTracePointWritable",
                BPF_PROG_TYPE_CGROUP_SOCKOPT => "CgroupSockOpt",
                BPF_PROG_TYPE_TRACING => "Tracing",
                BPF_PROG_TYPE_STRUCT_OPS => "StructOps",
                BPF_PROG_TYPE_EXT => "Ext",
                BPF_PROG_TYPE_LSM => "Lsm",
                BPF_PROG_TYPE_SK_LOOKUP => "SkLookup",
                BPF_PROG_TYPE_SYSCALL => "Syscall",
                BPF_PROG_TYPE_NETFILTER => "Netfilter",
                __MAX_BPF_PROG_TYPE => "MaxProgType",
            }
        )
    }
}
