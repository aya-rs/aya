#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_ret_code, xdp_action},
    macros::{
        cgroup_device, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, cgroup_sysctl,
        flow_dissector, kprobe, kretprobe, lsm, lsm_cgroup, sock_ops, tracepoint, uprobe,
        uretprobe, xdp,
    },
    programs::{
        DeviceContext, FlowDissectorContext, LsmContext, ProbeContext, RetProbeContext,
        SkBuffContext, SockAddrContext, SockContext, SockOpsContext, SockoptContext, SysctlContext,
        TracePointContext, XdpContext,
    },
};
#[cfg(not(test))]
extern crate ebpf_panic;

#[xdp]
const fn pass(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[kprobe]
const fn test_kprobe(_ctx: ProbeContext) -> u32 {
    0
}

#[kretprobe]
const fn test_kretprobe(_ctx: RetProbeContext) -> u32 {
    0
}

#[tracepoint]
const fn test_tracepoint(_ctx: TracePointContext) -> u32 {
    0
}

#[uprobe]
const fn test_uprobe(_ctx: ProbeContext) -> u32 {
    0
}

#[uretprobe]
const fn test_uretprobe(_ctx: RetProbeContext) -> u32 {
    0
}

#[flow_dissector]
const fn test_flow(_ctx: FlowDissectorContext) -> u32 {
    // TODO: write an actual flow dissector. See tools/testing/selftests/bpf/progs/bpf_flow.c in the
    // Linux kernel for inspiration.
    bpf_ret_code::BPF_FLOW_DISSECTOR_CONTINUE
}

#[lsm(hook = "socket_bind")]
const fn test_lsm(_ctx: LsmContext) -> i32 {
    -1 // Disallow.
}

#[lsm_cgroup(hook = "socket_bind")]
const fn test_lsm_cgroup(_ctx: LsmContext) -> i32 {
    0 // Disallow.
}

#[lsm_cgroup(hook = "socket_bind")]
const fn allow_bind(_ctx: LsmContext) -> i32 {
    1 // Allow.
}

#[cgroup_device]
const fn test_device(_ctx: DeviceContext) -> i32 {
    1 // Allow device access.
}

#[cgroup_skb(egress)]
const fn test_cgroup_skb(_ctx: SkBuffContext) -> i32 {
    1 // Allow the packet.
}

#[cgroup_skb]
const fn test_cgroup_skb_generic(_ctx: SkBuffContext) -> i32 {
    1 // Allow the packet.
}

#[cgroup_sock(sock_create)]
const fn test_sock(_ctx: SockContext) -> i32 {
    1 // Allow socket creation.
}

#[cgroup_sock_addr(connect4)]
const fn test_sock_addr(_ctx: SockAddrContext) -> i32 {
    1 // Allow IPv4 connections.
}

#[cgroup_sockopt(getsockopt)]
const fn test_sockopt(_ctx: SockoptContext) -> i32 {
    1 // Allow getsockopt.
}

#[cgroup_sysctl]
const fn test_sysctl(_ctx: SysctlContext) -> i32 {
    1 // Allow sysctl access.
}

#[sock_ops]
const fn test_sock_ops(_ctx: SockOpsContext) -> u32 {
    0 // No-op callback.
}
