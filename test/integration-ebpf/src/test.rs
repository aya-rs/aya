#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    bindings::{bpf_ret_code, xdp_action},
    macros::{
        flow_dissector, kprobe, kretprobe, lsm, lsm_cgroup, tracepoint, uprobe, uretprobe, xdp,
    },
    programs::{
        FlowDissectorContext, LsmContext, ProbeContext, RetProbeContext, TracePointContext,
        XdpContext,
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
