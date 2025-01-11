#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action, helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid}, macros::{kprobe, kretprobe, lsm, tracepoint, uprobe, uretprobe, xdp}, programs::{LsmContext, ProbeContext, RetProbeContext, TracePointContext, XdpContext}
};

#[xdp]
pub fn pass(ctx: XdpContext) -> u32 {
    match unsafe { try_pass(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_pass(_ctx: XdpContext) -> Result<u32, u32> {
    Ok(xdp_action::XDP_PASS)
}

#[kprobe]
pub fn test_kprobe(_ctx: ProbeContext) -> u32 {
    0
}

#[kretprobe]
pub fn test_kretprobe(_ctx: RetProbeContext) -> u32 {
    0
}

#[tracepoint]
pub fn test_tracepoint(_ctx: TracePointContext) -> u32 {
    0
}

#[uprobe]
pub fn test_uprobe(_ctx: ProbeContext) -> u32 {
    0
}

#[uretprobe]
pub fn test_uretprobe(_ctx: RetProbeContext) -> u32 {
    0
}

#[lsm(hook="socket_bind", cgroup)]
pub fn test_lsmcgroup(_ctx: LsmContext) -> i32 {
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
