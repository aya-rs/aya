use aya_ebpf::{EbpfContext as _, bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_xdp_dispatcher_ebpf::{
    MAX_DISPATCHER_ACTIONS, XDP_DISPATCHER_MAGIC, XDP_DISPATCHER_RETVAL, XDP_DISPATCHER_VERSION,
    XdpDispatcherConfig,
};

#[unsafe(link_section = ".rodata")]
#[unsafe(no_mangle)]
static conf: XdpDispatcherConfig = XdpDispatcherConfig {
    magic: XDP_DISPATCHER_MAGIC,
    dispatcher_version: XDP_DISPATCHER_VERSION,
    num_progs_enabled: 0,
    is_xdp_frags: 0,
    chain_call_actions: [0u32; MAX_DISPATCHER_ACTIONS],
    run_prios: [0u32; MAX_DISPATCHER_ACTIONS],
    program_flags: [0u32; MAX_DISPATCHER_ACTIONS],
};

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static _license: [u8; 29] = *b"GPL-2.0-only OR BSD-2-Clause\0";

#[unsafe(link_section = "xdp_metadata")]
#[unsafe(no_mangle)]
static dispatcher_version: [u32; XDP_DISPATCHER_VERSION as usize] =
    [0u32; XDP_DISPATCHER_VERSION as usize];

macro_rules! stub_program {
    ($prog:ident) => {
        #[unsafe(no_mangle)]
        #[inline(never)]
        pub fn $prog(ctx: *mut ::aya_ebpf::bindings::xdp_md) -> u32 {
            let ret: u32 = XDP_DISPATCHER_RETVAL;
            if ctx.is_null() {
                return xdp_action::XDP_ABORTED;
            }
            return ret;
        }
    };
}
stub_program!(prog0);
stub_program!(prog1);
stub_program!(prog2);
stub_program!(prog3);
stub_program!(prog4);
stub_program!(prog5);
stub_program!(prog6);
stub_program!(prog7);
stub_program!(prog8);
stub_program!(prog9);

#[xdp]
pub(crate) fn xdp_dispatcher(ctx: XdpContext) -> u32 {
    let cfg = &conf as *const XdpDispatcherConfig;
    let current_cfg = unsafe { core::ptr::read_volatile(&cfg) };
    let num_progs_enabled = unsafe { (*current_cfg).num_progs_enabled } as usize;

    macro_rules! stub_handler {
        ($n:literal, $fn:ident) => {
            if num_progs_enabled < ($n + 1) {
                return xdp_action::XDP_PASS;
            }
            let ret = $fn(ctx.as_ptr().cast());
            if (1u32 << ret) & unsafe { (*current_cfg).chain_call_actions[$n] } == 0 {
                return ret;
            }
        };
    }
    stub_handler!(0, prog0);
    stub_handler!(1, prog1);
    stub_handler!(2, prog2);
    stub_handler!(3, prog3);
    stub_handler!(4, prog4);
    stub_handler!(5, prog5);
    stub_handler!(6, prog6);
    stub_handler!(7, prog7);
    stub_handler!(8, prog8);
    stub_handler!(9, prog9);
    xdp_action::XDP_PASS
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    #[allow(clippy::empty_loop)]
    loop {}
}
