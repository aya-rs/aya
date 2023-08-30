#![no_std]
#![no_main]

use aya_bpf::{
    macros::{uprobe, map},
    programs::{perf_event, ProbeContext}, maps::PerfEventArray,
};
use aya_log_ebpf::{debug, info};

pub struct Args {
    a_0: u64,
    a_1: u64,
    a_2: u64,
    a_3: u64,
    a_4: u64,
    a_5: u64,

    a_6: u64,
    a_7: i64,
}

impl Args{
    fn new()->Self{
        Self{
            a_0: 0,
            a_1: 0,
            a_2: 0,
            a_3: 0,
            a_4: 0,
            a_5: 0,
            a_6: 0,
            a_7: 0,
        }
    }
}

#[map]
static EVENTS: PerfEventArray<Args> = PerfEventArray::with_max_entries(1024, 0);

#[uprobe]
pub fn test_stack_argument(ctx: ProbeContext) -> i32 {
    debug!(&ctx, "Hello from eBPF!");
    match try_stack_argument(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

//read argument, and send event
fn try_stack_argument(ctx: ProbeContext) -> Result<i32, i64> {
    let args = Args::new();
    args.a_0 = ctx.arg(0).ok_or(255)?;
    args.a_1 = ctx.arg(1).ok_or(255)?;
    args.a_2 = ctx.arg(2).ok_or(255)?;
    args.a_3 = ctx.arg(3).ok_or(255)?;
    args.a_4 = ctx.arg(4).ok_or(255)?;
    args.a_5 = ctx.arg(5).ok_or(255)?;
    args.a_6 = ctx.stack_arg(0).ok_or(255)?;
    args.a_7 = ctx.stack_arg(1).ok_or(255)?;
    

    EVENTS.output(&ctx, &args, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
