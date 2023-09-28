#![no_std]
#![no_main]

use aya_bpf::{
    macros::{map, uprobe},
    maps::HashMap,
    programs::ProbeContext,
};

#[map]
static ARGS: HashMap<u32, u64> = HashMap::with_max_entries(24, 0);

#[uprobe]
pub fn test_stack_argument(ctx: ProbeContext) -> i32 {
    match try_stack_argument(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

// read function arguments, and set to map.
fn try_stack_argument(ctx: ProbeContext) -> Result<i32, i64> {
    let _ = ARGS.insert(&0, &ctx.arg(0).ok_or(255)?, 0);
    let _ = ARGS.insert(&1, &ctx.arg(1).ok_or(255)?, 0);
    let _ = ARGS.insert(&2, &ctx.arg(2).ok_or(255)?, 0);
    let _ = ARGS.insert(&3, &ctx.arg(3).ok_or(255)?, 0);
    let _ = ARGS.insert(&4, &ctx.arg(4).ok_or(255)?, 0);
    let _ = ARGS.insert(&5, &ctx.arg(5).ok_or(255)?, 0);
    let _ = ARGS.insert(&6, &ctx.stack_arg(0).ok_or(255)?, 0);
    let _ = ARGS.insert(&7, &ctx.stack_arg(1).ok_or(255)?, 0);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
