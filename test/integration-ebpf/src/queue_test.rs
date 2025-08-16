#![no_std]
#![no_main]

use aya_ebpf::{
    cty::{c_int, c_long},
    macros::{map, uprobe},
    maps::{Array, Queue},
    programs::ProbeContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

const PEEK_INDEX: u32 = 0;
const POP_INDEX: u32 = 1;

#[map]
static RESULT: Array<c_int> = Array::<c_int>::with_max_entries(10, 0);

#[map]
static TEST_QUEUE: Queue<c_int> = Queue::with_max_entries(10, 0);

#[uprobe]
pub fn test_queue_push(ctx: ProbeContext) -> Result<(), c_long> {
    let value: c_int = ctx.arg(0).ok_or(-2)?;
    TEST_QUEUE.push(&value, 0)?;
    Ok(())
}

#[uprobe]
pub fn test_queue_peek(_: ProbeContext) -> Result<(), c_long> {
    let value = TEST_QUEUE.peek().unwrap_or(-1);
    result_set(PEEK_INDEX, value)?;
    Ok(())
}

#[uprobe]
pub fn test_queue_pop(_: ProbeContext) -> Result<(), c_long> {
    let value = TEST_QUEUE.pop().unwrap_or(-1);
    result_set(POP_INDEX, value)?;
    Ok(())
}

fn result_set(index: u32, value: c_int) -> Result<(), c_long> {
    let ptr = RESULT.get_ptr_mut(index).ok_or(-1)?;
    let dst = unsafe { ptr.as_mut() };
    let dst_res = dst.ok_or(-1)?;
    *dst_res = value;
    Ok(())
}
