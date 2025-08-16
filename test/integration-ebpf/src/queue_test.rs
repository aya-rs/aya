#![no_std]
#![no_main]

use aya_ebpf::maps::{Array, Queue};
use aya_ebpf::{
    cty::c_long,
    macros::{map, uprobe},
    programs::ProbeContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

const PEEK_INDEX: u32 = 0;
const POP_INDEX: u32 = 1;

#[map]
static RESULT: Array<i64> = Array::<i64>::with_max_entries(2, 0);

#[map]
static TEST_QUEUE: Queue<i64> = Queue::with_max_entries(10, 0);

#[uprobe]
pub fn test_queue_push(ctx: ProbeContext) -> Result<(), c_long> {
    let value: i64 = ctx.arg(0).ok_or(-1)?;
    TEST_QUEUE.push(&value, 0)?;
    Ok(())
}

#[uprobe]
pub fn test_queue_peek(_: ProbeContext) -> Result<(), c_long> {
    let value = TEST_QUEUE.peek().unwrap_or(-1);
    let result = RESULT.get_ptr_mut(PEEK_INDEX).ok_or(-1)?;
    unsafe {
        *result = value;
    }
    Ok(())
}

#[uprobe]
pub fn test_queue_pop(_: ProbeContext) -> Result<(), c_long> {
    let value = TEST_QUEUE.pop().unwrap_or(-1);
    let result = RESULT.get_ptr_mut(POP_INDEX).ok_or(-1)?;
    unsafe {
        *result = value;
    }
    Ok(())
}
