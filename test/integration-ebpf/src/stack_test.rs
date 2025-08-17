#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_long,
    macros::{map, uprobe},
    maps::{Array, Stack},
    programs::ProbeContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

const PEEK_INDEX: u32 = 0;
const POP_INDEX: u32 = 1;

#[map]
static RESULT: Array<u64> = Array::<u64>::with_max_entries(2, 0);

#[map]
static TEST_STACK: Stack<u64> = Stack::with_max_entries(10, 0);

#[uprobe]
pub fn test_stack_push(ctx: ProbeContext) -> Result<(), c_long> {
    let value = ctx.arg(0).ok_or(-1)?;
    TEST_STACK.push(&value, 0)?;
    Ok(())
}

#[uprobe]
pub fn test_stack_pop(_: ProbeContext) -> Result<(), c_long> {
    let value = TEST_STACK.pop().ok_or(-1)?;
    result_set(POP_INDEX, value)?;
    Ok(())
}

#[uprobe]
pub fn test_stack_peek(_: ProbeContext) -> Result<(), c_long> {
    let value = TEST_STACK.peek().ok_or(-1)?;
    result_set(PEEK_INDEX, value)?;
    Ok(())
}

fn result_set(index: u32, value: u64) -> Result<(), c_long> {
    let ptr = RESULT.get_ptr_mut(index).ok_or(-1)?;
    let dst = unsafe { ptr.as_mut() };
    let dst_res = dst.ok_or(-1)?;
    *dst_res = value;
    Ok(())
}
