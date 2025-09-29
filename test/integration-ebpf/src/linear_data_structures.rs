#![no_std]
#![no_main]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    cty::c_long,
    macros::{map, uprobe},
    maps::{Array, Queue, Stack},
    programs::ProbeContext,
};
use integration_common::linear_data_structures::{PEEK_INDEX, POP_INDEX};

#[map]
static RESULT: Array<u64> = Array::<u64>::with_max_entries(2, 0);

#[inline(always)]
fn result_set(index: u32, value: u64) -> Result<(), c_long> {
    let ptr = RESULT.get_ptr_mut(index).ok_or(-1)?;
    let dst = unsafe { ptr.as_mut() };
    let dst_res = dst.ok_or(-1)?;
    *dst_res = value;
    Ok(())
}

macro_rules! define_linear_ds_test {
    ($Type:ident, $map_ident:ident,
        push_fn: $push_fn:ident,
        pop_fn: $pop_fn:ident,
        peek_fn: $peek_fn:ident,
    ) => {
        #[map]
        static $map_ident: $Type<u64> = $Type::with_max_entries(10, 0);

        #[uprobe]
        pub fn $push_fn(ctx: ProbeContext) -> Result<(), c_long> {
            let value = ctx.arg(0).ok_or(-1)?;
            $map_ident.push(&value, 0)?;
            Ok(())
        }

        #[uprobe]
        pub fn $pop_fn(_: ProbeContext) -> Result<(), c_long> {
            let value = $map_ident.pop().ok_or(-1)?;
            result_set(POP_INDEX, value)?;
            Ok(())
        }

        #[uprobe]
        pub fn $peek_fn(_: ProbeContext) -> Result<(), c_long> {
            let value = $map_ident.peek().ok_or(-1)?;
            result_set(PEEK_INDEX, value)?;
            Ok(())
        }
    };
}

define_linear_ds_test!(Stack, TEST_STACK,
    push_fn: test_stack_push,
    pop_fn: test_stack_pop,
    peek_fn: test_stack_peek,
);

define_linear_ds_test!(Queue, TEST_QUEUE,
    push_fn: test_queue_push,
    pop_fn: test_queue_pop,
    peek_fn: test_queue_peek,
);
