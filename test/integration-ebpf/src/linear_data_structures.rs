#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    btf_maps::{Array as BtfArray, Queue as BtfQueue, Stack as BtfStack},
    cty::c_long,
    macros::{btf_map, map, uprobe},
    maps::{Array, Queue, Stack},
    programs::ProbeContext,
};
use integration_common::linear_data_structures::{PEEK_INDEX, POP_INDEX};

#[btf_map]
static RESULT: BtfArray<u64, 2, 0> = BtfArray::new();

#[btf_map]
static TEST_QUEUE: BtfQueue<u64, 10> = BtfQueue::new();

#[btf_map]
static TEST_STACK: BtfStack<u64, 10> = BtfStack::new();

#[map]
static RESULT_LEGACY: Array<u64> = Array::<u64>::with_max_entries(2, 0);

#[map]
static TEST_QUEUE_LEGACY: Queue<u64> = Queue::with_max_entries(10, 0);

#[map]
static TEST_STACK_LEGACY: Stack<u64> = Stack::with_max_entries(10, 0);

macro_rules! define_linear_ds_test {
    ($map:ident, $result_map:ident,
        push_fn: $push_fn:ident,
        pop_fn: $pop_fn:ident,
        peek_fn: $peek_fn:ident
        $(,)?
    ) => {
        #[uprobe]
        fn $push_fn(ctx: ProbeContext) -> Result<(), c_long> {
            let value = ctx.arg(0).ok_or(-1)?;
            $map.push(&value, 0)?;
            Ok(())
        }

        define_linear_ds_test!(@probe $map, $result_map, $pop_fn, pop, POP_INDEX);
        define_linear_ds_test!(@probe $map, $result_map, $peek_fn, peek, PEEK_INDEX);
    };

    (@probe $map:ident, $result_map:ident, $fn:ident, $method:ident, $idx:ident) => {
        #[uprobe]
        fn $fn(_: ProbeContext) -> Result<(), c_long> {
            let value = $map.$method()?.ok_or(-1)?;
            let ptr = $result_map.get_ptr_mut($idx).ok_or(-1)?;
            let dst = unsafe { ptr.as_mut() };
            let dst_res = dst.ok_or(-1)?;
            *dst_res = value;
            Ok(())
        }
    };
}

define_linear_ds_test!(TEST_STACK, RESULT,
    push_fn: test_stack_push,
    pop_fn: test_stack_pop,
    peek_fn: test_stack_peek,
);

define_linear_ds_test!(TEST_STACK_LEGACY, RESULT_LEGACY,
    push_fn: test_stack_push_legacy,
    pop_fn: test_stack_pop_legacy,
    peek_fn: test_stack_peek_legacy,
);

define_linear_ds_test!(TEST_QUEUE, RESULT,
    push_fn: test_queue_push,
    pop_fn: test_queue_pop,
    peek_fn: test_queue_peek,
);

define_linear_ds_test!(TEST_QUEUE_LEGACY, RESULT_LEGACY,
    push_fn: test_queue_push_legacy,
    pop_fn: test_queue_pop_legacy,
    peek_fn: test_queue_peek_legacy,
);
