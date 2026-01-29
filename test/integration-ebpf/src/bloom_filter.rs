#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    cty::c_long,
    macros::{map, uprobe},
    maps::{Array, BloomFilter},
    programs::ProbeContext,
};
use integration_common::bloom_filter::CONTAINS_ABSENT_INDEX;

const RESULT_SLOTS: u32 = CONTAINS_ABSENT_INDEX + 1;

#[map]
static RESULT: Array<i32> = Array::<i32>::with_max_entries(RESULT_SLOTS, 0);

#[map]
static FILTER: BloomFilter<u32> = BloomFilter::with_max_entries(64, 0);

#[inline(always)]
fn map_result(result: Result<(), c_long>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(err) => err as i32,
    }
}

#[uprobe]
fn bloom_filter_insert(ctx: ProbeContext) -> Result<(), i32> {
    let index: u32 = ctx.arg(0).ok_or(-1)?;
    let value: u32 = ctx.arg(1).ok_or(-1)?;
    let result = map_result(FILTER.insert(value, 0));
    RESULT.set(index, result, 0)
}

#[uprobe]
fn bloom_filter_contains(ctx: ProbeContext) -> Result<(), i32> {
    let index: u32 = ctx.arg(0).ok_or(-1)?;
    let value: u32 = ctx.arg(1).ok_or(-1)?;
    let result = map_result(FILTER.contains(value));
    RESULT.set(index, result, 0)
}
