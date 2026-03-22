#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    btf_maps::BloomFilter,
    cty::c_long,
    macros::{btf_map, map, uprobe},
    maps::Array,
    programs::ProbeContext,
};
use integration_common::bloom_filter::CONTAINS_ABSENT_INDEX;

const RESULT_SLOTS: usize = (CONTAINS_ABSENT_INDEX + 1) as usize;

#[map]
static RESULT: Array<i32> = Array::with_max_entries(RESULT_SLOTS as u32, 0);

#[btf_map]
static FILTER: BloomFilter<u32, 64, 0, 3> = BloomFilter::new();

#[inline(always)]
const fn map_result(result: Result<(), c_long>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(err) => err as i32,
    }
}

#[uprobe]
fn btf_bloom_filter_insert(ctx: ProbeContext) -> Result<(), i32> {
    let index: u32 = ctx.arg(0).ok_or(-1)?;
    let value: u32 = ctx.arg(1).ok_or(-1)?;
    let result = map_result(FILTER.insert(value, 0));
    RESULT.set(index, result, 0)
}

#[uprobe]
fn btf_bloom_filter_contains(ctx: ProbeContext) -> Result<(), i32> {
    let index: u32 = ctx.arg(0).ok_or(-1)?;
    let value: u32 = ctx.arg(1).ok_or(-1)?;
    let result = map_result(FILTER.contains(value));
    RESULT.set(index, result, 0)
}
