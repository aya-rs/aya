#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    btf_maps::{Array as BtfArray, BloomFilter as BtfBloomFilter},
    cty::c_long,
    macros::{btf_map, map, uprobe},
    maps::{Array as LegacyArray, BloomFilter as LegacyBloomFilter},
    programs::ProbeContext,
};
use integration_common::bloom_filter::CONTAINS_ABSENT_INDEX;

const RESULT_SLOTS: u32 = CONTAINS_ABSENT_INDEX + 1;

#[btf_map]
static RESULT: BtfArray<i32, { RESULT_SLOTS as usize }, 0> = BtfArray::new();

#[btf_map]
static FILTER: BtfBloomFilter<u32, 64, 0, 3> = BtfBloomFilter::new();

#[map]
static RESULT_LEGACY: LegacyArray<i32> = LegacyArray::<i32>::with_max_entries(RESULT_SLOTS, 0);

#[map]
static FILTER_LEGACY: LegacyBloomFilter<u32> = LegacyBloomFilter::with_max_entries(64, 0);

#[inline(always)]
const fn map_result(result: Result<(), c_long>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(err) => err as i32,
    }
}

macro_rules! define_bloom_filter_test {
    (
        $result_map:ident,
        $filter_map:ident,
        $insert_prog:ident,
        $contains_prog:ident
        $(,)?
    ) => {
        #[uprobe]
        fn $insert_prog(ctx: ProbeContext) -> Result<(), i32> {
            let index: u32 = ctx.arg(0).ok_or(-1)?;
            let value: u32 = ctx.arg(1).ok_or(-1)?;
            let result = map_result($filter_map.insert(value, 0));
            $result_map.set(index, result, 0)
        }

        #[uprobe]
        fn $contains_prog(ctx: ProbeContext) -> Result<(), i32> {
            let index: u32 = ctx.arg(0).ok_or(-1)?;
            let value: u32 = ctx.arg(1).ok_or(-1)?;
            let result = map_result($filter_map.contains(value));
            $result_map.set(index, result, 0)
        }
    };
}

define_bloom_filter_test!(
    RESULT,
    FILTER,
    btf_bloom_filter_insert,
    btf_bloom_filter_contains,
);
define_bloom_filter_test!(
    RESULT_LEGACY,
    FILTER_LEGACY,
    bloom_filter_insert_legacy,
    bloom_filter_contains_legacy,
);
