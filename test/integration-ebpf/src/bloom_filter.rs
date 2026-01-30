#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    cty::c_long,
    macros::{map, uprobe},
    maps::{Array, bloom_filter::BloomFilter},
    programs::ProbeContext,
};

#[map]
static mut BLOOMFILTER: BloomFilter<u32> = BloomFilter::with_max_entries(4, 0);

#[map]
static RESULT: Array<i64> = Array::with_max_entries(1, 0);

#[uprobe]
fn test_contains(ctx: ProbeContext) -> Result<(), c_long> {
    let value = ctx.arg(0).ok_or(-1)?;

    // Reset result
    RESULT.set(0, 0, 0)?;

    #[allow(static_mut_refs)]
    match unsafe { BLOOMFILTER.contains(&value) } {
        Ok(_) => RESULT.set(0, 1, 0)?,
        Err(err) => RESULT.set(0, err, 0)?,
    }

    Ok(())
}

#[uprobe]
fn test_insert(ctx: ProbeContext) -> Result<(), c_long> {
    let value = ctx.arg(0).ok_or(-1)?;

    // Reset result
    RESULT.set(0, 0, 0)?;

    #[allow(static_mut_refs)]
    match unsafe { BLOOMFILTER.insert(&value, 0) } {
        Ok(_) => RESULT.set(0, 1, 0)?,
        Err(err) => RESULT.set(0, err, 0)?,
    }

    Ok(())
}
