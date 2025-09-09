#![no_std]
#![no_main]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    btf_maps::Array,
    cty::c_long,
    macros::{btf_map, map, uprobe},
    maps::Array as LegacyArray,
    programs::ProbeContext,
};
use integration_common::array::{GET_INDEX, GET_PTR_INDEX, GET_PTR_MUT_INDEX};

#[btf_map]
static RESULT: Array<u32, 3 /* max_elements */, 0> = Array::new();
#[btf_map]
static ARRAY: Array<u32, 10 /* max_elements */, 0> = Array::new();

#[map]
static RESULT_LEGACY: LegacyArray<u32> = LegacyArray::with_max_entries(3, 0);
#[map]
static ARRAY_LEGACY: LegacyArray<u32> = LegacyArray::with_max_entries(10, 0);

macro_rules! define_array_test {
    (
        $result_map:ident,
        $array_map:ident,
        $result_set_fn:ident,
        $set_prog:ident,
        $get_prog:ident,
        $get_ptr_prog:ident,
        $get_ptr_mut_prog:ident
        $(,)?
    ) => {
        #[inline(always)]
        fn $result_set_fn(index: u32, value: u32) -> Result<(), c_long> {
            let ptr = $result_map.get_ptr_mut(index).ok_or(-1)?;
            let dst = unsafe { ptr.as_mut() };
            let dst_res = dst.ok_or(-1)?;
            *dst_res = value;
            Ok(())
        }

        #[uprobe]
        pub fn $set_prog(ctx: ProbeContext) -> Result<(), c_long> {
            let index = ctx.arg(0).ok_or(-1)?;
            let value = ctx.arg(1).ok_or(-1)?;
            $array_map.set(index, &value, 0)?;
            Ok(())
        }

        #[uprobe]
        pub fn $get_prog(ctx: ProbeContext) -> Result<(), c_long> {
            let index = ctx.arg(0).ok_or(-1)?;
            let value = $array_map.get(index)?.ok_or(-1)?;
            $result_set_fn(GET_INDEX, *value)?;
            Ok(())
        }

        #[uprobe]
        pub fn $get_ptr_prog(ctx: ProbeContext) -> Result<(), c_long> {
            let index = ctx.arg(0).ok_or(-1)?;
            let value = $array_map.get_ptr(index).ok_or(-1)?;
            $result_set_fn(GET_PTR_INDEX, unsafe { *value })?;
            Ok(())
        }

        #[uprobe]
        pub fn $get_ptr_mut_prog(ctx: ProbeContext) -> Result<(), c_long> {
            let index = ctx.arg(0).ok_or(-1)?;
            let ptr = $array_map.get_ptr_mut(index).ok_or(-1)?;
            let value = unsafe { *ptr };
            $result_set_fn(GET_PTR_MUT_INDEX, value)?;
            Ok(())
        }
    };
}

define_array_test!(RESULT, ARRAY, result_set, set, get, get_ptr, get_ptr_mut);
define_array_test!(
    RESULT_LEGACY,
    ARRAY_LEGACY,
    result_set_legacy,
    set_legacy,
    get_legacy,
    get_ptr_legacy,
    get_ptr_mut_legacy,
);
