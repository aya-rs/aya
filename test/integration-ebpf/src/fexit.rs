#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use core::ffi::c_void;

use aya_ebpf::{
    Argument,
    macros::{fexit, map},
    maps::Array,
    programs::FExitContext,
};
use integration_common::fexit::{
    ARG_MISMATCH, NO_ERROR, RETVAL_MISMATCH, TEST_CALLED, TEST_COUNT, TEST1_INDEX, TEST2_INDEX,
    TEST3_INDEX, TEST4_INDEX, TEST5_INDEX, TEST6_INDEX, TEST7_INDEX, TEST8_INDEX, TEST9_INDEX,
    TEST10_INDEX, TestResult,
};
#[cfg(not(test))]
extern crate ebpf_panic;

// FEXIT program return values are ignored by the tracing test-run path.
const DUMMY_FEXIT_PROG_RETVAL: i32 = 0;

#[repr(C)]
struct BpfFentryTest {
    a: *mut Self,
}

#[map]
static RESULTS: Array<TestResult> = Array::with_max_entries(TEST_COUNT, 0);

#[inline(always)]
fn record(index: u32, error: i32) {
    if let Some(result) = RESULTS.get_ptr_mut(index) {
        unsafe {
            *result = TestResult {
                called: TEST_CALLED,
                error,
            };
        }
    }
}

#[inline(always)]
fn expect_ret<T: Argument + PartialEq>(ctx: &FExitContext, expected: T) -> i32 {
    match ctx.ret::<T>() {
        Ok(retval) if retval == expected => NO_ERROR,
        Ok(_) => RETVAL_MISMATCH,
        Err(error) => error,
    }
}

// Mirrors libbpf's fexit selftest and the kernel's synthetic tracing sequence.
// The argument and return values below come from the kernel's fixed
// BPF_PROG_TEST_RUN tracing target calls.
// https://github.com/torvalds/linux/blob/v7.1-rc4/tools/testing/selftests/bpf/progs/fexit_test.c#L10-L80
// https://github.com/torvalds/linux/blob/v7.1-rc4/net/bpf/test_run.c#L706-L715
#[fexit(function = "bpf_fentry_test1")]
fn test1(ctx: FExitContext) -> i32 {
    let error = if ctx.arg::<i32>(0) == 1 {
        expect_ret::<i32>(&ctx, 2)
    } else {
        ARG_MISMATCH
    };
    record(TEST1_INDEX, error);
    DUMMY_FEXIT_PROG_RETVAL
}

#[fexit(function = "bpf_fentry_test2")]
fn test2(ctx: FExitContext) -> i32 {
    let error = if ctx.arg::<i32>(0) != 2 || ctx.arg::<u64>(1) != 3 {
        ARG_MISMATCH
    } else {
        expect_ret::<i32>(&ctx, 5)
    };
    record(TEST2_INDEX, error);
    DUMMY_FEXIT_PROG_RETVAL
}

#[fexit(function = "bpf_fentry_test3")]
fn test3(ctx: FExitContext) -> i32 {
    let error = if ctx.arg::<i8>(0) != 4 || ctx.arg::<i32>(1) != 5 || ctx.arg::<u64>(2) != 6 {
        ARG_MISMATCH
    } else {
        expect_ret::<i32>(&ctx, 15)
    };
    record(TEST3_INDEX, error);
    DUMMY_FEXIT_PROG_RETVAL
}

#[fexit(function = "bpf_fentry_test4")]
fn test4(ctx: FExitContext) -> i32 {
    let error = if ctx.arg::<*mut c_void>(0) as u64 != 7
        || ctx.arg::<i8>(1) != 8
        || ctx.arg::<i32>(2) != 9
        || ctx.arg::<u64>(3) != 10
    {
        ARG_MISMATCH
    } else {
        expect_ret::<i32>(&ctx, 34)
    };
    record(TEST4_INDEX, error);
    DUMMY_FEXIT_PROG_RETVAL
}

#[fexit(function = "bpf_fentry_test5")]
fn test5(ctx: FExitContext) -> i32 {
    let error = if ctx.arg::<u64>(0) != 11
        || ctx.arg::<*mut c_void>(1) as u64 != 12
        || ctx.arg::<i16>(2) != 13
        || ctx.arg::<i32>(3) != 14
        || ctx.arg::<u64>(4) != 15
    {
        ARG_MISMATCH
    } else {
        expect_ret::<i32>(&ctx, 65)
    };
    record(TEST5_INDEX, error);
    DUMMY_FEXIT_PROG_RETVAL
}

#[fexit(function = "bpf_fentry_test6")]
fn test6(ctx: FExitContext) -> i32 {
    let error = if ctx.arg::<u64>(0) != 16
        || ctx.arg::<*mut c_void>(1) as u64 != 17
        || ctx.arg::<i16>(2) != 18
        || ctx.arg::<i32>(3) != 19
        || ctx.arg::<*mut c_void>(4) as u64 != 20
        || ctx.arg::<u64>(5) != 21
    {
        ARG_MISMATCH
    } else {
        expect_ret::<i32>(&ctx, 111)
    };
    record(TEST6_INDEX, error);
    DUMMY_FEXIT_PROG_RETVAL
}

#[fexit(function = "bpf_fentry_test7")]
fn test7(ctx: FExitContext) -> i32 {
    let arg = ctx.arg::<*mut BpfFentryTest>(0);
    let error = if arg.is_null() {
        expect_ret::<i32>(&ctx, 0)
    } else {
        ARG_MISMATCH
    };
    record(TEST7_INDEX, error);
    DUMMY_FEXIT_PROG_RETVAL
}

#[fexit(function = "bpf_fentry_test8")]
fn test8(ctx: FExitContext) -> i32 {
    let arg = ctx.arg::<*mut BpfFentryTest>(0);
    let error = if arg.is_null() {
        ARG_MISMATCH
    } else {
        expect_ret::<i32>(&ctx, 0)
    };
    record(TEST8_INDEX, error);
    DUMMY_FEXIT_PROG_RETVAL
}

#[fexit(function = "bpf_fentry_test9")]
fn test9(ctx: FExitContext) -> i32 {
    let arg = ctx.arg::<*mut u32>(0);
    let error = if arg.is_null() {
        ARG_MISMATCH
    } else {
        expect_ret::<u32>(&ctx, 0)
    };
    record(TEST9_INDEX, error);
    DUMMY_FEXIT_PROG_RETVAL
}

#[fexit(function = "bpf_fentry_test10")]
fn test10(ctx: FExitContext) -> i32 {
    let error = if ctx.arg::<*const c_void>(0).is_null() {
        expect_ret::<i32>(&ctx, 0)
    } else {
        ARG_MISMATCH
    };
    record(TEST10_INDEX, error);
    DUMMY_FEXIT_PROG_RETVAL
}
