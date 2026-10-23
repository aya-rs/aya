#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{fexit, fmod_ret, map},
    maps::Array,
    programs::{FExitContext, FModRetContext},
};
use integration_common::fmod_ret::{
    ARGUMENT_INDEX, CONTROL_COUNT, FEXIT_RAN_INDEX, INCOMING_RETURN_INDEX, LONG_MODIFIER_RAN_INDEX,
    MODIFIER_RAN_INDEX, NOT_RUN, PASS_THROUGH, RESULT_COUNT, RETURN_VALUE_INDEX,
    RETURNED_VALUE_INDEX, SENDER_TGID_INDEX, SIDE_EFFECT_INDEX, TEST_RAN,
};

#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static CONTROL: Array<i32> = Array::with_max_entries(CONTROL_COUNT, 0);

#[map]
static RESULTS: Array<i32> = Array::with_max_entries(RESULT_COUNT, 0);

#[inline(always)]
fn record(index: u32, value: i32) {
    if let Some(slot) = RESULTS.get_ptr_mut(index) {
        // SAFETY: Aya bounds-checks the per-test array index; this test runs serially.
        unsafe {
            *slot = value;
        }
    }
}

#[fmod_ret(function = "bpf_modify_return_test")]
fn modify_return(ctx: FModRetContext) -> i32 {
    record(MODIFIER_RAN_INDEX, TEST_RAN);
    record(ARGUMENT_INDEX, ctx.arg(0));
    record(INCOMING_RETURN_INDEX, ctx.ret().unwrap_or(NOT_RUN));
    CONTROL
        .get(RETURN_VALUE_INDEX)
        .copied()
        .unwrap_or(PASS_THROUGH)
}

#[fexit(function = "bpf_modify_return_test")]
fn observe_return(ctx: FExitContext) -> i32 {
    record(FEXIT_RAN_INDEX, TEST_RAN);
    record(RETURNED_VALUE_INDEX, ctx.ret().unwrap_or(NOT_RUN));
    let value: *const i32 = ctx.arg(1);
    // SAFETY: the helper copies the target's live integer argument without retaining its pointer.
    record(
        SIDE_EFFECT_INDEX,
        unsafe { bpf_probe_read_kernel(value) }.unwrap_or(NOT_RUN),
    );
    0
}

#[fmod_ret]
fn modify_long_return(_ctx: FModRetContext) -> i32 {
    let sender = CONTROL.get(SENDER_TGID_INDEX).copied().unwrap_or(0) as u32;
    if sender == 0 || (bpf_get_current_pid_tgid() >> 32) as u32 != sender {
        return PASS_THROUGH;
    }
    record(LONG_MODIFIER_RAN_INDEX, TEST_RAN);
    CONTROL
        .get(RETURN_VALUE_INDEX)
        .copied()
        .unwrap_or(PASS_THROUGH)
}
