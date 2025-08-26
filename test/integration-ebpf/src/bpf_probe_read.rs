#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes},
    macros::{map, uprobe},
    maps::Array,
    programs::ProbeContext,
};
use integration_common::bpf_probe_read::{RESULT_BUF_LEN, TestResult};
#[cfg(not(test))]
extern crate ebpf_panic;

fn read_str_bytes(
    fun: unsafe fn(*const u8, &mut [u8]) -> Result<&[u8], i64>,
    iptr: Option<*const u8>,
    ilen: Option<usize>,
) {
    let Some(iptr) = iptr else {
        return;
    };
    let Some(ilen) = ilen else {
        return;
    };
    let Ok(ptr) = RESULT.get_ptr_mut(0) else {
        return;
    };
    let dst = unsafe { ptr.as_mut() };
    let Some(TestResult { buf, len }) = dst else {
        return;
    };
    *len = None;

    // len comes from ctx.arg(1) so it's dynamic and the verifier doesn't see any bounds. We slice
    // here to ensure that the verifier can see the upper bound, or you get:
    //
    // 18: (79) r7 = *(u64 *)(r7 +8)         ; R7_w=scalar()
    // [snip]
    // 27: (bf) r2 = r7                      ;
    // R2_w=scalar(id=2,umax=9223372036854775807,var_off=(0x0; 0x7fffffffffffffff)) [snip]
    // 28: (85) call bpf_probe_read_user_str#114
    // R2 unbounded memory access, use 'var &= const' or 'if (var < const)'
    let Some(buf) = buf.get_mut(..ilen) else {
        return;
    };

    *len = Some(unsafe { fun(iptr, buf) }.map(<[_]>::len));
}

#[map]
static RESULT: Array<TestResult> = Array::with_max_entries(1, 0);

#[map]
static KERNEL_BUFFER: Array<[u8; RESULT_BUF_LEN]> = Array::with_max_entries(1, 0);

#[uprobe]
pub fn test_bpf_probe_read_user_str_bytes(ctx: ProbeContext) {
    read_str_bytes(
        bpf_probe_read_user_str_bytes,
        ctx.arg::<*const u8>(0),
        ctx.arg::<usize>(1),
    );
}

#[uprobe]
pub fn test_bpf_probe_read_kernel_str_bytes(ctx: ProbeContext) {
    read_str_bytes(
        bpf_probe_read_kernel_str_bytes,
        KERNEL_BUFFER
            .get_ptr(0)
            .ok()
            .and_then(|ptr| unsafe { ptr.as_ref() })
            .map(|buf| buf.as_ptr()),
        ctx.arg::<usize>(0),
    );
}
