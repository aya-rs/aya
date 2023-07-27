#![no_builtins]
#![no_main]
#![no_std]

use aya_bpf::{
    helpers::{bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes},
    macros::{map, uprobe},
    maps::Array,
    programs::ProbeContext,
};

const RESULT_BUF_LEN: usize = 1024;

macro_rules! read_str_bytes {
    ($fun:ident, $ptr:expr, $len:expr $(,)?) => {
        let Some(ptr) = RESULT.get_ptr_mut(0) else {
            return;
        };
        let TestResult {
            did_error,
            len,
            buf,
        } = unsafe { &mut *ptr };

        // $len comes from ctx.arg(1) so it's dynamic and the verifier
        // doesn't see any bounds. We do $len.min(RESULT_BUF_LEN) here to
        // ensure that the verifier can see the upper bound, or you get:
        //
        // 18: (79) r7 = *(u64 *)(r7 +8)         ; R7_w=scalar()
        // [snip]
        // 27: (bf) r2 = r7                      ;
        // R2_w=scalar(id=2,umax=9223372036854775807,var_off=(0x0; 0x7fffffffffffffff)) [snip]
        // 28: (85) call bpf_probe_read_user_str#114
        // R2 unbounded memory access, use 'var &= const' or 'if (var < const)'
        let Some(buf) = buf.get_mut(..$len) else {
            return;
        };

        match unsafe { $fun($ptr, buf) } {
            Ok(s) => {
                *len = s.len();
            }
            Err(_) => {
                *did_error = 1;
            }
        }
    };
}

#[repr(C)]
struct TestResult {
    did_error: u64,
    len: usize,
    buf: [u8; RESULT_BUF_LEN],
}

#[map]
static RESULT: Array<TestResult> = Array::with_max_entries(1, 0);

#[map]
static KERNEL_BUFFER: Array<[u8; RESULT_BUF_LEN]> = Array::with_max_entries(1, 0);

#[uprobe]
pub fn test_bpf_probe_read_user_str_bytes(ctx: ProbeContext) {
    read_str_bytes!(
        bpf_probe_read_user_str_bytes,
        match ctx.arg::<*const u8>(0) {
            Some(p) => p,
            _ => return,
        },
        match ctx.arg::<usize>(1) {
            Some(p) => p,
            _ => return,
        },
    );
}

#[uprobe]
pub fn test_bpf_probe_read_kernel_str_bytes(ctx: ProbeContext) {
    read_str_bytes!(
        bpf_probe_read_kernel_str_bytes,
        match KERNEL_BUFFER.get_ptr(0) {
            Some(p) => p as *const u8,
            _ => return,
        },
        match ctx.arg::<usize>(0) {
            Some(p) => p,
            _ => return,
        },
    );
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
