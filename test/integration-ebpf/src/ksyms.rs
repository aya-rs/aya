#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]
use aya_ebpf::{
    macros::{map, tracepoint},
    maps::Array,
    programs::TracePointContext,
};

#[cfg(not(test))]
extern crate ebpf_panic;

#[repr(C)]
struct TestData {
    counter: u64,
    read_value: u64,
}

#[map]
static DATA_MAP: Array<TestData> = Array::with_max_entries(1, 0);

// Opaque type for dynptr
#[repr(C)]
struct bpf_dynptr {
    _opaque: [u64; 2],
}

unsafe extern "C" {
    // Kfunc with multiple arguments: (data, size, flags, dynptr)
    fn bpf_dynptr_from_mem(data: *mut u8, size: u32, flags: u64, ptr: *mut bpf_dynptr) -> i32;

    // Kfunc with multiple arguments: (dynptr, offset, dst, len)
    fn bpf_dynptr_read(ptr: *const bpf_dynptr, offset: u32, dst: *mut u8, len: u32) -> i32;
}

#[tracepoint]
fn sys_enter(ctx: TracePointContext) -> u32 {
    match try_sys_enter(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_sys_enter(_ctx: &TracePointContext) -> Result<(), ()> {
    unsafe {
        if let Some(data) = DATA_MAP.get_ptr_mut(0) {
            // Test data
            let mut test_val: u64 = 0x1234567890ABCDEF;
            let mut dynptr: bpf_dynptr = core::mem::zeroed();

            // Test kfunc with 4 arguments
            let ret = bpf_dynptr_from_mem(
                &mut test_val as *mut u64 as *mut u8,
                8, // size
                0, // flags
                &mut dynptr,
            );

            if ret == 0 {
                let mut read_buf: u64 = 0;

                // Test another kfunc with 4 arguments
                let ret = bpf_dynptr_read(
                    &dynptr,
                    0, // offset
                    &mut read_buf as *mut u64 as *mut u8,
                    8, // len
                );

                if ret == 0 {
                    (*data).read_value = read_buf;
                }
            }

            (*data).counter = (*data).counter.wrapping_add(1);
        }
    }

    Ok(())
}
