#![no_std]
#![no_main]
#![expect(internal_features, reason = "atomic_xadd is unstable")]
#![expect(unstable_features, reason = "atomic_xadd is unstable")]
#![feature(core_intrinsics)]

use aya_ebpf::{
    btf_maps::RingBuf as BtfRingBuf,
    macros::{btf_map, map, uprobe},
    maps::{Array, RingBuf as LegacyRingBuf},
    programs::ProbeContext,
};
use integration_common::ring_buf::{AlignedEvent, OUTPUT_ARGUMENT, PageEvent, Registers};
#[cfg(not(test))]
extern crate ebpf_panic;

#[btf_map]
static RING_BUF: BtfRingBuf<u64, 0, 0> = BtfRingBuf::new();

#[btf_map]
static RING_BUF_MISMATCH: BtfRingBuf<u32, 0, 0> = BtfRingBuf::new();

#[btf_map]
static RING_BUF_ALIGNED: BtfRingBuf<AlignedEvent, 0, 0> = BtfRingBuf::new();

#[map]
static RING_BUF_LEGACY: LegacyRingBuf = LegacyRingBuf::with_byte_size(0, 0);

#[map]
static REGISTERS: Array<Registers> = Array::with_max_entries(1, 0);

#[map]
static REGISTERS_LEGACY: Array<Registers> = Array::with_max_entries(1, 0);

macro_rules! define_ring_buf_test {
    ($registers:ident, $name:ident, $reserve:expr) => {
        #[uprobe]
        fn $name(ctx: ProbeContext) {
            let Some(regs) = $registers.get_ptr_mut(0) else {
                return;
            };
            let Some(mut entry) = $reserve else {
                unsafe {
                    core::intrinsics::atomic_xadd::<
                        u64,
                        u64,
                        { core::intrinsics::AtomicOrdering::Relaxed },
                    >(&raw mut (*regs).dropped, 1);
                }
                return;
            };
            // Write the first argument to the function back out to RING_BUF if it is even,
            // otherwise increment the counter in REJECTED. This exercises discarding data.
            let arg: u64 = match ctx.arg(0) {
                Some(arg) => arg,
                None => return,
            };
            if arg.is_multiple_of(2) {
                entry.write(arg);
                entry.submit(0);
            } else {
                unsafe {
                    core::intrinsics::atomic_xadd::<
                        u64,
                        u64,
                        { core::intrinsics::AtomicOrdering::Relaxed },
                    >(&raw mut (*regs).rejected, 1);
                }
                entry.discard(0);
            }
        }
    };
}

define_ring_buf_test!(REGISTERS, ring_buf_test, RING_BUF.reserve(0));
define_ring_buf_test!(
    REGISTERS_LEGACY,
    ring_buf_test_legacy,
    RING_BUF_LEGACY.reserve::<u64>(0)
);

macro_rules! define_ring_buf_mismatch {
    ($name:ident, $ty:ty) => {
        #[uprobe]
        fn $name(ctx: ProbeContext) {
            let Some(mut entry) = RING_BUF_MISMATCH.reserve_untyped::<$ty>(0) else {
                return;
            };
            let arg: $ty = match ctx.arg(0) {
                Some(arg) => arg,
                None => return,
            };
            entry.write(arg);
            entry.submit(0);
        }
    };
}

define_ring_buf_mismatch!(ring_buf_mismatch_small, u16);
define_ring_buf_mismatch!(ring_buf_mismatch_large, u64);

macro_rules! define_ring_buf_aligned {
    ($name:ident, $ring:ident, $reserve:expr) => {
        #[uprobe]
        fn $name(ctx: ProbeContext) {
            let Some(arg) = ctx.arg::<u64>(0) else { return };
            // A 24-byte record (including its header) changes the next
            // reservation's position modulo 32, covering all four paddings.
            let Some(prefix) = $ring.reserve_bytes(16, 0) else {
                return;
            };
            prefix.discard(0);
            let Some(mut entry) = $reserve else { return };
            let value = entry.write(AlignedEvent([arg, arg + 1, arg + 2, arg + 3]));
            if arg == OUTPUT_ARGUMENT {
                // Copy from an aligned reservation instead of a temporary:
                // the BPF stack only guarantees eight-byte alignment.
                let _result: Result<(), i32> = $ring.output(value, 0);
                entry.discard(0);
            } else if arg & 4 == 0 {
                entry.submit(0);
            } else {
                entry.discard(0);
            }
        }
    };
}

define_ring_buf_aligned!(
    ring_buf_aligned,
    RING_BUF_ALIGNED,
    RING_BUF_ALIGNED.reserve(0)
);
define_ring_buf_aligned!(
    ring_buf_aligned_legacy,
    RING_BUF_LEGACY,
    RING_BUF_LEGACY.reserve::<AlignedEvent>(0)
);

#[uprobe]
fn ring_buf_page_aligned(_ctx: ProbeContext) {
    let Some(mut entry) = RING_BUF_LEGACY.reserve::<PageEvent>(0) else {
        return;
    };
    // Initialize in place instead of materializing a value larger than the
    // BPF stack. The entire reservation payload is written before submission.
    unsafe {
        entry.as_mut_ptr().write_bytes(42, 1);
    }
    entry.submit(0);
}
