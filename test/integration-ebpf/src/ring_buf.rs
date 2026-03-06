#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]
#![expect(internal_features, reason = "atomic_xadd is unstable")]
#![expect(unstable_features, reason = "atomic_xadd is unstable")]
#![feature(core_intrinsics)]

use aya_ebpf::{
    btf_maps::RingBuf as BtfRingBuf,
    macros::{btf_map, map, uprobe},
    maps::{Array, RingBuf as LegacyRingBuf},
    programs::ProbeContext,
};
use integration_common::ring_buf::Registers;
#[cfg(not(test))]
extern crate ebpf_panic;

#[btf_map]
static RING_BUF: BtfRingBuf<u64, 0, 0> = BtfRingBuf::new();

#[btf_map]
static RING_BUF_MISMATCH: BtfRingBuf<u32, 0, 0> = BtfRingBuf::new();

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
                    >(core::ptr::addr_of_mut!((*regs).dropped), 1);
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
                    >(core::ptr::addr_of_mut!((*regs).rejected), 1);
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
