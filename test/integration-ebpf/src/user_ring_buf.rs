#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use core::ops::ControlFlow;

use aya_ebpf::{
    btf_maps::{RingBuf, UserRingBuf as BtfUserRingBuf},
    macros::{btf_map, map, uprobe},
    maps::{Array, UserRingBuf as LegacyUserRingBuf, user_ring_buf::UserRingBufEntry},
    programs::ProbeContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

#[btf_map]
static USER_RING_BUF: BtfUserRingBuf<u64, 0, 0> = BtfUserRingBuf::new();

#[map]
static USER_RING_BUF_LEGACY: LegacyUserRingBuf = LegacyUserRingBuf::with_byte_size(0, 0);

// Each drained sample is echoed back to user space through this ring buffer so the test can assert
// on the values the kernel observed.
#[btf_map]
static RESULT: RingBuf<u64, 0, 0> = RingBuf::new();

// The number of samples the last drain reported, so the test can assert on the drain return value.
#[map]
static DRAIN_COUNT: Array<u64> = Array::with_max_entries(1, 0);

fn echo_sample(entry: UserRingBufEntry<'_>) {
    // SAFETY: the test publishes `u64` samples, and `u64` is valid for any bit pattern. A sample
    // too short to hold a `u64` yields `None` and is skipped.
    if let Some(value) = unsafe { entry.read::<u64>() } {
        let _result = RESULT.output(value, 0);
    }
}

// Echoes every sample, draining the whole ring buffer.
fn echo(entry: UserRingBufEntry<'_>) -> ControlFlow<()> {
    echo_sample(entry);
    ControlFlow::Continue(())
}

// Echoes a single sample and then stops, leaving the rest of the ring buffer undrained.
fn echo_once(entry: UserRingBufEntry<'_>) -> ControlFlow<()> {
    echo_sample(entry);
    ControlFlow::Break(())
}

macro_rules! define_user_ring_buf_drain {
    ($name:ident, $map:expr, $callback:expr) => {
        #[uprobe]
        fn $name(_ctx: ProbeContext) {
            if let Ok(drained) = $map.drain($callback, 0) {
                if let Some(count) = DRAIN_COUNT.get_ptr_mut(0) {
                    // SAFETY: the integration tests run single-threaded, so this is the only writer
                    // of slot 0.
                    unsafe { *count = drained.into() };
                }
            }
        }
    };
}

define_user_ring_buf_drain!(user_ring_buf_test, USER_RING_BUF, echo);
define_user_ring_buf_drain!(user_ring_buf_test_legacy, USER_RING_BUF_LEGACY, echo);
define_user_ring_buf_drain!(user_ring_buf_test_break, USER_RING_BUF, echo_once);
define_user_ring_buf_drain!(
    user_ring_buf_test_break_legacy,
    USER_RING_BUF_LEGACY,
    echo_once
);
