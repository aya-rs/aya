#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    btf_maps::{Array, LpmTrie, lpm_trie::Key},
    macros::{btf_map, uprobe},
    programs::ProbeContext,
};
use integration_common::btf_lpm_trie::{LPM_MATCH_SLOT, NO_MATCH_SLOT, REMOVE_SLOT, TestResult};

#[cfg(not(test))]
extern crate ebpf_panic;

#[btf_map]
static ROUTES: LpmTrie<[u8; 4], u32, 64> = LpmTrie::new();

#[btf_map]
static RESULTS: Array<TestResult, 3> = Array::new();

#[inline(always)]
fn record(slot: u32, key: &Key<[u8; 4]>) {
    if let Some(ptr) = RESULTS.get_ptr_mut(slot) {
        if let Some(val) = ROUTES.get(key) {
            unsafe {
                (*ptr).value = *val;
            }
        }
        unsafe {
            (*ptr).ran = 1;
        }
    }
}

#[uprobe]
pub(crate) fn test_btf_lpm_trie(_ctx: ProbeContext) -> u32 {
    record(LPM_MATCH_SLOT, &Key::new(32, [192, 168, 1, 42]));
    record(NO_MATCH_SLOT, &Key::new(32, [10, 0, 0, 1]));
    if ROUTES.remove(&Key::new(24, [192, 168, 1, 0])).is_ok() {
        record(REMOVE_SLOT, &Key::new(32, [192, 168, 1, 42]));
    }

    0
}
