#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    btf_maps::{Array as BtfArray, LpmTrie as BtfLpmTrie, lpm_trie::Key},
    macros::{btf_map, map, uprobe},
    maps::{Array as LegacyArray, LpmTrie as LegacyLpmTrie},
    programs::ProbeContext,
};
use integration_common::lpm_trie::{
    LPM_MATCH_SLOT, NO_MATCH_SLOT, NUM_SLOTS, REMOVE_SLOT, TestResult,
};

#[btf_map]
static ROUTES: BtfLpmTrie<[u8; 4], u32, 64> = BtfLpmTrie::new();

#[btf_map]
static RESULTS: BtfArray<TestResult, { NUM_SLOTS as usize }> = BtfArray::new();

#[map]
static ROUTES_LEGACY: LegacyLpmTrie<[u8; 4], u32> =
    LegacyLpmTrie::<[u8; 4], u32>::with_max_entries(64, 0);

#[map]
static RESULTS_LEGACY: LegacyArray<TestResult> =
    LegacyArray::<TestResult>::with_max_entries(NUM_SLOTS, 0);

macro_rules! define_lpm_trie_test {
    ($routes_map:ident, $results_map:ident, $probe_name:ident $(,)?) => {
        #[uprobe]
        fn $probe_name(_ctx: ProbeContext) -> u32 {
            let record = |slot: u32, key: &Key<[u8; 4]>| {
                if let Some(ptr) = $results_map.get_ptr_mut(slot) {
                    unsafe {
                        if let Some(val) = $routes_map.get(key) {
                            (*ptr).value = *val;
                        }
                        (*ptr).ran = 1;
                    }
                }
            };

            record(LPM_MATCH_SLOT, &Key::new(32, [192, 168, 1, 42]));
            record(NO_MATCH_SLOT, &Key::new(32, [10, 0, 0, 1]));
            if $routes_map.remove(&Key::new(24, [192, 168, 1, 0])).is_ok() {
                record(REMOVE_SLOT, &Key::new(32, [192, 168, 1, 42]));
            }

            0
        }
    };
}

define_lpm_trie_test!(ROUTES, RESULTS, test_btf_lpm_trie);
define_lpm_trie_test!(ROUTES_LEGACY, RESULTS_LEGACY, test_lpm_trie_legacy);
