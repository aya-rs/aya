#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    btf_maps::{
        Array as BtfArray, HashMap as BtfHashMap, LruHashMap as BtfLruHashMap,
        LruPerCpuHashMap as BtfLruPerCpuHashMap, PerCpuHashMap as BtfPerCpuHashMap,
    },
    cty::c_long,
    macros::{btf_map, map, uprobe},
    maps::{Array, HashMap, LruHashMap, LruPerCpuHashMap, PerCpuHashMap},
    programs::ProbeContext,
};

#[btf_map]
static RESULT: BtfArray<u64, 1, 0> = BtfArray::new();

#[btf_map]
static HASH_BTF: BtfHashMap<u32, u64, 1> = BtfHashMap::new();

#[btf_map]
static LRU_HASH_BTF: BtfLruHashMap<u32, u64, 1> = BtfLruHashMap::new();

#[btf_map]
static PER_CPU_HASH_BTF: BtfPerCpuHashMap<u32, u64, 1> = BtfPerCpuHashMap::new();

#[btf_map]
static LRU_PER_CPU_HASH_BTF: BtfLruPerCpuHashMap<u32, u64, 1> = BtfLruPerCpuHashMap::new();

#[map]
static RESULT_LEGACY: Array<u64> = Array::<u64>::with_max_entries(1, 0);

#[map]
static HASH_LEGACY: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

#[map]
static LRU_HASH_LEGACY: LruHashMap<u32, u64> = LruHashMap::with_max_entries(1, 0);

#[map]
static PER_CPU_HASH_LEGACY: PerCpuHashMap<u32, u64> = PerCpuHashMap::with_max_entries(1, 0);

#[map]
static LRU_PER_CPU_HASH_LEGACY: LruPerCpuHashMap<u32, u64> =
    LruPerCpuHashMap::with_max_entries(1, 0);

macro_rules! define_hash_lookup {
    ($map:ident, $result_map:ident, $fn:ident) => {
        #[uprobe]
        fn $fn(_: ProbeContext) -> Result<(), c_long> {
            let value = unsafe { $map.get(&0u32) }.ok_or(-1)?;
            let ptr = $result_map.get_ptr_mut(0).ok_or(-1)?;
            unsafe {
                *ptr = *value;
            }
            Ok(())
        }
    };
}

define_hash_lookup!(HASH_BTF, RESULT, test_hash_btf);
define_hash_lookup!(LRU_HASH_BTF, RESULT, test_lru_hash_btf);
define_hash_lookup!(PER_CPU_HASH_BTF, RESULT, test_per_cpu_hash_btf);
define_hash_lookup!(LRU_PER_CPU_HASH_BTF, RESULT, test_lru_per_cpu_hash_btf);

define_hash_lookup!(HASH_LEGACY, RESULT_LEGACY, test_hash_legacy);
define_hash_lookup!(LRU_HASH_LEGACY, RESULT_LEGACY, test_lru_hash_legacy);
define_hash_lookup!(PER_CPU_HASH_LEGACY, RESULT_LEGACY, test_per_cpu_hash_legacy);
define_hash_lookup!(
    LRU_PER_CPU_HASH_LEGACY,
    RESULT_LEGACY,
    test_lru_per_cpu_hash_legacy
);
