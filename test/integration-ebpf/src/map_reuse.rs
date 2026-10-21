#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_F_NO_COMMON_LRU,
    macros::map,
    maps::{DevMap, DevMapHash, LruHashMap, LruPerCpuHashMap},
};
#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static DEVMAP: DevMap = DevMap::pinned(1, 0);

#[map]
static DEVMAP_HASH: DevMapHash = DevMapHash::pinned(1, 0);

#[map]
static LRU_HASH: LruHashMap<u32, u32> = LruHashMap::pinned(1, BPF_F_NO_COMMON_LRU);

#[map]
static LRU_PERCPU: LruPerCpuHashMap<u32, u32> = LruPerCpuHashMap::pinned(1, BPF_F_NO_COMMON_LRU);
