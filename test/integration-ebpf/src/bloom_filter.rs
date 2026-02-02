#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{macros::map, maps::BloomFilter};

#[map]
static BLOOM: BloomFilter<u32> = BloomFilter::with_max_entries(64, 0);
