//! eBPF program using only `btf_maps` (no legacy maps).
//!
//! This program is used to test that libbpf can load BTF maps
//! produced by aya-ebpf's `btf_maps` module.

#![no_std]
#![no_main]
#![allow(
    unused_crate_dependencies,
    reason = "ebpf_panic is only required for non-test eBPF builds; importing it unconditionally would register its panic handler during tests and conflict with std"
)]

#[cfg(not(test))]
extern crate ebpf_panic;

// Required for satisfying unused-crate-dependencies lint
#[rustfmt::skip]
use aya_log_ebpf as _;
#[rustfmt::skip]
use integration_ebpf as _;
#[rustfmt::skip]
use integration_common as _;
#[rustfmt::skip]
use network_types as _;

use aya_ebpf::{
    btf_maps::Array,
    macros::{btf_map, uprobe},
    programs::ProbeContext,
};

#[btf_map]
static BTF_ARRAY: Array<u64, 16> = Array::new();

#[uprobe]
fn btf_maps_plain(_ctx: ProbeContext) -> u32 {
    if let Some(value) = BTF_ARRAY.get(0) {
        *value as u32
    } else {
        0
    }
}
