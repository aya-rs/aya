#![no_std]
#![allow(
    unused_crate_dependencies,
    reason = "ebpf_panic is only required for non-test eBPF builds; importing it unconditionally would register its panic handler during tests and conflict with std"
)]

// Required for satisfying unused-crate-dependencies lint
#[rustfmt::skip]
use aya_ebpf as _;
#[rustfmt::skip]
use aya_log_ebpf as _;
#[rustfmt::skip]
use integration_common as _;
#[rustfmt::skip]
use network_types as _;
