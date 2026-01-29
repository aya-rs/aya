#![cfg_attr(
    target_arch = "bpf",
    expect(unused_crate_dependencies, reason = "compiler_builtins")
)]
#![no_std]

pub mod spin_lock;

pub use spin_lock::SpinLock;
