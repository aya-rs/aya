#![allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    clippy::all,
    missing_docs
)]

#[cfg(target_arch = "aarch64")]
mod linux_bindings_aarch64;
#[cfg(target_arch = "arm")]
mod linux_bindings_armv7;
#[cfg(target_arch = "riscv64")]
mod linux_bindings_riscv64;
#[cfg(target_arch = "x86_64")]
mod linux_bindings_x86_64;

#[cfg(target_arch = "x86_64")]
pub use linux_bindings_x86_64::*;

#[cfg(target_arch = "arm")]
pub use linux_bindings_armv7::*;

#[cfg(target_arch = "aarch64")]
pub use linux_bindings_aarch64::*;

#[cfg(target_arch = "riscv64")]
pub use linux_bindings_riscv64::*;
