#![allow(dead_code, non_camel_case_types, non_snake_case, clippy::all)]

mod btf_internal_bindings;
#[cfg(target_arch = "aarch64")]
mod linux_bindings_aarch64;
#[cfg(target_arch = "arm")]
mod linux_bindings_armv7;
#[cfg(target_arch = "x86_64")]
mod linux_bindings_x86_64;

pub use btf_internal_bindings::*;

#[cfg(target_arch = "x86_64")]
pub use linux_bindings_x86_64::*;

#[cfg(target_arch = "arm")]
pub use linux_bindings_armv7::*;

#[cfg(target_arch = "aarch64")]
pub use linux_bindings_aarch64::*;
