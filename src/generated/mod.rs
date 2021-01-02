#![allow(dead_code, non_camel_case_types, non_snake_case)]

// FIXME: generate for x86_64 and aarch64

mod bpf_bindings;
mod perf_bindings;

pub use bpf_bindings::*;
pub use perf_bindings::*;
