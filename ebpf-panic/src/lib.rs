//! A panic handler for eBPF rust targets.
//!
//! Panics are not supported in the eBPF rust targets however since crates for
//! the eBPF targets are no_std they must provide a panic handler. This crate
//! provides a panic handler that loops forever. Such a function, if called,
//! will cause the program to be rejected by the eBPF verifier with an error
//! message similar to:
//!
//! ```text
//! last insn is not an exit or jmp
//! ```
//!
//! # Example
//!
//! ```no_run
//! #![no_std]
//!
//! use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
//! #[cfg(not(test))]
//! extern crate ebpf_panic;
//!
//! #[tracepoint]
//! pub fn test_tracepoint_one(_ctx: TracePointContext) -> u32 {
//!     0
//! }
//! ```
#![no_std]

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
