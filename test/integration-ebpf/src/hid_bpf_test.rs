//! HID-BPF test program demonstrating the HID-BPF macros.
//!
//! This program shows how to use the HID-BPF macros in Rust.
//! Note: This requires kernel 6.3+ with HID-BPF support.

#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    helpers::bpf_printk,
    macros::{hid_device_event, hid_hw_request, hid_rdesc_fixup},
    programs::HidBpfContext,
};

#[cfg(not(test))]
extern crate ebpf_panic;

/// Device event handler - called for each HID input report.
#[hid_device_event]
pub(crate) fn hid_device_event_handler(_ctx: HidBpfContext) -> i32 {
    unsafe {
        bpf_printk!(b"hid_device_event called");
    }
    0
}

/// Report descriptor fixup - called at probe time.
#[hid_rdesc_fixup]
pub(crate) fn hid_rdesc_fixup_handler(_ctx: HidBpfContext) -> i32 {
    unsafe {
        bpf_printk!(b"hid_rdesc_fixup called");
    }
    0
}

/// Hardware request handler - called for feature reports etc.
#[hid_hw_request]
pub(crate) fn hid_hw_request_handler(_ctx: HidBpfContext) -> i32 {
    unsafe {
        bpf_printk!(b"hid_hw_request called");
    }
    0
}
