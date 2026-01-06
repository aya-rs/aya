//! HID-BPF program support.
//!
//! HID-BPF is a struct_ops-based interface for implementing HID device drivers
//! in BPF. It allows intercepting and modifying HID reports, fixing report
//! descriptors, and handling hardware requests.
//!
//! # Callbacks
//!
//! HID-BPF supports several callbacks:
//!
//! - `hid_device_event`: Called for each HID input report
//! - `hid_rdesc_fixup`: Called to modify the HID report descriptor at probe time
//! - `hid_hw_request`: Called for hardware requests (feature reports, etc.)
//! - `hid_hw_output_report`: Called for output reports

use core::ffi::c_void;

use crate::EbpfContext;

/// Context for HID-BPF callbacks.
///
/// This context is passed to HID-BPF struct_ops callbacks and provides access
/// to HID report data through the [`hid_bpf_get_data`] kfunc.
#[repr(C)]
pub struct HidBpfContext {
    ctx: *mut c_void,
}

impl HidBpfContext {
    /// Creates a new HidBpfContext from a raw pointer.
    ///
    /// # Safety
    ///
    /// The pointer must be a valid `struct hid_bpf_ctx *` from the kernel.
    #[inline]
    pub fn new(ctx: *mut c_void) -> Self {
        Self { ctx }
    }

    /// Returns a raw pointer to the underlying `hid_bpf_ctx`.
    #[inline]
    pub fn hid_bpf_ctx(&self) -> *mut c_void {
        self.ctx
    }
}

impl EbpfContext for HidBpfContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}

/// Arguments for HID-BPF probe syscall.
///
/// This struct is passed to the probe function to determine if the BPF program
/// should attach to a specific HID device interface.
#[repr(C)]
pub struct HidBpfProbeArgs {
    /// HID device ID.
    pub hid: u32,
    /// Size of the report descriptor.
    pub rdesc_size: u32,
    /// The raw report descriptor bytes.
    pub rdesc: [u8; 4096],
    /// Return value - set to 0 to attach, negative errno to skip.
    pub retval: i32,
}

/// HID report types.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidReportType {
    /// Input report - data from device to host.
    Input = 0,
    /// Output report - data from host to device.
    Output = 1,
    /// Feature report - bidirectional configuration data.
    Feature = 2,
}

/// HID class request types.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidClassRequest {
    /// Get report request.
    GetReport = 0x01,
    /// Get idle request.
    GetIdle = 0x02,
    /// Get protocol request.
    GetProtocol = 0x03,
    /// Set report request.
    SetReport = 0x09,
    /// Set idle request.
    SetIdle = 0x0a,
    /// Set protocol request.
    SetProtocol = 0x0b,
}

// Bus types from linux/input.h
pub const BUS_USB: u16 = 0x03;
pub const BUS_BLUETOOTH: u16 = 0x05;
pub const BUS_I2C: u16 = 0x18;

// HID groups from linux/hid.h
pub const HID_GROUP_ANY: u16 = 0x0000;
pub const HID_GROUP_GENERIC: u16 = 0x0001;

/// Return value to indicate the event should be ignored.
pub const HID_IGNORE_EVENT: i32 = -1;

// Note: hid_bpf_get_data and other kfuncs must be declared in the BPF program
// using extern blocks. See the hid-bpf example for usage.
