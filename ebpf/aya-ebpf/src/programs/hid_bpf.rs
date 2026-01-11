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
//!
//! # BTF Requirements
//!
//! For kfuncs like `hid_bpf_get_data` to work, the BPF program must use
//! `*mut hid_bpf_ctx` as the context parameter type. This generates the correct
//! BTF that the kernel verifier expects.
//!
//! # Example
//!
//! ```ignore
//! use aya_ebpf::programs::hid_bpf::hid_bpf_ctx;
//!
//! // Declare kfuncs as extern - the linker resolves these to kernel functions
//! extern "C" {
//!     fn hid_bpf_get_data(ctx: *mut hid_bpf_ctx, offset: u32, size: u32) -> *mut u8;
//! }
//!
//! #[no_mangle]
//! #[link_section = "struct_ops/hid_device_event"]
//! pub unsafe extern "C" fn my_hid_event(ctx: *mut hid_bpf_ctx) -> i32 {
//!     let data = hid_bpf_get_data(ctx, 0, 8);
//!     if data.is_null() {
//!         return 0;
//!     }
//!     // Process HID report data...
//!     0
//! }
//! ```

use core::ffi::c_void;

use crate::EbpfContext;

/// Forward declaration of hid_device to match kernel's BTF.
/// This is never instantiated; we only use pointers to it.
#[repr(C)]
pub struct hid_device {
    _opaque: [u8; 0],
}

/// Kernel's HID-BPF context structure.
///
/// This struct must be named `hid_bpf_ctx` (snake_case) to match the kernel's
/// BTF type name. The kernel verifier checks that kfunc arguments point to
/// this exact struct type.
///
/// # BTF Generation
///
/// When used as `*mut hid_bpf_ctx` in function signatures, LLVM generates
/// BTF with `STRUCT 'hid_bpf_ctx'` which the kernel verifier can match.
///
/// # Layout
///
/// This matches the kernel's `struct hid_bpf_ctx` from `include/linux/hid_bpf.h`.
/// Using simple i32 for retval since the union is just size alias.
#[repr(C)]
pub struct hid_bpf_ctx {
    /// Pointer to the HID device (opaque, do not dereference in BPF).
    pub hid: *mut hid_device,
    /// Allocated size for data buffer access.
    pub allocated_size: u32,
    /// Return value (same memory as size in kernel's union).
    pub retval: i32,
}

/// High-level context wrapper for HID-BPF callbacks.
///
/// This wrapper provides a safe interface around the raw `hid_bpf_ctx` pointer.
/// For kfunc calls, use [`Self::ctx_ptr()`] to get the properly typed pointer.
#[repr(C)]
pub struct HidBpfContext {
    ctx: *mut hid_bpf_ctx,
}

impl HidBpfContext {
    /// Creates a new HidBpfContext from a raw hid_bpf_ctx pointer.
    ///
    /// # Safety
    ///
    /// The pointer must be a valid `struct hid_bpf_ctx *` from the kernel.
    #[inline]
    pub fn new(ctx: *mut hid_bpf_ctx) -> Self {
        Self { ctx }
    }

    /// Returns a raw pointer to the underlying `hid_bpf_ctx`.
    ///
    /// Use this pointer when calling kfuncs like `hid_bpf_get_data`.
    #[inline]
    pub fn ctx_ptr(&self) -> *mut hid_bpf_ctx {
        self.ctx
    }

    /// Returns the allocated size from the context.
    ///
    /// # Safety
    ///
    /// The context pointer must be valid.
    #[inline]
    pub unsafe fn allocated_size(&self) -> u32 {
        unsafe { (*self.ctx).allocated_size }
    }

    /// Returns the retval field from the context.
    ///
    /// # Safety
    ///
    /// The context pointer must be valid.
    #[inline]
    pub unsafe fn retval(&self) -> i32 {
        unsafe { (*self.ctx).retval }
    }

    /// Sets the retval field in the context.
    ///
    /// # Safety
    ///
    /// The context pointer must be valid.
    #[inline]
    pub unsafe fn set_retval(&mut self, val: i32) {
        unsafe { (*self.ctx).retval = val };
    }
}

impl EbpfContext for HidBpfContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx as *mut c_void
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
