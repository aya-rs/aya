//! HID-BPF program support.
//!
//! HID-BPF is a struct_ops-based interface for implementing HID device drivers
//! in BPF. It allows intercepting and modifying HID reports, fixing report
//! descriptors, and handling hardware requests.
//!
//! # Safe Abstractions
//!
//! This module provides safe Rust abstractions over the raw kernel interfaces:
//!
//! - [`HidBpfContext`]: Safe wrapper around kernel's `hid_bpf_ctx`
//! - [`HidBpfData`]: Bounds-checked access to HID report data buffers
//! - `AllocatedContext`: RAII guard for allocated contexts (auto-releases on drop, BPF target only)
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
//! # Example
//!
//! ```ignore
//! use aya_ebpf::programs::hid_bpf::{HidBpfContext, HidReportType, HidClassRequest};
//!
//! #[no_mangle]
//! #[link_section = "struct_ops/hid_device_event"]
//! pub extern "C" fn my_hid_event(ctx_ptr: *mut hid_bpf_ctx) -> i32 {
//!     let ctx = HidBpfContext::new(ctx_ptr);
//!
//!     // Safe bounds-checked data access
//!     let Some(data) = ctx.data(0, 8) else {
//!         return 0;
//!     };
//!
//!     // Read bytes safely
//!     if let Some(first_byte) = data.get(0) {
//!         // Process...
//!     }
//!
//!     0
//! }
//! ```

use core::{ffi::c_void, marker::PhantomData};

use crate::EbpfContext;

// =============================================================================
// Kernel type definitions
// =============================================================================

/// Kernel's HID-BPF context structure.
///
/// This struct must be named `hid_bpf_ctx` (snake_case) to match the kernel's
/// BTF type name. The kernel verifier checks that kfunc arguments point to
/// this exact struct type.
///
/// # Layout
///
/// This matches the kernel's `struct hid_bpf_ctx` from `include/linux/hid_bpf.h`.
///
/// # Note on struct naming
///
/// This struct is intentionally NOT named `hid_bpf_ctx` to avoid BTF collision
/// with the kernel's vmlinux type. When the verifier checks kfunc arguments,
/// it resolves types by name from vmlinux BTF, finding the kernel's definition
/// which has `struct hid_device *hid` (a pointer to struct, not scalar).
///
/// By using a different name, we ensure the verifier uses our scalar-field
/// definition for type checking, avoiding the "must point to scalar" error.
///
/// The actual kernel ABI is preserved since we only access fields by offset
/// through the context pointer, and kfunc calls use inline asm which bypasses
/// BTF type matching.
#[repr(C)]
pub struct hid_bpf_ctx {
    /// Pointer to the HID device stored as opaque u64 (do not use directly).
    /// The kernel passes an actual pointer here, but we must represent it as
    /// a scalar integer to satisfy the struct_ops verifier.
    pub hid: u64,
    /// Allocated size for data buffer access.
    pub allocated_size: u32,
    /// Return value (same memory as size in kernel's union).
    pub retval: i32,
}

// =============================================================================
// Safe data buffer wrapper
// =============================================================================

/// Safe wrapper around HID report data buffer with bounds checking.
///
/// This type provides safe indexed access to the kernel's HID report buffer,
/// preventing out-of-bounds access that would be undefined behavior.
///
/// # Lifetime
///
/// The lifetime `'a` is tied to the [`HidBpfContext`] that created this buffer,
/// ensuring the buffer cannot outlive the context.
pub struct HidBpfData<'a> {
    ptr: *mut u8,
    len: u32,
    _marker: PhantomData<&'a mut [u8]>,
}

impl HidBpfData<'_> {
    /// Get a byte at the given index.
    ///
    /// Returns `None` if the index is out of bounds.
    #[inline(always)]
    pub fn get(&self, idx: usize) -> Option<u8> {
        if idx < self.len as usize {
            // SAFETY: bounds checked above, ptr valid for len bytes per kernel contract
            Some(unsafe { *self.ptr.add(idx) })
        } else {
            None
        }
    }

    /// Set a byte at the given index.
    ///
    /// Returns `true` if successful, `false` if out of bounds.
    #[inline(always)]
    pub fn set(&mut self, idx: usize, val: u8) -> bool {
        if idx < self.len as usize {
            // SAFETY: bounds checked above, ptr valid for len bytes per kernel contract
            unsafe { *self.ptr.add(idx) = val };
            true
        } else {
            false
        }
    }

    /// Copy a slice into the buffer at the given offset.
    ///
    /// Returns `true` if successful, `false` if the write would exceed bounds.
    #[inline(always)]
    pub fn copy_from_slice(&mut self, offset: usize, src: &[u8]) -> bool {
        let end = offset.saturating_add(src.len());
        if end > self.len as usize {
            return false;
        }
        for (i, &byte) in src.iter().enumerate() {
            // SAFETY: bounds checked above
            unsafe { *self.ptr.add(offset + i) = byte };
        }
        true
    }

    /// Check if the buffer starts with the given pattern.
    #[inline(always)]
    pub fn starts_with(&self, pattern: &[u8]) -> bool {
        if pattern.len() > self.len as usize {
            return false;
        }
        for (i, &expected) in pattern.iter().enumerate() {
            // SAFETY: bounds checked above
            if unsafe { *self.ptr.add(i) } != expected {
                return false;
            }
        }
        true
    }

    /// Returns the length of the buffer.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns true if the buffer is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// =============================================================================
// Context wrapper
// =============================================================================

/// Safe wrapper around the kernel's `hid_bpf_ctx`.
///
/// This wrapper provides safe access to context fields and data buffers.
/// All unsafe operations are encapsulated within this type's methods.
#[repr(transparent)]
pub struct HidBpfContext {
    ctx: *mut hid_bpf_ctx,
}

impl HidBpfContext {
    /// Creates a new HidBpfContext from a raw `hid_bpf_ctx` pointer.
    ///
    /// # Safety
    ///
    /// The pointer must be a valid `struct hid_bpf_ctx *` from the kernel.
    /// This is guaranteed when called from a HID-BPF callback.
    #[inline(always)]
    pub unsafe fn new(ctx: *mut hid_bpf_ctx) -> Self {
        Self { ctx }
    }

    /// Get safe access to the HID report data buffer.
    ///
    /// Returns `None` if the kernel returns a null pointer (e.g., invalid offset/size).
    #[cfg(target_arch = "bpf")]
    #[inline(always)]
    pub fn data(&self, offset: u32, size: u32) -> Option<HidBpfData<'_>> {
        // SAFETY: kfunc returns valid pointer or null, size is validated by kernel
        let ptr = unsafe { kfunc::hid_bpf_get_data(self.ctx, offset, size) };
        if ptr.is_null() {
            None
        } else {
            Some(HidBpfData {
                ptr,
                len: size,
                _marker: PhantomData,
            })
        }
    }

    /// Returns the allocated buffer size from the context.
    #[inline(always)]
    pub fn allocated_size(&self) -> u32 {
        // SAFETY: context pointer valid per kernel contract
        unsafe { (*self.ctx).allocated_size }
    }

    /// Returns the retval field from the context.
    ///
    /// For `hid_rdesc_fixup`, this contains the original descriptor size.
    #[inline(always)]
    pub fn retval(&self) -> i32 {
        // SAFETY: context pointer valid per kernel contract
        unsafe { (*self.ctx).retval }
    }

    /// Sets the retval field in the context.
    #[inline(always)]
    pub fn set_retval(&mut self, val: i32) {
        // SAFETY: context pointer valid per kernel contract
        unsafe { (*self.ctx).retval = val };
    }

    /// Returns a raw pointer to the underlying `hid_bpf_ctx`.
    ///
    /// Use this when you need to pass the context to kfuncs directly.
    #[inline(always)]
    pub fn as_ptr(&self) -> *mut hid_bpf_ctx {
        self.ctx
    }
}

impl EbpfContext for HidBpfContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx.cast::<c_void>()
    }
}

// =============================================================================
// RAII guard for allocated contexts
// =============================================================================

/// RAII guard for an allocated HID-BPF context.
///
/// When you need to send requests to a different HID interface (e.g., sending
/// commands to a vendor interface while handling events on the keyboard interface),
/// you allocate a new context. This guard ensures the context is properly released
/// when dropped, even on early returns or panics.
///
/// # Example
///
/// ```ignore
/// // Allocate context for vendor interface
/// let Some(vendor) = AllocatedContext::new(vendor_hid_id) else {
///     return 0;
/// };
///
/// // Send command - context auto-released on drop
/// let ret = vendor.hw_request(&mut buf, HidReportType::Feature, HidClassRequest::SetReport);
/// ```
#[cfg(target_arch = "bpf")]
pub struct AllocatedContext {
    ctx: *mut hid_bpf_ctx,
}

#[cfg(target_arch = "bpf")]
impl AllocatedContext {
    /// Allocate a new HID-BPF context for the given HID ID.
    ///
    /// Returns `None` if allocation fails (e.g., invalid HID ID).
    #[inline(always)]
    pub fn new(hid_id: u32) -> Option<Self> {
        // SAFETY: kfunc returns valid pointer or null
        let ctx = unsafe { kfunc::hid_bpf_allocate_context(hid_id) };
        if ctx.is_null() {
            None
        } else {
            Some(Self { ctx })
        }
    }

    /// Send a HID hardware request through this context.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer for request data (and response for GET requests)
    /// * `rtype` - Report type (Input, Output, or Feature)
    /// * `reqtype` - Class request type (GetReport, SetReport, etc.)
    ///
    /// # Returns
    ///
    /// Number of bytes transferred on success, negative error code on failure.
    #[inline(always)]
    pub fn hw_request(
        &self,
        buf: &mut [u8],
        rtype: HidReportType,
        reqtype: HidClassRequest,
    ) -> i32 {
        // SAFETY: context valid, buffer valid for its length
        unsafe {
            kfunc::hid_bpf_hw_request(
                self.ctx,
                buf.as_mut_ptr(),
                buf.len(),
                rtype as u32,
                reqtype as u32,
            )
        }
    }

    /// Returns a raw pointer to the underlying context.
    #[inline(always)]
    pub fn as_ptr(&self) -> *mut hid_bpf_ctx {
        self.ctx
    }
}

#[cfg(target_arch = "bpf")]
impl Drop for AllocatedContext {
    #[inline(always)]
    fn drop(&mut self) {
        // SAFETY: context was allocated successfully in new()
        unsafe { kfunc::hid_bpf_release_context(self.ctx) };
    }
}

// =============================================================================
// Kernel function (kfunc) bindings
// =============================================================================

/// Low-level kernel function bindings for HID-BPF.
///
/// These functions call kernel kfuncs using inline assembly to ensure reliable
/// invocation. The extern declarations are for BTF generation only.
///
/// Most users should use the safe wrappers ([`HidBpfContext`], [`AllocatedContext`])
/// instead of calling these directly.
#[cfg(target_arch = "bpf")]
pub mod kfunc {
    use super::hid_bpf_ctx;

    // External kfunc declarations with proper type signatures.
    // Using *mut hid_bpf_ctx to match our struct definition.
    #[allow(improper_ctypes)]
    unsafe extern "C" {
        #[link_name = "hid_bpf_get_data"]
        fn extern_hid_bpf_get_data(ctx: *mut hid_bpf_ctx, offset: u32, size: u32) -> *mut u8;
        #[link_name = "hid_bpf_allocate_context"]
        fn extern_hid_bpf_allocate_context(hid_id: u32) -> *mut hid_bpf_ctx;
        #[link_name = "hid_bpf_release_context"]
        fn extern_hid_bpf_release_context(ctx: *mut hid_bpf_ctx);
        #[link_name = "hid_bpf_hw_request"]
        fn extern_hid_bpf_hw_request(
            ctx: *mut hid_bpf_ctx,
            buf: *mut u8,
            buf_sz: usize,
            rtype: u32,
            reqtype: u32,
        ) -> i32;
    }

    // Force externs to be emitted in .ksyms section for BTF generation.
    // Using typed function pointers with *mut hid_bpf_ctx.
    #[used]
    #[unsafe(link_section = ".ksyms")]
    static HID_BPF_GET_DATA_REF: unsafe extern "C" fn(*mut hid_bpf_ctx, u32, u32) -> *mut u8 =
        extern_hid_bpf_get_data;

    #[used]
    #[unsafe(link_section = ".ksyms")]
    static HID_BPF_ALLOCATE_CONTEXT_REF: unsafe extern "C" fn(u32) -> *mut hid_bpf_ctx =
        extern_hid_bpf_allocate_context;

    #[used]
    #[unsafe(link_section = ".ksyms")]
    static HID_BPF_RELEASE_CONTEXT_REF: unsafe extern "C" fn(*mut hid_bpf_ctx) =
        extern_hid_bpf_release_context;

    #[used]
    #[unsafe(link_section = ".ksyms")]
    static HID_BPF_HW_REQUEST_REF: unsafe extern "C" fn(
        *mut hid_bpf_ctx,
        *mut u8,
        usize,
        u32,
        u32,
    ) -> i32 = extern_hid_bpf_hw_request;

    /// Get a pointer to the HID report data buffer.
    ///
    /// # Safety
    ///
    /// - `ctx` must be a valid `hid_bpf_ctx` pointer from a HID-BPF callback
    /// - The returned pointer (if non-null) is valid for `size` bytes
    #[inline(always)]
    pub unsafe fn hid_bpf_get_data(ctx: *mut hid_bpf_ctx, offset: u32, size: u32) -> *mut u8 {
        let result: *mut u8;
        unsafe {
            core::arch::asm!(
                "call hid_bpf_get_data",
                in("r1") ctx,
                in("r2") offset,
                in("r3") size,
                lateout("r0") result,
                clobber_abi("C"),
            );
        }
        result
    }

    /// Allocate a new HID-BPF context for the given HID ID.
    ///
    /// # Safety
    ///
    /// - Must be called from a sleepable BPF context
    /// - The returned context must be released with [`hid_bpf_release_context`]
    #[inline(always)]
    pub unsafe fn hid_bpf_allocate_context(hid_id: u32) -> *mut hid_bpf_ctx {
        let result: *mut hid_bpf_ctx;
        unsafe {
            core::arch::asm!(
                "call hid_bpf_allocate_context",
                in("r1") hid_id,
                lateout("r0") result,
                clobber_abi("C"),
            );
        }
        result
    }

    /// Release an allocated HID-BPF context.
    ///
    /// # Safety
    ///
    /// - `ctx` must have been allocated by [`hid_bpf_allocate_context`]
    /// - Must not be called twice on the same context
    #[inline(always)]
    pub unsafe fn hid_bpf_release_context(ctx: *mut hid_bpf_ctx) {
        unsafe {
            core::arch::asm!(
                "call hid_bpf_release_context",
                in("r1") ctx,
                clobber_abi("C"),
            );
        }
    }

    /// Send a HID hardware request.
    ///
    /// # Safety
    ///
    /// - `ctx` must be a valid allocated context
    /// - `buf` must be valid for `buf_sz` bytes
    #[inline(always)]
    pub unsafe fn hid_bpf_hw_request(
        ctx: *mut hid_bpf_ctx,
        buf: *mut u8,
        buf_sz: usize,
        rtype: u32,
        reqtype: u32,
    ) -> i32 {
        let result: i32;
        unsafe {
            core::arch::asm!(
                "call hid_bpf_hw_request",
                in("r1") ctx,
                in("r2") buf,
                in("r3") buf_sz,
                in("r4") rtype,
                in("r5") reqtype,
                lateout("r0") result,
                clobber_abi("C"),
            );
        }
        result
    }
}

// =============================================================================
// Enums and constants
// =============================================================================

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

// Bus types from linux/input.h
/// USB bus type.
pub const BUS_USB: u16 = 0x03;
/// Bluetooth bus type.
pub const BUS_BLUETOOTH: u16 = 0x05;
/// I2C bus type.
pub const BUS_I2C: u16 = 0x18;

// HID groups from linux/hid.h
/// Match any HID group.
pub const HID_GROUP_ANY: u16 = 0x0000;
/// Generic HID group.
pub const HID_GROUP_GENERIC: u16 = 0x0001;

/// Return value to indicate the event should be ignored.
pub const HID_IGNORE_EVENT: i32 = -1;
