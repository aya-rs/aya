//! Socket load balancing with SO_REUSEPORT programs.
//!
//! This module provides context and constants for BPF_PROG_TYPE_SK_REUSEPORT programs
//! which allow custom load balancing logic for SO_REUSEPORT socket groups.
//!
//! # Basic Usage
//!
//! ```no_run
//! use aya_ebpf::{macros::sk_reuseport, programs::{SkReuseportContext, SK_PASS, SK_DROP}};
//!
//! #[sk_reuseport]
//! pub fn load_balancer(ctx: SkReuseportContext) -> u32 {
//!     // Allow packet through - kernel will balance among sockets
//!     SK_PASS
//! }
//! ```
//!
//! # Advanced Socket Selection
//!
//! For explicit socket selection, use `bpf_sk_select_reuseport()` with socket arrays:
//!
//! ```no_run
//! use aya_ebpf::{
//!     macros::{sk_reuseport, map},
//!     programs::{SkReuseportContext, SK_PASS, SK_DROP},
//!     helpers::bpf_sk_select_reuseport,
//!     maps::ReusePortSockArray,
//!     EbpfContext,
//! };
//!
//! #[map(name = "socket_map")]
//! static SOCKET_MAP: ReusePortSockArray = ReusePortSockArray::with_max_entries(10, 0);
//!
//! #[sk_reuseport]
//! pub fn select_worker(ctx: SkReuseportContext) -> u32 {
//!     // Custom logic to determine worker index
//!     let worker_id: u32 = 2;
//!     
//!     // Select specific socket using helper
//!     let ret = unsafe {
//!         bpf_sk_select_reuseport(
//!             ctx.as_ptr() as *mut _,
//!             SOCKET_MAP.as_ptr(),
//!             &worker_id as *const _ as *mut _,
//!             0
//!         )
//!     };
//!     
//!     // Return SK_DROP on error, SK_PASS on success
//!     if ret == 0 {
//!         SK_PASS
//!     } else {
//!         SK_DROP
//!     }
//! }
//! ```
//!
//! # Context Field Access Example
//!
//! Access packet metadata for custom load balancing decisions:
//!
//! ```no_run
//! use aya_ebpf::{
//!     macros::{sk_reuseport, map},
//!     programs::{SkReuseportContext, SK_PASS, SK_DROP},
//!     helpers::bpf_sk_select_reuseport,
//!     maps::ReusePortSockArray,
//!     EbpfContext,
//! };
//!
//! #[map(name = "socket_map")]
//! static SOCKET_MAP: ReusePortSockArray = ReusePortSockArray::with_max_entries(4, 0);
//!
//! #[sk_reuseport]
//! pub fn hash_based_selection(ctx: SkReuseportContext) -> u32 {
//!     // Use packet hash for consistent load balancing
//!     let socket_idx = ctx.hash() % 4;
//!     
//!     // Only handle TCP traffic
//!     if ctx.ip_protocol() == 6 {  // IPPROTO_TCP
//!         let ret = unsafe {
//!             bpf_sk_select_reuseport(
//!                 ctx.as_ptr() as *mut _,
//!                 SOCKET_MAP.as_ptr(),
//!                 &socket_idx as *const _ as *mut _,
//!                 0
//!             )
//!         };
//!         
//!         if ret == 0 {
//!             SK_PASS
//!         } else {
//!             SK_DROP
//!         }
//!     } else {
//!         // Let kernel handle non-TCP traffic
//!         SK_PASS
//!     }
//! }
//! ```

use core::ffi::c_void;

use crate::{EbpfContext, bindings::sk_reuseport_md};

/// SK_PASS: Allow packet through and let kernel handle socket selection
pub const SK_PASS: u32 = 1;

/// SK_DROP: Drop the packet
pub const SK_DROP: u32 = 0;

pub struct SkReuseportContext {
    pub md: *mut sk_reuseport_md,
}

impl SkReuseportContext {
    pub fn new(md: *mut sk_reuseport_md) -> SkReuseportContext {
        SkReuseportContext { md }
    }

    /// Returns the start of the directly accessible data.
    pub fn data(&self) -> usize {
        unsafe { (*self.md).__bindgen_anon_1.data as usize }
    }

    /// Returns the end of the directly accessible data.
    pub fn data_end(&self) -> usize {
        unsafe { (*self.md).__bindgen_anon_2.data_end as usize }
    }

    /// Returns the total packet length.
    #[expect(clippy::len_without_is_empty)]
    pub fn len(&self) -> u32 {
        unsafe { (*self.md).len }
    }

    /// Returns the ethernet protocol from the packet (network byte order).
    pub fn eth_protocol(&self) -> u32 {
        unsafe { (*self.md).eth_protocol }
    }

    /// Returns the IP protocol (e.g., IPPROTO_TCP, IPPROTO_UDP).
    pub fn ip_protocol(&self) -> u32 {
        unsafe { (*self.md).ip_protocol }
    }

    /// Returns whether the socket is bound to an INANY address.
    pub fn bind_inany(&self) -> u32 {
        unsafe { (*self.md).bind_inany }
    }

    /// Returns the hash of the packet's 4-tuple for load balancing.
    pub fn hash(&self) -> u32 {
        unsafe { (*self.md).hash }
    }
}

impl EbpfContext for SkReuseportContext {
    fn as_ptr(&self) -> *mut c_void {
        self.md as *mut _
    }
}
