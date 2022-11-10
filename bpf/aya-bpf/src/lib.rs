//! [![](https://aya-rs.dev/assets/images/aya_logo_docs.svg)](https://aya-rs.dev)
//!
//! A library to write eBPF programs.
//!
//! Aya-bpf is an eBPF library built with a focus on operability and developer experience.
//! It is the kernel-space counterpart of [Aya](https://docs.rs/aya)

#![doc(
    html_logo_url = "https://aya-rs.dev/assets/images/crabby.svg",
    html_favicon_url = "https://aya-rs.dev/assets/images/crabby.svg"
)]
#![cfg_attr(unstable, feature(never_type))]
#![allow(clippy::missing_safety_doc)]
#![no_std]

pub use aya_bpf_bindings::bindings;

mod args;
pub use args::PtRegs;
pub mod helpers;
pub mod maps;
pub mod programs;

pub use aya_bpf_cty as cty;

use core::ffi::c_void;
use cty::{c_int, c_long};
use helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid};

pub use aya_bpf_macros as macros;

pub const TASK_COMM_LEN: usize = 16;

pub trait BpfContext {
    fn as_ptr(&self) -> *mut c_void;

    #[inline]
    fn command(&self) -> Result<[u8; TASK_COMM_LEN], c_long> {
        bpf_get_current_comm()
    }

    fn pid(&self) -> u32 {
        bpf_get_current_pid_tgid() as u32
    }

    fn tgid(&self) -> u32 {
        (bpf_get_current_pid_tgid() >> 32) as u32
    }

    fn uid(&self) -> u32 {
        bpf_get_current_uid_gid() as u32
    }

    fn gid(&self) -> u32 {
        (bpf_get_current_uid_gid() >> 32) as u32
    }
}

#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut u8, c: c_int, n: usize) {
    let base = s as usize;
    for i in 0..n {
        *((base + i) as *mut u8) = c as u8;
    }
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *mut u8, n: usize) {
    let dest_base = dest as usize;
    let src_base = src as usize;
    for i in 0..n {
        *((dest_base + i) as *mut u8) = *((src_base + i) as *mut u8);
    }
}
