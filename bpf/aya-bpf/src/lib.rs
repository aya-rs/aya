#![allow(clippy::missing_safety_doc)]
#![no_std]

pub use aya_bpf_bindings::bindings;

pub mod helpers;
pub mod maps;
pub mod programs;

pub use aya_bpf_cty as cty;

use core::ffi::c_void;
use cty::{c_char, c_int, c_long};
use helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid};

pub use aya_bpf_macros as macros;

pub const TASK_COMM_LEN: usize = 16;

pub trait BpfContext {
    fn as_ptr(&self) -> *mut c_void;

    #[inline]
    fn command(&self) -> Result<[c_char; TASK_COMM_LEN], c_long> {
        bpf_get_current_comm()
    }

    fn pid(&self) -> u32 {
        bpf_get_current_pid_tgid() as u32
    }

    fn tgid(&self) -> u32 {
        (bpf_get_current_pid_tgid() >> 32) as u32
    }
}

#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut u8, c: c_int, n: usize) {
    let base = s as usize;
    for i in 0..n {
        *((base + i) as *mut u8) = c as u8;
    }
}
