#![no_std]

pub mod bpf;
pub mod maps;
pub mod programs;

pub use aya_bpf_cty as cty;

use bpf::helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid};
use core::ffi::c_void;
use cty::c_char;

pub use aya_bpf_macros as macros;

pub const TASK_COMM_LEN: usize = 16;

pub trait BpfContext {
    fn as_ptr(&self) -> *mut c_void;

    #[inline]
    fn command(&self) -> Result<[c_char; TASK_COMM_LEN], ()> {
        bpf_get_current_comm()
    }

    #[inline]
    fn pid(&self) -> u32 {
        bpf_get_current_pid_tgid() as u32
    }

    #[inline]
    fn tgid(&self) -> u32 {
        (bpf_get_current_pid_tgid() >> 32) as u32
    }
}
