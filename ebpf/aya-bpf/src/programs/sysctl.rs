use core::ffi::c_void;

use crate::{bindings::bpf_sysctl, BpfContext};

pub struct SysctlContext {
    pub sysctl: *mut bpf_sysctl,
}

impl SysctlContext {
    pub fn new(sysctl: *mut bpf_sysctl) -> SysctlContext {
        SysctlContext { sysctl }
    }
}

impl BpfContext for SysctlContext {
    fn as_ptr(&self) -> *mut c_void {
        self.sysctl as *mut _
    }
}
