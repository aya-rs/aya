use core::ffi::c_void;

use crate::{EbpfContext, bindings::bpf_cgroup_dev_ctx};

pub struct DeviceContext {
    pub device: *mut bpf_cgroup_dev_ctx,
}

impl DeviceContext {
    pub fn new(device: *mut bpf_cgroup_dev_ctx) -> DeviceContext {
        DeviceContext { device }
    }
}

impl EbpfContext for DeviceContext {
    fn as_ptr(&self) -> *mut c_void {
        self.device as *mut _
    }
}
