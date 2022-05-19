use core::ffi::c_void;

use crate::{bindings::bpf_sk_lookup, BpfContext};

pub struct SkLookupContext {
    pub lookup: *mut bpf_sk_lookup,
}

impl SkLookupContext {
    pub fn new(lookup: *mut bpf_sk_lookup) -> SkLookupContext {
        SkLookupContext { lookup }
    }
}

impl BpfContext for SkLookupContext {
    fn as_ptr(&self) -> *mut c_void {
        self.lookup as *mut _
    }
}
