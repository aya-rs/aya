use core::ffi::c_void;

use crate::{EbpfContext, bindings::bpf_sk_lookup};

pub struct SkLookupContext {
    pub lookup: *mut bpf_sk_lookup,
}

impl SkLookupContext {
    pub fn new(lookup: *mut bpf_sk_lookup) -> SkLookupContext {
        SkLookupContext { lookup }
    }
}

impl EbpfContext for SkLookupContext {
    fn as_ptr(&self) -> *mut c_void {
        self.lookup as *mut _
    }
}
