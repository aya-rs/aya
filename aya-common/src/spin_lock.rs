use aya_ebpf_cty::c_uint;

// #[expect(non_camel_case_types, reason = "Binding to a C type.")]
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct bpf_spin_lock {
    pub val: c_uint,
}

/// A spin lock that can be used to procect shared data in eBPF maps.
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct SpinLock(bpf_spin_lock);

impl SpinLock {
    pub fn as_ptr(&self) -> *mut bpf_spin_lock {
        core::ptr::from_ref::<bpf_spin_lock>(&self.0).cast_mut()
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SpinLock {}
