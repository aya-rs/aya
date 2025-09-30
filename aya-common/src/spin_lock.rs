use aya_ebpf_cty::c_uint;

// The name `bpf_spin_lock` is expected by the verifier.
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
struct bpf_spin_lock([u8; size_of::<c_uint>()]);

/// A spin lock that can be used to procect shared data in eBPF maps.
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct SpinLock(bpf_spin_lock);

#[cfg(feature = "user")]
unsafe impl aya::Pod for SpinLock {}
