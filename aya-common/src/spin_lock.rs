use aya_ebpf_cty::c_uint;

// The name `bpf_spin_lock` is expected by the verifier.
// Wrapping this struct in an another struct does not work.
#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct bpf_spin_lock(c_uint);

/// A spin lock that can be used to protect shared data in eBPF maps
pub type SpinLock = bpf_spin_lock;

#[cfg(feature = "user")]
unsafe impl aya::Pod for SpinLock {}
