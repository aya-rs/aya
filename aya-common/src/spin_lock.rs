/// A spin lock that can be used to protect shared data in eBPF maps
pub type SpinLock = aya_ebpf_bindings::bindings::bpf_spin_lock;
