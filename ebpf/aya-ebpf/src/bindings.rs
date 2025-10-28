#[cfg(any(
    bpf_target_arch = "arm",
    bpf_target_arch = "mips",
    bpf_target_arch = "powerpc64",
    bpf_target_arch = "x86_64",
))]
pub use aya_ebpf_bindings::bindings::pt_regs;
#[cfg(any(
    bpf_target_arch = "aarch64",
    bpf_target_arch = "loongarch64",
    bpf_target_arch = "s390x",
))]
pub use aya_ebpf_bindings::bindings::user_pt_regs as pt_regs;
#[cfg(bpf_target_arch = "riscv64")]
pub use aya_ebpf_bindings::bindings::user_regs_struct as pt_regs;
pub use aya_ebpf_bindings::bindings::*;
