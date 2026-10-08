use aya::{
    EbpfLoader,
    maps::{Array, MapData},
    programs::KProbe,
};
use integration_common::syscall_args::SpliceArgs;

// Sentinel values passed as the six arguments of the `splice(2)` syscall.
// The kprobe distinguishes each register slot round-trip through the syscall
// wrapper. Mirrors the kernel selftest pattern in
// <https://github.com/torvalds/linux/blob/e5f0a698b/tools/testing/selftests/bpf/progs/bpf_syscall_macro.c#L89-L103>.
//
// Positive `i32` values are used for `fd_in`/`fd_out` to avoid sign-extension
// differences between architectures. The offset pointers are invalid non-null
// sentinels; the kernel will fail with `EFAULT` but the kprobe fires first.
const SPLICE_FD_IN: u64 = 0x0bad_f00d;
const SPLICE_FD_OUT: u64 = 0x0f00_d0ad;
const SPLICE_OFF_IN: u64 = 0x1234_5678_9abc_def0;
const SPLICE_OFF_OUT: u64 = 0x0fed_cba9_8765_4321;
const SPLICE_LEN: u64 = 0xcafe_babe_dad0_bad0;
const SPLICE_FLAGS: u64 = 0x0edb_ab1e;

// The captured arguments, in `splice` argument order. On `x86-64` arg 3
// (`off_out`) is delivered in `r10` rather than `rcx`, so a wrong value there
// indicates the regular calling convention was used incorrectly.
const EXPECTED: SpliceArgs = [
    SPLICE_FD_IN,
    SPLICE_OFF_IN,
    SPLICE_FD_OUT,
    SPLICE_OFF_OUT,
    SPLICE_LEN,
    SPLICE_FLAGS,
];

// Returns the syscall wrapper symbol used by the host architecture, or `None`
// if the architecture does not implement `CONFIG_ARCH_HAS_SYSCALL_WRAPPER`.
fn splice_syscall_wrapper() -> Option<&'static str> {
    if cfg!(target_arch = "x86_64") {
        Some("__x64_sys_splice")
    } else if cfg!(target_arch = "aarch64") {
        Some("__arm64_sys_splice")
    } else {
        None
    }
}

#[test_log::test]
fn syscall_arg_splice() {
    let Some(wrapper) = splice_syscall_wrapper() else {
        eprintln!(
            "skipping test - syscall wrappers unavailable on {}",
            std::env::consts::ARCH
        );
        return;
    };

    let target_tgid = std::process::id();
    let mut bpf = EbpfLoader::new()
        .override_global("TARGET_TGID", &target_tgid, true)
        .load(crate::SYSCALL_ARGS)
        .unwrap();

    let results: Array<MapData, SpliceArgs> =
        Array::try_from(bpf.take_map("RESULTS").unwrap()).unwrap();

    let prog: &mut KProbe = bpf
        .program_mut("syscall_args_splice")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach(wrapper, 0).unwrap();

    // For `off_in`/`off_out` (which are `loff_t *` pointers) we pass invalid
    // non-null sentinel addresses; the kernel will fail with `EFAULT` when it
    // tries to dereference them, but the kprobe fires first and captures the
    // raw register value.
    let off_in_ptr = std::ptr::with_exposed_provenance_mut::<libc::loff_t>(SPLICE_OFF_IN as usize);
    let off_out_ptr =
        std::ptr::with_exposed_provenance_mut::<libc::loff_t>(SPLICE_OFF_OUT as usize);

    // Trigger the syscall. `splice` returns an error on these arguments
    // (`EBADF` from the invalid fds or `EFAULT` from the invalid offset
    // pointers), but the kprobe fires before the kernel validates them.
    let rc = unsafe {
        libc::splice(
            SPLICE_FD_IN as i32,
            off_in_ptr,
            SPLICE_FD_OUT as i32,
            off_out_ptr,
            SPLICE_LEN as usize,
            SPLICE_FLAGS as u32,
        )
    };
    assert!(rc < 0, "splice unexpectedly succeeded");

    // A fresh map starts zeroed and every sentinel is nonzero, so a matching
    // array proves the probe ran and every read used the syscall calling
    // convention.
    let args: SpliceArgs = results.get(&0, 0).unwrap();
    assert_eq!(
        args, EXPECTED,
        "kprobe did not fire or recorded wrong arguments"
    );
}
