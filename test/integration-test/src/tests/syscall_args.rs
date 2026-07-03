use aya::{
    EbpfLoader,
    maps::{Array, MapData},
    programs::KProbe,
};
use integration_common::syscall_args::{
    RAN, RESULT_INDEX, SPLICE_FD_IN, SPLICE_FD_OUT, SPLICE_FLAGS, SPLICE_LEN, TestResult,
};

// The number of attempts we make to capture our own `splice(2)` call. The
// kprobe is global, so concurrent `splice` invocations from other processes
// can overwrite the shared result slot. Each attempt resets the slot, updates
// the `pid` global, and triggers another `splice` call.
const ATTEMPTS: usize = 16;

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

    let mut bpf = EbpfLoader::new().load(crate::SYSCALL_ARGS).unwrap();

    let mut results: Array<MapData, TestResult> =
        Array::try_from(bpf.take_map("RESULTS").unwrap()).unwrap();

    let prog: &mut KProbe = bpf
        .program_mut("syscall_args_splice")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach(wrapper, 0).unwrap();

    // We pass distinct sentinel values for each of `splice`'s six arguments.
    // On `x86-64` arg4 (`off_out`) is delivered in `r10` rather than `rcx`;
    // a wrong `off_out` value indicates the regular calling convention was
    // used incorrectly.
    //
    // Pass invalid fds and a non-null offset pointer; `splice(2) returns an
    // error (usually `EBADF`), but the kprobe fires before the kernel validates
    // the arguments.
    let off_in: u64 = 0;
    let off_out: u64 = 0;

    for _ in 0..ATTEMPTS {
        // Reset the result slot before triggering the kprobe.
        results.set(RESULT_INDEX, TestResult::default(), 0).unwrap();

        // Trigger the syscall. `splice` returns an error on these arguments
        // (`EBADF` from the invalid fds), but the kprobe fires first.
        let rc = unsafe {
            libc::splice(
                SPLICE_FD_IN as i32,
                off_in as *mut libc::loff_t,
                SPLICE_FD_OUT as i32,
                off_out as *mut libc::loff_t,
                SPLICE_LEN as usize,
                SPLICE_FLAGS as u32,
            )
        };
        // We expect `splice` to fail with an invalid fd.
        assert!(rc < 0, "splice unexpectedly succeeded");

        let result = results.get(&RESULT_INDEX, 0).unwrap();
        if result.ran != RAN
            || result.fd_in != SPLICE_FD_IN
            || result.fd_out != SPLICE_FD_OUT
            || result.len != SPLICE_LEN
            || result.flags != SPLICE_FLAGS
        {
            // Probably overwritten by another process' `splice` call. Retry.
            continue;
        }

        return;
    }

    panic!("did not observe our own splice() after {ATTEMPTS} attempts");
}
